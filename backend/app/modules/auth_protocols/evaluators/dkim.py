"""DKIM Verification Service using bounded ThreadPool executor and async DNS.

Architecture reference: MS-ARCH-SEC-2026-AUTH-PROTOCOLS-REV13
Standards: RFC 6376, RFC 8301, RFC 8463
"""

from __future__ import annotations

import asyncio
import binascii
import logging
import re
from typing import Any, List, Optional, Tuple

import dkim

from app.modules.auth_protocols.config import AuthProtocolsConfig
from app.modules.auth_protocols.dns_resolver import BaseDNSResolver, DNSQueryType, DNSResponseStatus
from app.modules.auth_protocols.executor import (
    DKIMCapacityExhaustedError,
    DKIMExecutor,
    DKIMExecutorShuttingDownError,
    DKIMShutdownCancelledError,
)
from app.modules.contracts import (
    AuthProtocolsResult,
    DKIMEvaluationState,
    DKIMSignatureResult,
    ProtocolStatus,
)
from app.modules.identity.domain_utils import get_registered_domain_offline

logger = logging.getLogger(__name__)


def _verify_signature_worker(
    raw_bytes: bytes,
    signature_index: int,
    key_txt_bytes: bytes,
    min_key_bits: int = 1024,
) -> Tuple[bool, Optional[int]]:
    """CPU-bound worker executing dkimpy verification in a separate OS thread.
    
    A fresh dkim.DKIM instance is constructed for thread isolation.
    """
    inst = dkim.DKIM(raw_bytes, minkey=min_key_bits)

    def _sync_dns(name: bytes, timeout: int = 5) -> bytes:
        return key_txt_bytes

    verified = inst.verify(idx=signature_index, dnsfunc=_sync_dns)
    return bool(verified), getattr(inst, "keysize", None)


class DKIMVerifier:
    """Standards-compliant, bounded asynchronous DKIM verifier.
    
    Invariants:
    1. Preserves original raw RFC 5322 message bytes untouched.
    2. Uses async DNS resolver for selector TXT lookups with caching & transient error classification.
    3. Enforces cryptographic algorithms:
       - RSA >= 1024 bits (RFC 8301)
       - Ed25519 (RFC 8463)
       - Explicit rejection of SHA-1 (RFC 8301)
       - simple and relaxed canonicalizations (RFC 6376)
    4. Evaluates multiple signatures independently with thread-safe DKIM instance isolation.
    5. Offloads CPU-bound cryptographic verification to DKIMExecutor.
    """

    def __init__(
        self,
        dns_resolver: BaseDNSResolver,
        executor: Optional[DKIMExecutor] = None,
        config: Optional[AuthProtocolsConfig] = None,
    ) -> None:
        self._resolver = dns_resolver
        self._config = config or AuthProtocolsConfig()
        self._executor = executor
        self._owns_executor = executor is None

    @property
    def executor(self) -> DKIMExecutor:
        if self._executor is None:
            self._executor = DKIMExecutor(config=self._config)
        return self._executor

    async def shutdown(self) -> None:
        """Shuts down the internal executor if owned by this verifier."""
        if self._owns_executor and self._executor is not None:
            await self._executor.shutdown()

    async def __aenter__(self) -> "DKIMVerifier":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.shutdown()

    async def verify(
        self,
        message_bytes: Optional[bytes],
        from_domain: Optional[str] = None,
    ) -> List[DKIMSignatureResult]:
        """Verifies all DKIM-Signature headers present in raw message bytes.
        
        Args:
            message_bytes: Untouched raw RFC 5322 message bytes.
            from_domain: RFC 5322 From header domain for alignment assessment.
            
        Returns:
            List of DKIMSignatureResult instances for each signature, or empty list if none.
        """
        # Critical Requirement: verify original raw bytes without reconstruction
        if message_bytes is None or not isinstance(message_bytes, (bytes, bytearray)) or len(message_bytes) == 0:
            return [
                DKIMSignatureResult(
                    index=0,
                    status=ProtocolStatus.PERMERROR,
                    evaluation_state=DKIMEvaluationState.NOT_EVALUATED_MISSING_RAW_BYTES,
                    reason_code="MISSING_RAW_MESSAGE_BYTES",
                    error_reason="Missing original raw message bytes",
                )
            ]

        raw = bytes(message_bytes)

        # Parse headers to identify DKIM-Signature count
        try:
            d_init = dkim.DKIM(raw)
            sig_indices = [
                i for i, (h, _) in enumerate(d_init.headers)
                if h.lower() == b"dkim-signature"
            ]
        except (dkim.MessageFormatError, dkim.ParameterError, dkim.InvalidCanonicalizationPolicyError) as exc:
            return [
                DKIMSignatureResult(
                    index=0,
                    status=ProtocolStatus.PERMERROR,
                    evaluation_state=DKIMEvaluationState.EVALUATED_COMPLETED,
                    reason_code="MALFORMED_MESSAGE_HEADERS",
                    error_reason=f"Malformed RFC 5322 message headers ({type(exc).__name__})",
                )
            ]
        except Exception as exc:
            return [
                DKIMSignatureResult(
                    index=0,
                    status=ProtocolStatus.INDETERMINATE,
                    evaluation_state=DKIMEvaluationState.INCOMPLETE_INTERNAL_ERROR,
                    reason_code="DKIM_INTERNAL_HEADER_PARSE_ERROR",
                    error_reason=f"DKIM internal evaluation error parsing headers ({type(exc).__name__})",
                )
            ]

        if not sig_indices:
            # Message has no DKIM signatures
            return []

        results: List[DKIMSignatureResult] = []
        for idx in range(len(sig_indices)):
            res = await self._verify_single_signature(raw, idx, from_domain)
            results.append(res)

        return results

    async def _verify_single_signature(
        self,
        raw_bytes: bytes,
        idx: int,
        from_domain: Optional[str],
    ) -> DKIMSignatureResult:
        """Evaluates a single signature at 0-based DKIM-Signature header index `idx`."""
        try:
            d_sig = dkim.DKIM(raw_bytes)
            try:
                prep = d_sig.verify_headerprep(idx)
                if not prep:
                    return DKIMSignatureResult(
                        index=idx,
                        status=ProtocolStatus.PERMERROR,
                        evaluation_state=DKIMEvaluationState.EVALUATED_COMPLETED,
                        reason_code="MISSING_DKIM_SIGNATURE_HEADER",
                        error_reason="DKIM-Signature header missing or inaccessible",
                    )
                sig, include_headers, sigheaders = prep
            except (
                dkim.MessageFormatError,
                dkim.ParameterError,
                dkim.InvalidCanonicalizationPolicyError,
                dkim.ValidationError,
            ) as exc:
                return DKIMSignatureResult(
                    index=idx,
                    status=ProtocolStatus.PERMERROR,
                    evaluation_state=DKIMEvaluationState.EVALUATED_COMPLETED,
                    reason_code="MALFORMED_DKIM_SIGNATURE",
                    error_reason=f"Malformed DKIM-Signature header ({type(exc).__name__})",
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("Unexpected error preparing DKIM signature %d (%s)", idx, type(exc).__name__)
                return DKIMSignatureResult(
                    index=idx,
                    status=ProtocolStatus.INDETERMINATE,
                    evaluation_state=DKIMEvaluationState.INCOMPLETE_INTERNAL_ERROR,
                    reason_code="DKIM_INTERNAL_HEADERPREP_ERROR",
                    error_reason=f"DKIM internal header preparation exception ({type(exc).__name__})",
                )

            # Extract tags
            domain = sig.get(b"d", b"").decode("utf-8", errors="replace").strip()
            selector = sig.get(b"s", b"").decode("utf-8", errors="replace").strip()
            identity = (
                sig.get(b"i", b"").decode("utf-8", errors="replace").strip()
                if b"i" in sig else f"@{domain}"
            )
            algo = sig.get(b"a", b"").decode("utf-8", errors="replace").strip().lower()
            canon_raw = sig.get(b"c", b"simple/simple").decode("utf-8", errors="replace").strip().lower()
            canon = canon_raw if "/" in canon_raw else f"{canon_raw}/simple"
            b_raw = sig.get(b"b", b"").decode("utf-8", errors="replace").strip()
            b_clean = re.sub(r"[\s\r\n]+", "", b_raw)
            sig_b_prefix = b_clean[:8] if b_clean else None

            # Compute diagnostic From-domain alignment (PSL heuristic only — never authoritative for DMARC!)
            # Authoritative RFC 9989 §4.10.2 alignment is determined by DMARCEvaluator via DNS Tree Walk.
            aligned_strict = False
            aligned_relaxed = False
            if from_domain and domain:
                f_norm = from_domain.strip().lower()
                d_norm = domain.lower()
                aligned_strict = (d_norm == f_norm)
                org_from = get_registered_domain_offline(f_norm)
                org_d = get_registered_domain_offline(d_norm)
                aligned_relaxed = aligned_strict or (bool(org_from) and bool(org_d) and org_from == org_d)
            is_aligned = aligned_relaxed

            base_res = {
                "index": idx,
                "selector": selector,
                "domain": domain,
                "identity": identity,
                "algorithm": algo,
                "signature_b_prefix": sig_b_prefix,
                "canonicalization": canon,
                "is_aligned_with_from": is_aligned,
                "aligned_relaxed": aligned_relaxed,
                "aligned_strict": aligned_strict,
                "alignment_source": "standalone_psl_diagnostic_only" if from_domain and domain else "uncomputed",
                "alignment_is_authoritative": False,
                "standalone_psl_aligned_relaxed": aligned_relaxed if from_domain and domain else None,
            }

            # 1. Algorithm enforcement (RFC 8301, RFC 8463)
            if algo in ("rsa-sha1", "sha1") or algo.endswith("-sha1"):
                return DKIMSignatureResult(
                    **base_res,
                    status=ProtocolStatus.PERMERROR,
                    evaluation_state=DKIMEvaluationState.EVALUATED_COMPLETED,
                    reason_code="INSECURE_ALGORITHM_SHA1",
                    error_reason="Insecure algorithm rsa-sha1 disallowed by RFC 8301",
                )

            if algo not in ("rsa-sha256", "ed25519-sha256"):
                return DKIMSignatureResult(
                    **base_res,
                    status=ProtocolStatus.PERMERROR,
                    evaluation_state=DKIMEvaluationState.EVALUATED_COMPLETED,
                    reason_code="UNSUPPORTED_ALGORITHM",
                    error_reason=f"Unsupported signature algorithm '{algo}'",
                )

            # 2. Canonicalization validation (RFC 6376 Section 3.4)
            c_parts = canon.split("/")
            if len(c_parts) != 2 or c_parts[0] not in ("simple", "relaxed") or c_parts[1] not in ("simple", "relaxed"):
                return DKIMSignatureResult(
                    **base_res,
                    status=ProtocolStatus.PERMERROR,
                    evaluation_state=DKIMEvaluationState.EVALUATED_COMPLETED,
                    reason_code="UNSUPPORTED_CANONICALIZATION",
                    error_reason=f"Unsupported canonicalization mode '{canon}'",
                )

            # 3. Asynchronous DNS public key resolution
            query_name = f"{selector}._domainkey.{domain}"
            dns_res = await self._resolver.resolve(query_name, DNSQueryType.TXT)

            if dns_res.is_transient_error or dns_res.is_malformed_response:
                err_msg = dns_res.error_message or dns_res.status.value
                return DKIMSignatureResult(
                    **base_res,
                    status=ProtocolStatus.TEMPERROR,
                    evaluation_state=DKIMEvaluationState.INCOMPLETE_TRANSIENT_ERROR,
                    reason_code="DKIM_DNS_TRANSIENT_ERROR",
                    error_reason=f"DNS transient error retrieving DKIM key: {err_msg}",
                )

            if dns_res.is_invalid_query or dns_res.is_internal_error or dns_res.status == DNSResponseStatus.ERROR:
                err_msg = dns_res.error_message or dns_res.status.value
                return DKIMSignatureResult(
                    **base_res,
                    status=ProtocolStatus.INDETERMINATE,
                    evaluation_state=DKIMEvaluationState.INCOMPLETE_INTERNAL_ERROR,
                    reason_code="DKIM_DNS_INTERNAL_OR_INVALID_QUERY",
                    error_reason=f"DNS invalid query or internal resolver error retrieving DKIM key: {err_msg}",
                )

            txt_values = dns_res.txt_values()
            if dns_res.is_authoritative_absence or not txt_values:
                return DKIMSignatureResult(
                    **base_res,
                    status=ProtocolStatus.PERMERROR,
                    evaluation_state=DKIMEvaluationState.EVALUATED_COMPLETED,
                    reason_code="DKIM_PUBLIC_KEY_NOT_FOUND",
                    error_reason="DKIM public key record not found (NXDOMAIN or empty)",
                )

            if len(txt_values) > 1:
                # RFC 6376 Section 3.6.2.2: multiple records must be treated as invalid
                return DKIMSignatureResult(
                    **base_res,
                    status=ProtocolStatus.PERMERROR,
                    evaluation_state=DKIMEvaluationState.EVALUATED_COMPLETED,
                    reason_code="MULTIPLE_DKIM_KEY_RECORDS",
                    error_reason="Multiple DKIM key records found in DNS (RFC 6376 Section 3.6.2.2 requires key to be treated as invalid)",
                )

            # 4. Public key record parsing & key size validation
            txt_record_str = txt_values[0]
            txt_bytes = txt_record_str.encode("ascii", errors="replace")

            try:
                pk, ksize, ktag, _ = dkim.evaluate_pk(query_name.encode("ascii"), txt_bytes)
            except (
                dkim.KeyFormatError,
                binascii.Error,
                dkim.UnknownKeyTypeError,
                dkim.NaClNotFoundError,
                dkim.UnparsableKeyError,
                ValueError,
            ) as exc:
                return DKIMSignatureResult(
                    **base_res,
                    status=ProtocolStatus.PERMERROR,
                    evaluation_state=DKIMEvaluationState.EVALUATED_COMPLETED,
                    reason_code="MALFORMED_DKIM_PUBLIC_KEY",
                    error_reason=f"Malformed DKIM public key record ({type(exc).__name__})",
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("Unexpected error parsing DKIM public key %s (%s)", query_name, type(exc).__name__)
                return DKIMSignatureResult(
                    **base_res,
                    status=ProtocolStatus.INDETERMINATE,
                    evaluation_state=DKIMEvaluationState.INCOMPLETE_INTERNAL_ERROR,
                    reason_code="DKIM_INTERNAL_KEY_PARSE_ERROR",
                    error_reason=f"DKIM internal key-parsing exception ({type(exc).__name__})",
                )

            # Key type vs algorithm consistency
            if algo == "ed25519-sha256" and ktag != b"ed25519":
                return DKIMSignatureResult(
                    **base_res,
                    status=ProtocolStatus.PERMERROR,
                    evaluation_state=DKIMEvaluationState.EVALUATED_COMPLETED,
                    reason_code="DKIM_KEY_TYPE_MISMATCH",
                    error_reason=f"Key type '{ktag.decode(errors='replace') if ktag else ''}' does not match algorithm ed25519-sha256",
                )
            if algo == "rsa-sha256" and ktag != b"rsa":
                return DKIMSignatureResult(
                    **base_res,
                    status=ProtocolStatus.PERMERROR,
                    evaluation_state=DKIMEvaluationState.EVALUATED_COMPLETED,
                    reason_code="DKIM_KEY_TYPE_MISMATCH",
                    error_reason=f"Key type '{ktag.decode(errors='replace') if ktag else ''}' does not match algorithm rsa-sha256",
                )

            # RSA key size lower bound (RFC 8301)
            if ktag == b"rsa" and ksize is not None and ksize < 1024:
                return DKIMSignatureResult(
                    **base_res,
                    key_size_bits=ksize,
                    status=ProtocolStatus.PERMERROR,
                    evaluation_state=DKIMEvaluationState.EVALUATED_COMPLETED,
                    reason_code="DKIM_WEAK_RSA_KEY",
                    error_reason=f"RSA key size too small ({ksize} bits); minimum is 1024 bits per RFC 8301",
                )

            # 5. Delegate CPU-bound cryptographic verification to DKIMExecutor
            try:
                verified, resolved_ksize = await self.executor.submit(
                    _verify_signature_worker,
                    raw_bytes,
                    idx,
                    txt_bytes,
                    1024,
                    timeout=self._config.dkim_verification_timeout,
                )
            except (DKIMCapacityExhaustedError, asyncio.TimeoutError) as exc:
                return DKIMSignatureResult(
                    **base_res,
                    key_size_bits=ksize,
                    status=ProtocolStatus.TEMPERROR,
                    evaluation_state=DKIMEvaluationState.INCOMPLETE_TRANSIENT_ERROR,
                    reason_code="DKIM_WORKER_TIMEOUT_OR_EXHAUSTED",
                    error_reason=f"DKIM verification worker unavailable or timed out ({type(exc).__name__})",
                )
            except (DKIMExecutorShuttingDownError, DKIMShutdownCancelledError) as exc:
                return DKIMSignatureResult(
                    **base_res,
                    key_size_bits=ksize,
                    status=ProtocolStatus.TEMPERROR,
                    evaluation_state=DKIMEvaluationState.INCOMPLETE_TRANSIENT_ERROR,
                    reason_code="DKIM_EXECUTOR_SHUTTING_DOWN",
                    error_reason=f"DKIM executor shutting down ({type(exc).__name__})",
                )
            except dkim.ValidationError as exc:
                return DKIMSignatureResult(
                    **base_res,
                    key_size_bits=ksize,
                    status=ProtocolStatus.FAIL,
                    evaluation_state=DKIMEvaluationState.EVALUATED_COMPLETED,
                    reason_code="SIGNATURE_VERIFICATION_FAILED",
                    error_reason=f"DKIM cryptographic signature verification failed ({type(exc).__name__})",
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("Unexpected worker exception during DKIM verification (%s)", type(exc).__name__)
                return DKIMSignatureResult(
                    **base_res,
                    key_size_bits=ksize,
                    status=ProtocolStatus.INDETERMINATE,
                    evaluation_state=DKIMEvaluationState.INCOMPLETE_INTERNAL_ERROR,
                    reason_code="DKIM_INTERNAL_WORKER_ERROR",
                    error_reason=f"DKIM internal verification exception ({type(exc).__name__})",
                )

            final_key_size = resolved_ksize or ksize
            if verified:
                return DKIMSignatureResult(
                    **base_res,
                    key_size_bits=final_key_size,
                    status=ProtocolStatus.PASS,
                    evaluation_state=DKIMEvaluationState.EVALUATED_COMPLETED,
                    reason_code="DKIM_VERIFIED",
                    error_reason=None,
                )
            else:
                return DKIMSignatureResult(
                    **base_res,
                    key_size_bits=final_key_size,
                    status=ProtocolStatus.FAIL,
                    evaluation_state=DKIMEvaluationState.EVALUATED_COMPLETED,
                    reason_code="SIGNATURE_VERIFICATION_FAILED",
                    error_reason="DKIM cryptographic signature verification failed",
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("Unexpected DKIM evaluation exception (%s)", type(exc).__name__)
            return DKIMSignatureResult(
                index=idx,
                status=ProtocolStatus.INDETERMINATE,
                evaluation_state=DKIMEvaluationState.INCOMPLETE_INTERNAL_ERROR,
                reason_code="DKIM_INTERNAL_EVALUATION_ERROR",
                error_reason=f"DKIM internal evaluation exception ({type(exc).__name__})",
            )

    async def evaluate_auth_protocol(
        self,
        message_bytes: Optional[bytes],
        from_domain: Optional[str] = None,
    ) -> AuthProtocolsResult:
        """Evaluates DKIM and populates an AuthProtocolsResult model."""
        signatures = await self.verify(message_bytes, from_domain=from_domain)
        if message_bytes is None or not isinstance(message_bytes, (bytes, bytearray)) or len(message_bytes) == 0:
            dkim_eval_state = DKIMEvaluationState.NOT_EVALUATED_MISSING_RAW_BYTES
            dkim_status = signatures[0].status if signatures else ProtocolStatus.NOT_EVALUATED
            dkim_domain = None
        elif not signatures:
            dkim_eval_state = DKIMEvaluationState.EVALUATED_NO_SIGNATURES
            dkim_status = ProtocolStatus.NONE
            dkim_domain = None
        else:
            pass_sigs = [s for s in signatures if s.status == ProtocolStatus.PASS]
            has_internal = any(
                s.evaluation_state == DKIMEvaluationState.INCOMPLETE_INTERNAL_ERROR
                or s.status in (ProtocolStatus.INDETERMINATE, ProtocolStatus.NOT_EVALUATED)
                for s in signatures
            )
            has_temperror = any(
                s.evaluation_state == DKIMEvaluationState.INCOMPLETE_TRANSIENT_ERROR
                or s.status == ProtocolStatus.TEMPERROR
                for s in signatures
            )
            if pass_sigs:
                dkim_eval_state = DKIMEvaluationState.EVALUATED_COMPLETED
                dkim_status = ProtocolStatus.PASS
                dkim_domain = pass_sigs[0].domain
            elif has_temperror:
                dkim_eval_state = DKIMEvaluationState.INCOMPLETE_TRANSIENT_ERROR
                dkim_status = ProtocolStatus.TEMPERROR
                dkim_domain = signatures[0].domain
            elif has_internal:
                dkim_eval_state = DKIMEvaluationState.INCOMPLETE_INTERNAL_ERROR
                dkim_status = ProtocolStatus.INDETERMINATE
                dkim_domain = signatures[0].domain
            elif any(s.status == ProtocolStatus.FAIL for s in signatures):
                dkim_eval_state = DKIMEvaluationState.EVALUATED_COMPLETED
                dkim_status = ProtocolStatus.FAIL
                dkim_domain = signatures[0].domain
            else:
                dkim_eval_state = DKIMEvaluationState.EVALUATED_COMPLETED
                dkim_status = ProtocolStatus.PERMERROR
                dkim_domain = signatures[0].domain

        aligned_dkim = any(s.status == ProtocolStatus.PASS and s.is_aligned_with_from for s in signatures)
        return AuthProtocolsResult(
            dkim_status=dkim_status,
            dkim_domain=dkim_domain,
            dkim_evaluation_state=dkim_eval_state,
            dkim_signatures=signatures,
            dmarc_aligned_dkim=aligned_dkim,
            execution_telemetry={
                "dkim_evaluation_state": dkim_eval_state.value,
                "dkim_alignment_source": "standalone_psl_diagnostic_only",
                "dkim_alignment_authoritative": False,
            },
        )
