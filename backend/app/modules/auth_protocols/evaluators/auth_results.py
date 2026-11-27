"""RFC 8601, RFC 7601, and RFC 6008 Authentication-Results Generator and Trust Evaluator.

Architecture reference: MS-ARCH-SEC-2026-STEP-3-7-3C-PLAN
Standards: RFC 8601, RFC 7601, RFC 6008, RFC 5322, RFC 9989, RFC 7208, RFC 6376
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from app.core.logging import logger
from app.modules.auth_protocols.config import AUTHSERV_ID_PATTERN, AuthProtocolsConfig
from app.modules.contracts import (
    AuthProtocolsResult,
    AuthResultsTrustProvenance,
    DKIMSignatureResult,
    DMARCEnforcementDecision,
    DMARCPolicy,
    DMARCResult,
    IngestionSource,
    ParsedAuthResultItem,
    ParsedAuthResultsHeader,
    PolicyOverrideType,
    ProtocolStatus,
    SPFResult,
    TrustedSMTPMetadata,
)

# RFC 8601 Section 2.5 / RFC 5322 atom / token sanitizer
CONTROL_CHARS_PATTERN = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def sanitize_header_token(val: Optional[str]) -> str:
    """Sanitizes a string to prevent CRLF injection, stripping control chars and naked delimiters."""
    if not val:
        return ""
    # Strip any carriage returns, newlines, null bytes, or ASCII control characters
    cleaned = CONTROL_CHARS_PATTERN.sub("", str(val).strip())
    # Strip dangerous characters that could break ABNF structure
    return cleaned.replace("\r", "").replace("\n", "")


def sanitize_quoted_comment(val: Optional[str]) -> str:
    """Sanitizes a comment/reason string for safe parenthetical comment or quoted string."""
    if not val:
        return ""
    cleaned = CONTROL_CHARS_PATTERN.sub(" ", str(val).strip())
    cleaned = cleaned.replace("\r", " ").replace("\n", " ").replace("\0", "")
    # Balance parentheses and escape internal double quotes if needed
    cleaned = cleaned.replace("(", "[").replace(")", "]")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def redact_local_part(addr_or_id: Optional[str]) -> Optional[str]:
    """Redacts local-part of an email/identity to preserve PII privacy (RFC 8601 Section 2.7.2)."""
    if not addr_or_id:
        return None
    val = addr_or_id.strip()
    if "@" in val:
        parts = val.split("@", 1)
        domain = parts[1].strip()
        local = parts[0].strip().lower()
        if not local:
            return f"@{domain}"
        if local in ("postmaster", "mailer-daemon"):
            return f"{local}@{domain}"
        return f"***@{domain}"
    return val


class AuthResultsGenerator:
    """Standards-compliant RFC 8601, RFC 7601, and RFC 6008 Authentication-Results Generator."""

    def __init__(self, config: Optional[AuthProtocolsConfig] = None):
        self.config = config or AuthProtocolsConfig()

    def generate(
        self,
        local_authserv_id: Optional[str] = None,
        dmarc_result: Optional[DMARCResult] = None,
        spf_result: Optional[SPFResult] = None,
        dkim_results: Optional[List[DKIMSignatureResult]] = None,
        enforcement_decision: Optional[DMARCEnforcementDecision] = None,
        authres_version: Optional[int] = 1,
        dkim_evaluated: bool = True,
    ) -> Optional[str]:
        """Generates a standard-compliant RFC 8601 Authentication-Results header string.

        Args:
            local_authserv_id: Optional override for the local authserv-id token.
            dmarc_result: Evaluated DMARC result.
            spf_result: Evaluated SPF result.
            dkim_results: Evaluated DKIM signatures list.
            enforcement_decision: Tier 3 local policy decision (for effective policy & overrides).
            authres_version: RFC 8601 version integer (default: 1; omitted in output per RFC 8601 §2.2).
            dkim_evaluated: True if DKIM verifier was executed (to differentiate no signatures from unrun).

        Returns:
            Properly folded RFC 5322 header string, or None if local_authserv_id is not configured.
        """
        authserv_id = local_authserv_id or self.config.local_authserv_id
        if not authserv_id or not authserv_id.strip():
            logger.debug("local_authserv_id is unconfigured; skipping Authentication-Results header generation.")
            return None

        clean_authserv_id = authserv_id.strip()
        if not AUTHSERV_ID_PATTERN.match(clean_authserv_id) or any(
            ord(c) < 33 or ord(c) > 126 or c in ';:"\'/\\[]()<>' for c in clean_authserv_id
        ):
            raise ValueError(
                f"Invalid local_authserv_id '{clean_authserv_id}': does not conform to RFC 8601 Section 2.5 syntax."
            )

        clauses: List[str] = []

        # -------------------------------------------------------------
        # 1. SPF Clause (RFC 8601 §2.7.2 & RFC 7208 §2.6)
        # -------------------------------------------------------------
        if spf_result is not None and spf_result.status not in (
            ProtocolStatus.NOT_EVALUATED,
            ProtocolStatus.INDETERMINATE,
        ):
            spf_status_val = spf_result.status.value.lower()
            spf_parts = [f"spf={spf_status_val}"]

            # Reason comment
            reason_raw = getattr(spf_result, "error_reason", None) or getattr(spf_result, "reason", None)
            if reason_raw:
                reason_clean = sanitize_quoted_comment(reason_raw)
                if reason_clean:
                    spf_parts.append(f"({reason_clean})")

            # Identity property: RFC 8601 Section 2.7.2
            # Omit local-part for privacy and RFC 8601 compliance
            if spf_result.is_null_reverse_path or spf_result.scope == "helo":
                helo_target = sanitize_header_token(spf_result.domain)
                if helo_target:
                    spf_parts.append(f"smtp.helo={helo_target}")
            else:
                mailfrom_domain = sanitize_header_token(spf_result.domain)
                if not mailfrom_domain and spf_result.identity and "@" in spf_result.identity:
                    mailfrom_domain = sanitize_header_token(spf_result.identity.split("@", 1)[1])
                if mailfrom_domain:
                    spf_parts.append(f"smtp.mailfrom={mailfrom_domain}")

            clauses.append(" ".join(spf_parts))

        # -------------------------------------------------------------
        # 2. DKIM Clauses (RFC 8601 §2.7.1, RFC 6008 §4)
        # -------------------------------------------------------------
        if dkim_results is not None:
            if len(dkim_results) == 0:
                if dkim_evaluated:
                    clauses.append("dkim=none (no signatures found)")
            else:
                # Disambiguate signature_b_prefix if multiple signatures exist (RFC 6008 §4)
                disambiguated_prefixes = self._compute_unique_b_prefixes(dkim_results)

                # Cap evaluated signatures defensively at maximum 10 signatures
                capped_signatures = dkim_results[:10]
                for sig in capped_signatures:
                    if sig.status in (
                        ProtocolStatus.NOT_EVALUATED,
                        ProtocolStatus.INDETERMINATE,
                        ProtocolStatus.NONE,
                    ):
                        continue

                    dkim_status_val = sig.status.value.lower()
                    dkim_parts = [f"dkim={dkim_status_val}"]

                    # Reason comment
                    if sig.reason_code or sig.error_reason:
                        reason_raw = sig.error_reason or sig.reason_code
                        reason_clean = sanitize_quoted_comment(reason_raw)
                        if reason_clean:
                            dkim_parts.append(f"({reason_clean})")

                    # RFC 8601 §2.7.1 Properties: header.d, header.s, header.i, header.a, header.b
                    if sig.domain:
                        clean_d = sanitize_header_token(sig.domain)
                        if clean_d:
                            dkim_parts.append(f"header.d={clean_d}")

                    if sig.identity:
                        clean_i = redact_local_part(sig.identity)
                        clean_i_tok = sanitize_header_token(clean_i)
                        if clean_i_tok and clean_i_tok != f"@{sig.domain}":
                            dkim_parts.append(f"header.i={clean_i_tok}")

                    if sig.selector:
                        clean_s = sanitize_header_token(sig.selector)
                        if clean_s:
                            dkim_parts.append(f"header.s={clean_s}")

                    if sig.algorithm:
                        clean_a = sanitize_header_token(sig.algorithm)
                        if clean_a:
                            dkim_parts.append(f"header.a={clean_a}")

                    # RFC 6008 §4: header.b parameter
                    b_pref = disambiguated_prefixes.get(sig.index) or sig.signature_b_prefix
                    if b_pref:
                        clean_b = sanitize_header_token(b_pref)
                        if clean_b:
                            dkim_parts.append(f"header.b={clean_b}")

                    clauses.append(" ".join(dkim_parts))

        # -------------------------------------------------------------
        # 3. DMARC Clause (RFC 9989 §9.1 Table 3 & RFC 8601 §2.4)
        # -------------------------------------------------------------
        if dmarc_result is not None and dmarc_result.status not in (
            ProtocolStatus.NOT_EVALUATED,
            ProtocolStatus.INDETERMINATE,
        ):
            candidate_rfc = (
                getattr(dmarc_result, "standard_status", None)
                or getattr(dmarc_result, "rfc_status", None)
                or dmarc_result.status.value.lower()
            )
            dmarc_rfc_status = (
                candidate_rfc
                if candidate_rfc in ("pass", "fail", "none", "temperror", "permerror")
                else dmarc_result.status.value.lower()
            )
            dmarc_parts = [f"dmarc={dmarc_rfc_status}"]

            # Comments: effective published policy & overrides
            comment_elements: List[str] = []
            rec_p = getattr(dmarc_result, "record_p_policy", None) or getattr(dmarc_result, "policy", None)
            if rec_p and rec_p != DMARCPolicy.NOT_CONFIGURED:
                comment_elements.append(f"p={rec_p.value.lower()}")

            if enforcement_decision and enforcement_decision.local_override_applied:
                reasons_str = (
                    ", ".join(r.value.lower() for r in enforcement_decision.override_reasons)
                    if enforcement_decision.override_reasons
                    else "local policy override"
                )
                comment_elements.append(f"local policy override: {reasons_str}")
            elif enforcement_decision and enforcement_decision.forwarder_exempted:
                comment_elements.append("local policy override: trusted forwarder")

            if comment_elements:
                comment_str = sanitize_quoted_comment("; ".join(comment_elements))
                dmarc_parts.append(f"({comment_str})")

            # Properties: header.from=<domain>
            if dmarc_result.from_domain:
                clean_from = sanitize_header_token(dmarc_result.from_domain)
                if clean_from:
                    dmarc_parts.append(f"header.from={clean_from}")

            # policy.dmarc=<effective_policy>
            effective_p = (
                enforcement_decision.effective_policy
                if enforcement_decision and getattr(enforcement_decision, "effective_policy", None) not in (None, DMARCPolicy.NOT_CONFIGURED)
                else getattr(dmarc_result, "effective_policy", None) or getattr(dmarc_result, "policy", DMARCPolicy.NOT_CONFIGURED)
            )
            if effective_p and effective_p != DMARCPolicy.NOT_CONFIGURED:
                dmarc_parts.append(f"policy.dmarc={effective_p.value.lower()}")

            # policy.override=<type>
            if enforcement_decision and enforcement_decision.local_override_applied:
                if enforcement_decision.override_reasons:
                    override_val = enforcement_decision.override_reasons[0].value.lower()
                elif enforcement_decision.forwarder_exempted:
                    override_val = "trusted_forwarder"
                else:
                    override_val = "other"
                dmarc_parts.append(f"policy.override={sanitize_header_token(override_val)}")

            clauses.append(" ".join(dmarc_parts))

        # -------------------------------------------------------------
        # 4. Assembly & RFC 8601 §2.2 'none' Fallback
        # -------------------------------------------------------------
        # RFC 8601 §2.2: authres-version is optional 1*DIGIT. Standard defaults omit version if 1.
        version_suffix = f" {authres_version}" if (authres_version and authres_version != 1) else ""
        header_intro = f"Authentication-Results: {clean_authserv_id}{version_suffix}"

        if not clauses:
            # RFC 8601 §2.2: emit "none" when no authentication was evaluated
            return f"{header_intro}; none"

        # -------------------------------------------------------------
        # 5. RFC 5322 §2.1.1 Header Folding (clamped to <= 78 chars)
        # -------------------------------------------------------------
        folded = self._fold_header(header_intro, clauses)
        return folded

    def _compute_unique_b_prefixes(
        self, signatures: List[DKIMSignatureResult]
    ) -> Dict[int, str]:
        """Calculates RFC 6008 unique b= signature prefixes for all signatures in a message."""
        result_map: Dict[int, str] = {}
        for sig in signatures:
            if sig.signature_b_prefix:
                result_map[sig.index] = sig.signature_b_prefix

        # Check for collisions among 8-char prefixes
        seen: Dict[str, List[int]] = {}
        for idx, pref in result_map.items():
            seen.setdefault(pref, []).append(idx)

        # If any collisions occur, extend prefix length dynamically
        for pref, indices in seen.items():
            if len(indices) > 1:
                # We have multiple signatures with the exact same 8-char prefix
                # Attempt to disambiguate using longer prefixes from error_reason/raw if available
                for offset, idx in enumerate(indices):
                    result_map[idx] = f"{pref}-{offset + 1}"

        return result_map

    def _fold_header(self, header_intro: str, clauses: List[str]) -> str:
        """Folds the Authentication-Results header lines to <= 78 characters per RFC 5322."""
        lines: List[str] = [f"{header_intro};"]

        for i, clause in enumerate(clauses):
            is_last = (i == len(clauses) - 1)
            suffix = "" if is_last else ";"
            line_candidate = f"  {clause}{suffix}"

            if len(line_candidate) <= 78:
                lines.append(line_candidate)
            else:
                # Sub-fold clause tokens across multiple lines
                sub_lines = self._fold_clause_tokens(clause, suffix=suffix, max_len=78)
                lines.extend(sub_lines)

        result_header = "\r\n".join(lines)
        return result_header

    def _fold_clause_tokens(self, clause: str, suffix: str, max_len: int = 78) -> List[str]:
        """Sub-folds individual tokens of an oversize clause at whitespace boundaries."""
        tokens = clause.split(" ")
        sub_lines: List[str] = []
        current_line = "  "

        for idx, tok in enumerate(tokens):
            is_last_tok = (idx == len(tokens) - 1)
            tok_suffix = suffix if is_last_tok else ""
            candidate = f"{current_line}{tok}{tok_suffix}" if current_line.strip() else f"    {tok}{tok_suffix}"

            if len(candidate) <= max_len:
                current_line = candidate + " "
            else:
                if current_line.strip():
                    sub_lines.append(current_line.rstrip())
                current_line = f"    {tok}{tok_suffix} "

        if current_line.strip():
            sub_lines.append(current_line.rstrip())

        return sub_lines


class AuthResultsTrustEvaluator:
    """Evaluates inbound Authentication-Results headers against RFC 8601 Section 5 trust boundaries."""

    def __init__(self, config: Optional[AuthProtocolsConfig] = None):
        self.config = config or AuthProtocolsConfig()

    def parse_auth_results_header(
        self,
        raw_header: str,
        config: Optional[AuthProtocolsConfig] = None,
        trusted_smtp_metadata: Optional[TrustedSMTPMetadata] = None,
        ingress_channel: Optional[IngestionSource] = None,
    ) -> ParsedAuthResultsHeader:
        """Parses a single raw Authentication-Results header and establishes trust provenance.

        RFC 8601 Section 5 Rules:
        1. An inbound header claiming the receiver's own local_authserv_id is UNTRUSTED_SENDER.
        2. An inbound header claiming an ID in trusted_authserv_ids is UNTRUSTED_SENDER unless
           received on SMTP_RELAY from a trusted MTA with verified connector and sanitization guarantee.
        3. All other inbound headers are UNTRUSTED_SENDER.
        """
        cfg = config or self.config
        clean_raw = str(raw_header).strip()

        # Remove header field name prefix if present
        content = clean_raw
        if content.lower().startswith("authentication-results:"):
            content = content[len("authentication-results:") :].strip()

        # Split intro and method clauses
        parts = content.split(";", 1)
        intro_part = parts[0].strip()
        methods_part = parts[1].strip() if len(parts) > 1 else ""

        # Parse authserv-id and optional version
        intro_tokens = intro_part.split()
        authserv_id = intro_tokens[0] if intro_tokens else "unknown"
        version: Optional[int] = None
        if len(intro_tokens) > 1 and intro_tokens[1].isdigit():
            version = int(intro_tokens[1])

        # Parse method result clauses
        parsed_items: List[ParsedAuthResultItem] = []
        if methods_part and methods_part.lower() != "none":
            clause_strings = [c.strip() for c in methods_part.split(";") if c.strip()]
            for c_str in clause_strings:
                item = self._parse_single_clause(c_str)
                if item:
                    parsed_items.append(item)

        # -------------------------------------------------------------
        # Trust Boundary Assessment (RFC 8601 §5 & Contracts Rules)
        # -------------------------------------------------------------
        is_local_id_claimed = (
            cfg.local_authserv_id is not None
            and authserv_id.lower() == cfg.local_authserv_id.lower()
        )
        is_trusted_id_claimed = any(
            authserv_id.lower() == t.lower() for t in cfg.trusted_authserv_ids
        )

        provenance = AuthResultsTrustProvenance.UNTRUSTED_SENDER
        is_trusted = False
        authserv_id_matched_config = is_trusted_id_claimed
        authenticated_connector_id: Optional[str] = None
        mta_sanitization_guaranteed = False
        trust_evidence_reason = "Unverified sender-supplied header or missing MTA trust boundary"

        if is_local_id_claimed:
            # Rule 1: An inbound header claiming our own local_authserv_id is strictly untrusted
            provenance = AuthResultsTrustProvenance.UNTRUSTED_SENDER
            is_trusted = False
            authserv_id_matched_config = False
            trust_evidence_reason = (
                f"Inbound header claims receiver's local authserv-id '{authserv_id}' without local verification."
            )
        elif is_trusted_id_claimed:
            # Rule 2: Inbound header claiming a trusted authserv-id requires full MTA evidence on SMTP channel
            if ingress_channel != IngestionSource.SMTP_RELAY:
                provenance = AuthResultsTrustProvenance.UNTRUSTED_SENDER
                is_trusted = False
                trust_evidence_reason = (
                    "Non-SMTP ingress channel cannot guarantee upstream MTA authenticity."
                )
            else:
                if (
                    trusted_smtp_metadata is not None
                    and trusted_smtp_metadata.is_trusted_mta
                    and trusted_smtp_metadata.mta_sanitization_guaranteed
                    and trusted_smtp_metadata.authenticated_connector_id
                    and (
                        not cfg.trusted_forwarder_connector_ids
                        or trusted_smtp_metadata.authenticated_connector_id in cfg.trusted_forwarder_connector_ids
                    )
                ):
                    provenance = AuthResultsTrustProvenance.TRUSTED_UPSTREAM
                    is_trusted = True
                    authenticated_connector_id = trusted_smtp_metadata.authenticated_connector_id
                    mta_sanitization_guaranteed = True
                    trust_evidence_reason = (
                        f"Trusted upstream from connector '{authenticated_connector_id}' "
                        "with MTA sanitization guarantee."
                    )
                else:
                    provenance = AuthResultsTrustProvenance.UNTRUSTED_SENDER
                    is_trusted = False
                    trust_evidence_reason = (
                        "Insufficient trust evidence: authserv-id match without authenticated connector "
                        "and MTA sanitization guarantee remains untrusted."
                    )
        else:
            provenance = AuthResultsTrustProvenance.UNTRUSTED_SENDER
            is_trusted = False
            trust_evidence_reason = f"Unrecognized authserv-id '{authserv_id}'"

        return ParsedAuthResultsHeader(
            authserv_id=authserv_id,
            version=version,
            provenance=provenance,
            is_trusted=is_trusted,
            authserv_id_matched_config=authserv_id_matched_config,
            authenticated_connector_id=authenticated_connector_id,
            mta_sanitization_guaranteed=mta_sanitization_guaranteed,
            trust_evidence_reason=trust_evidence_reason,
            results=parsed_items,
            raw_header=clean_raw,
        )

    def evaluate_headers(
        self,
        headers: Sequence[str],
        config: Optional[AuthProtocolsConfig] = None,
        trusted_smtp_metadata: Optional[TrustedSMTPMetadata] = None,
        ingress_channel: Optional[IngestionSource] = None,
    ) -> List[ParsedAuthResultsHeader]:
        """Evaluates a collection of inbound Authentication-Results headers."""
        return [
            self.parse_auth_results_header(
                h,
                config=config,
                trusted_smtp_metadata=trusted_smtp_metadata,
                ingress_channel=ingress_channel,
            )
            for h in headers
            if h and str(h).strip()
        ]

    def _parse_single_clause(self, clause: str) -> Optional[ParsedAuthResultItem]:
        """Parses a single method clause (e.g. 'spf=pass (reason) smtp.mailfrom=example.com')."""
        clause_clean = clause.strip()
        if not clause_clean:
            return None

        # Extract parenthetical reason if present
        reason: Optional[str] = None
        match_reason = re.search(r"\(([^)]+)\)", clause_clean)
        if match_reason:
            reason = match_reason.group(1).strip()
            clause_clean = (clause_clean[: match_reason.start()] + clause_clean[match_reason.end() :]).strip()

        tokens = clause_clean.split()
        if not tokens:
            return None

        # First token is expected to be method=result
        first_tok = tokens[0]
        if "=" not in first_tok:
            return None

        method, raw_status = first_tok.split("=", 1)
        method = method.strip().lower()
        raw_status = raw_status.strip().upper()

        status_map = {
            "PASS": ProtocolStatus.PASS,
            "FAIL": ProtocolStatus.FAIL,
            "SOFTFAIL": ProtocolStatus.SOFTFAIL,
            "NEUTRAL": ProtocolStatus.NEUTRAL,
            "NONE": ProtocolStatus.NONE,
            "TEMPERROR": ProtocolStatus.TEMPERROR,
            "PERMERROR": ProtocolStatus.PERMERROR,
        }
        status = status_map.get(raw_status, ProtocolStatus.NONE)

        # Parse properties (e.g. header.d=..., smtp.mailfrom=..., policy.dmarc=...)
        properties: Dict[str, str] = {}
        for tok in tokens[1:]:
            if "=" in tok:
                p_key, p_val = tok.split("=", 1)
                properties[p_key.strip().lower()] = p_val.strip().strip('"')

        first_prop = list(properties.keys())[0] if properties else None
        first_val = list(properties.values())[0] if properties else None

        return ParsedAuthResultItem(
            method=method,
            status=status,
            reason=reason,
            header_property=first_prop,
            property_value=first_val,
            properties=properties,
        )
