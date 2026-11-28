"""Cross-dataset evaluation engine connecting dataset adapters to MailSentra detection modules."""

import os
import json
import base64
import hashlib
import asyncio
import concurrent.futures
import email.message
import tarfile
from typing import Dict, List, Any, Optional, Tuple
from app.models.scan import RiskTier
from app.modules.contracts import (
    AttachmentMetadata,
    IngestionSource,
    RawEmailPayload,
    UrlRiskSeverity,
)
from app.modules.parser.parser import EmailParser
from app.modules.identity.analyzer import SenderIdentityAnalyzer
from app.modules.auth_protocols.analyzer import AuthProtocolsAnalyzer
from app.modules.url_analysis.analyzer import UrlAnalyzer
from app.modules.url_analysis.config import UrlAnalysisConfig
from app.modules.attachment_analysis.analyzer import AttachmentAnalyzer
from app.modules.risk_engine.engine import RiskEngine
from app.datasets.contracts import CanonicalThreatLabel, DatasetCategory
from app.datasets.adapters import EmailDatasetAdapter, UrlDatasetAdapter, AttachmentDatasetAdapter
from app.datasets.pipeline import DatasetValidationPipeline


DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data"))
RAW_DIR = os.path.join(DATA_DIR, "raw")


def _run_sync(coro):
    """Executes a coroutine safely whether within an event loop or in standard synchronous context."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    else:
        return asyncio.run(coro)


MAX_RECONSTRUCTED_HEADER_LENGTH = 4096


def _sanitize_reconstructed_header(
    val: Any,
    default: str = "",
    max_length: int = MAX_RECONSTRUCTED_HEADER_LENGTH,
) -> str:
    """Sanitizes an email header value for safe RFC 5322 MIME reconstruction.

    Guarantees:
    - Normalizes CR ('\\r') and LF ('\\n') characters to single spaces, preventing CRLF header
      injection and header boundary manipulation.
    - Handles missing, null, non-string, and malformed inputs safely via string coercion.
    - Limits header length to max_length to prevent memory exhaustion or regex DOS.
    - Preserves internal header content while trimming leading/trailing whitespace.
    - Returns `default` if the resulting sanitized string is empty or None.
    """
    if val is None:
        return default

    if not isinstance(val, str):
        try:
            val = str(val)
        except Exception:
            return default

    # Normalize CR and LF characters to space to eliminate header-injection boundaries
    normalized = val.replace("\r", " ").replace("\n", " ")

    # Bound maximum header length
    if len(normalized) > max_length:
        normalized = normalized[:max_length]

    stripped = normalized.strip()
    return stripped if stripped else default


class DatasetEvaluator:
    """Executes genuine evaluation runs across normalized dataset samples using production modules."""

    def __init__(self, offline_auth: bool = True, fixture_mode: bool = False):
        self.offline_auth = offline_auth
        self.fixture_mode = fixture_mode
        self.parser = EmailParser()
        self.identity_analyzer = SenderIdentityAnalyzer()
        self.auth_analyzer = AuthProtocolsAnalyzer(offline_mode=offline_auth)
        self.url_analyzer = UrlAnalyzer(
            config=UrlAnalysisConfig(protected_domains=["microsoft.com", "google.com", "paypal.com", "apple.com"])
        )
        self.attachment_analyzer = AttachmentAnalyzer()
        self.risk_engine = RiskEngine()
        self.pipeline = DatasetValidationPipeline()

    def _prepare_email_payload(self, rec: Dict[str, Any]) -> bytes:
        """Extracts or reconstructs RFC 822 MIME bytes from a record."""
        # 1. Direct raw bytes if present
        raw_bytes = rec.get("raw_bytes")
        if isinstance(raw_bytes, (bytes, bytearray)):
            return bytes(raw_bytes)

        # 2. Raw EML string if present
        raw_eml = rec.get("raw_eml")
        if isinstance(raw_eml, str):
            return raw_eml.encode("utf-8", errors="replace")

        # 3. Archive member extraction if path exists
        archive_member = rec.get("archive_member_path")
        parent_archive = rec.get("parent_archive")
        if parent_archive and os.path.exists(parent_archive) and archive_member:
            try:
                if parent_archive.endswith((".tar.bz2", ".tbz2", ".tar.gz", ".tgz")):
                    with tarfile.open(parent_archive, "r:*") as tar:
                        member = tar.getmember(archive_member)
                        f = tar.extractfile(member)
                        if f:
                            return f.read()
            except Exception:
                pass

        # 4. RFC 822 reconstruction from structured fields (safe against CRLF injection and unhandled CR/LF values)
        msg = email.message.EmailMessage()

        from_val = _sanitize_reconstructed_header(
            rec.get("from") or rec.get("sender"),
            default="unknown@sender.invalid",
        )
        to_val = _sanitize_reconstructed_header(
            rec.get("to"),
            default="recipient@example.com",
        )
        subj_val = _sanitize_reconstructed_header(
            rec.get("subject"),
            default="",
        )

        try:
            msg["From"] = from_val
        except Exception:
            msg["From"] = "unknown@sender.invalid"

        try:
            msg["To"] = to_val
        except Exception:
            msg["To"] = "recipient@example.com"

        try:
            msg["Subject"] = subj_val
        except Exception:
            msg["Subject"] = ""

        if rec.get("message_id") is not None:
            mid_val = _sanitize_reconstructed_header(rec["message_id"])
            if mid_val:
                try:
                    msg["Message-ID"] = mid_val
                except Exception:
                    pass

        if rec.get("date") is not None:
            date_val = _sanitize_reconstructed_header(rec["date"])
            if date_val:
                try:
                    msg["Date"] = date_val
                except Exception:
                    pass

        if rec.get("return_path") is not None:
            rp_val = _sanitize_reconstructed_header(rec["return_path"])
            if rp_val:
                try:
                    msg["Return-Path"] = rp_val
                except Exception:
                    pass

        if rec.get("reply_to") is not None:
            reply_val = _sanitize_reconstructed_header(rec["reply_to"])
            if reply_val:
                try:
                    msg["Reply-To"] = reply_val
                except Exception:
                    pass

        if rec.get("cc") is not None:
            cc_val = _sanitize_reconstructed_header(rec["cc"])
            if cc_val:
                try:
                    msg["Cc"] = cc_val
                except Exception:
                    pass

        body_html = rec.get("body_html")
        if body_html is not None and not isinstance(body_html, str):
            try:
                body_html = str(body_html)
            except Exception:
                body_html = None

        body_plain = rec.get("body_plain") or rec.get("body") or rec.get("text") or ""
        if not isinstance(body_plain, str):
            try:
                body_plain = str(body_plain)
            except Exception:
                body_plain = ""

        try:
            if body_html and body_plain:
                msg.set_content(body_plain)
                msg.add_alternative(body_html, subtype="html")
            elif body_html:
                msg.set_content(body_html, subtype="html")
            else:
                msg.set_content(body_plain)

            return msg.as_bytes()
        except Exception:
            fallback_eml = (
                f"From: {msg.get('From', 'unknown@sender.invalid')}\n"
                f"To: {msg.get('To', 'recipient@example.com')}\n"
                f"Subject: {msg.get('Subject', '')}\n\n"
                f"{body_plain}"
            )
            return fallback_eml.encode("utf-8", errors="replace")

    def evaluate_url_dataset(
        self, sample_records: List[Dict[str, Any]], fixture_mode: Optional[bool] = None
    ) -> Dict[str, Any]:
        adapter = UrlDatasetAdapter("DS-URL-EVAL", DatasetCategory.MALICIOUS_URLS, "Module 4")
        processed = self.pipeline.ingest_records(adapter, sample_records)
        train_set, test_set = self.pipeline.split_records(processed)

        effective_fixture_mode = self.fixture_mode if fixture_mode is None else fixture_mode
        if not test_set:
            if not effective_fixture_mode:
                return {
                    "category": "malicious_urls",
                    "status": "EMPTY_TEST_PARTITION",
                    "total_tested": 0,
                    "error": "Deterministic split yielded empty test partition. Benchmark fallback to training data prohibited to prevent train/test leakage.",
                    "tp": 0, "fp": 0, "tn": 0, "fn": 0,
                    "precision": 0.0, "recall": 0.0, "specificity": 0.0, "f1": 0.0, "fpr": 0.0,
                    "partition_fallback_applied": False,
                    "evaluation_mode": "BENCHMARK_STRICT",
                    "details": [],
                }
            eval_set = processed
            partition_fallback_applied = True
            evaluation_mode = "FIXTURE_FALLBACK"
        else:
            eval_set = test_set
            partition_fallback_applied = False
            evaluation_mode = "BENCHMARK_TEST_SPLIT"

        tp, fp, tn, fn = 0, 0, 0, 0
        details = []

        # Run detection on test split (or processed if fixture_mode enabled)
        for rec in eval_set:
            url = rec["url"]
            finding = self.url_analyzer.analyze_url(url)
            is_detected_malicious = finding.severity.value in ("SUSPICIOUS", "MALICIOUS")
            is_ground_truth_malicious = rec["canonical_label"] in (
                CanonicalThreatLabel.MALICIOUS_URL.value,
                CanonicalThreatLabel.MALWARE_ATTACHMENT.value,
                CanonicalThreatLabel.PHISHING.value,
            )

            if is_ground_truth_malicious and is_detected_malicious:
                tp += 1
            elif not is_ground_truth_malicious and is_detected_malicious:
                fp += 1
            elif not is_ground_truth_malicious and not is_detected_malicious:
                tn += 1
            else:
                fn += 1

            details.append({
                "url": url,
                "truth": rec["canonical_label"],
                "severity": finding.severity.value,
                "reason": finding.reason,
            })

        precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if tp == 0 and fp == 0 else 0.0)
        recall = tp / (tp + fn) if (tp + fn) > 0 else (1.0 if tp == 0 and fn == 0 else 0.0)
        specificity = tn / (tn + fp) if (tn + fp) > 0 else (1.0 if tn == 0 and fp == 0 else 0.0)
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        return {
            "category": "malicious_urls",
            "total_tested": len(eval_set),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "specificity": round(specificity, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
            "partition_fallback_applied": partition_fallback_applied,
            "evaluation_mode": evaluation_mode,
            "details": details,
        }

    def _extract_attachment_payload(
        self, rec: Dict[str, Any], max_limit: Optional[int] = None
    ) -> Tuple[Optional[bytes], Optional[str]]:
        """Safely extracts and validates binary attachment payload bytes from a record.

        Enforces:
        - Strict pre-decode size bounds on Base64 strings:
          max_b64_len = ((max_payload_bytes + 2) // 3) * 4 + 8192
        - Safe handling of raw binary bytes/bytearrays
        - Explicit contract for string payloads:
          Only explicit base64 prefixes ('base64:' or data URIs) or explicit raw_base64 fields
          are base64-decoded. Ambiguous plain-text strings in raw_bytes without prefix are rejected
          with STRING_NOT_BINARY.
        - Telemetry and safe error reporting for oversized or malformed inputs without exceptions.

        Returns:
            Tuple of (raw_payload_bytes, warning_or_error_message)
        """
        if max_limit is None:
            max_limit = self.attachment_analyzer.config.max_attachment_size_bytes

        # Derive strict pre-decode length bound
        max_b64_len = ((max_limit + 2) // 3) * 4 + 8192

        raw_val = rec.get("raw_bytes")
        if raw_val is None:
            raw_val = rec.get("raw_payload")

        # 1. If explicit raw_base64 / payload_base64 field is provided
        raw_b64 = rec.get("raw_base64") or rec.get("payload_base64")
        if raw_b64 is not None:
            if not isinstance(raw_b64, str):
                return None, f"Unsupported raw_base64 type: {type(raw_b64).__name__}"
            if len(raw_b64) > max_b64_len:
                return None, f"OVERSIZED_BASE64: Base64 payload length ({len(raw_b64)}) exceeds pre-decode limit ({max_b64_len})"
            stripped = raw_b64.strip()
            if len(stripped) > max_b64_len:
                return None, f"OVERSIZED_BASE64: Base64 payload length ({len(stripped)}) exceeds pre-decode limit ({max_b64_len})"
            try:
                decoded = base64.b64decode(stripped, validate=True)
                return decoded, None
            except Exception as e:
                return None, f"Invalid base64 payload: {type(e).__name__}"

        # If no raw_bytes / raw_payload provided either, return None, None (metadata-only)
        if raw_val is None:
            return None, None

        # 2. Binary bytes / bytearray
        if isinstance(raw_val, (bytes, bytearray)):
            return bytes(raw_val), None

        # 3. String in raw_bytes / raw_payload
        if isinstance(raw_val, str):
            # Explicit contract: only decode if explicit prefix is present
            if raw_val.startswith("base64:"):
                encoded_part = raw_val[7:]
                if len(encoded_part) > max_b64_len:
                    return None, f"OVERSIZED_BASE64: Base64 payload length ({len(encoded_part)}) exceeds pre-decode limit ({max_b64_len})"
                try:
                    decoded = base64.b64decode(encoded_part.strip(), validate=True)
                    return decoded, None
                except Exception as e:
                    return None, f"Invalid base64 payload: {type(e).__name__}"
            elif raw_val.startswith("data:") and ";base64," in raw_val:
                encoded_part = raw_val.split(";base64,", 1)[1]
                if len(encoded_part) > max_b64_len:
                    return None, f"OVERSIZED_BASE64: Base64 payload length ({len(encoded_part)}) exceeds pre-decode limit ({max_b64_len})"
                try:
                    decoded = base64.b64decode(encoded_part.strip(), validate=True)
                    return decoded, None
                except Exception as e:
                    return None, f"Invalid base64 payload: {type(e).__name__}"
            else:
                # Ambiguous plain-text string without explicit base64 indicator
                return None, "STRING_NOT_BINARY: Plain-text string provided for raw_bytes without explicit base64 indicator"

        # 4. Any other unsupported type
        return None, f"Unsupported raw_bytes type: {type(raw_val).__name__}"

    def evaluate_attachment_dataset(
        self, sample_records: List[Dict[str, Any]], fixture_mode: Optional[bool] = None
    ) -> Dict[str, Any]:
        adapter = AttachmentDatasetAdapter("DS-MA-EVAL", DatasetCategory.MALWARE_ATTACHMENTS, "Module 6")
        processed = self.pipeline.ingest_records(adapter, sample_records)
        train_set, test_set = self.pipeline.split_records(processed)

        effective_fixture_mode = self.fixture_mode if fixture_mode is None else fixture_mode
        if not test_set:
            if not effective_fixture_mode:
                return {
                    "category": "malware_attachments",
                    "status": "EMPTY_TEST_PARTITION",
                    "total_tested": 0,
                    "error": "Deterministic split yielded empty test partition. Benchmark fallback to training data prohibited to prevent train/test leakage.",
                    "tp": 0, "fp": 0, "tn": 0, "fn": 0,
                    "precision": 0.0, "recall": 0.0, "specificity": 0.0, "f1": 0.0, "fpr": 0.0,
                    "partition_fallback_applied": False,
                    "evaluation_mode": "BENCHMARK_STRICT",
                    "details": [],
                }
            eval_set = processed
            partition_fallback_applied = True
            evaluation_mode = "FIXTURE_FALLBACK"
        else:
            eval_set = test_set
            partition_fallback_applied = False
            evaluation_mode = "BENCHMARK_TEST_SPLIT"

        tp, fp, tn, fn = 0, 0, 0, 0
        details = []

        for rec in eval_set:
            filename = rec["filename"]
            ext = os.path.splitext(filename)[1].lstrip(".")

            payload_bytes, payload_warning = self._extract_attachment_payload(rec)

            declared_size = rec.get("size_bytes")
            if declared_size is None:
                declared_size = rec.get("file_size")

            actual_payload_size = len(payload_bytes) if payload_bytes is not None else None

            # Effective size calculation:
            if actual_payload_size is not None:
                effective_size = max(declared_size or 0, actual_payload_size)
            else:
                effective_size = declared_size if declared_size is not None else 1024

            max_limit = self.attachment_analyzer.config.max_attachment_size_bytes
            is_truncated = False
            bounded_payload = payload_bytes

            # Authentic full payload SHA-256 BEFORE defensive truncation
            if payload_bytes is not None:
                original_full_sha256 = hashlib.sha256(payload_bytes).hexdigest()
                sha256_hash = rec.get("sha256") or original_full_sha256
            else:
                sha256_hash = rec.get("file_sha256") or rec.get("sha256")

            # Defensive truncation for memory safety if payload exceeds max_limit
            if payload_bytes is not None and len(payload_bytes) > max_limit:
                bounded_payload = payload_bytes[:max_limit]
                is_truncated = True

            att_meta = AttachmentMetadata(
                filename=filename,
                original_filename=filename,
                content_type=rec.get("content_type") or "application/octet-stream",
                file_extension=ext,
                size_bytes=effective_size,
                sha256_hash=sha256_hash or "",
                raw_payload=bounded_payload,
                is_truncated=is_truncated,
                declared_size_bytes=declared_size,
                actual_payload_size=actual_payload_size,
            )
            finding = self.attachment_analyzer.analyze_single_attachment(att_meta)
            is_detected_malicious = finding.severity in ("SUSPICIOUS", "MALICIOUS")
            is_ground_truth_malicious = rec["canonical_label"] == CanonicalThreatLabel.MALWARE_ATTACHMENT.value

            if is_ground_truth_malicious and is_detected_malicious:
                tp += 1
            elif not is_ground_truth_malicious and is_detected_malicious:
                fp += 1
            elif not is_ground_truth_malicious and not is_detected_malicious:
                tn += 1
            else:
                fn += 1

            detail_item = {
                "filename": filename,
                "truth": rec["canonical_label"],
                "detected": is_detected_malicious,
                "severity": finding.severity,
                "has_raw_payload": payload_bytes is not None,
                "is_truncated": is_truncated,
                "effective_size": effective_size,
                "declared_size": declared_size,
                "actual_payload_size": actual_payload_size,
                "detected_mime": finding.detected_mime,
                "detected_format": finding.detected_format,
                "sha256_hash": finding.sha256_hash,
                "details": finding.details,
            }
            if payload_warning:
                detail_item["payload_warning"] = payload_warning
            details.append(detail_item)

        precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if tp == 0 and fp == 0 else 0.0)
        recall = tp / (tp + fn) if (tp + fn) > 0 else (1.0 if tp == 0 and fn == 0 else 0.0)
        specificity = tn / (tn + fp) if (tn + fp) > 0 else (1.0 if tn == 0 and fp == 0 else 0.0)
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        return {
            "category": "malware_attachments",
            "total_tested": len(eval_set),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "specificity": round(specificity, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
            "partition_fallback_applied": partition_fallback_applied,
            "evaluation_mode": evaluation_mode,
            "details": details,
        }

    def evaluate_email_dataset(
        self,
        category: DatasetCategory,
        sample_records: List[Dict[str, Any]],
        offline_auth: Optional[bool] = None,
        fixture_mode: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Executes full production pipeline evaluation across normalized email records."""
        use_offline_auth = self.offline_auth if offline_auth is None else offline_auth
        adapter = EmailDatasetAdapter(f"DS-{category.value.upper()}-EVAL", category, "Module 1/2/5")
        processed = self.pipeline.ingest_records(adapter, sample_records)
        train_set, test_set = self.pipeline.split_records(processed)

        module_telemetry = {
            "records_parsed": 0,
            "records_identity": 0,
            "records_auth": 0,
            "records_url": 0,
            "records_attachment": 0,
            "records_risk": 0,
            "offline_auth_enforced": use_offline_auth,
        }

        effective_fixture_mode = self.fixture_mode if fixture_mode is None else fixture_mode
        if not test_set:
            if not effective_fixture_mode:
                return {
                    "category": category.value,
                    "status": "EMPTY_TEST_PARTITION",
                    "total_tested": 0,
                    "error": "Deterministic split yielded empty test partition. Benchmark fallback to training data prohibited to prevent train/test leakage.",
                    "tp": 0, "fp": 0, "tn": 0, "fn": 0,
                    "precision": 0.0, "recall": 0.0, "specificity": 0.0, "f1": 0.0, "fpr": 0.0,
                    "partition_fallback_applied": False,
                    "evaluation_mode": "BENCHMARK_STRICT",
                    "module_telemetry": module_telemetry,
                    "details": [],
                }
            eval_set = processed
            partition_fallback_applied = True
            evaluation_mode = "FIXTURE_FALLBACK"
        else:
            eval_set = test_set
            partition_fallback_applied = False
            evaluation_mode = "BENCHMARK_TEST_SPLIT"

        tp, fp, tn, fn = 0, 0, 0, 0
        details = []

        for rec in eval_set:
            payload_bytes = self._prepare_email_payload(rec)
            raw_payload = RawEmailPayload(raw_bytes=payload_bytes, source=IngestionSource.RAW_PAYLOAD)

            # 1. Parse RFC 5322 MIME Structure (Module 1)
            parsed_email = self.parser.parse(raw_payload)
            module_telemetry["records_parsed"] += 1

            # 2. Sender Identity Analysis (Module 3)
            identity_result = _run_sync(self.identity_analyzer.analyze(parsed_email))
            module_telemetry["records_identity"] += 1

            # 3. Authentication Protocols Analysis (Module 4) - Offline safe
            auth_result = _run_sync(
                self.auth_analyzer.analyze(
                    raw_payload=raw_payload,
                    parsed_email=parsed_email,
                    offline_mode=use_offline_auth,
                )
            )
            module_telemetry["records_auth"] += 1

            # 4. URL Security Analysis (Module 5)
            url_result = _run_sync(self.url_analyzer.analyze(parsed_email))
            module_telemetry["records_url"] += 1

            # 5. Attachment Forensics Analysis (Module 6)
            attachment_result = _run_sync(
                self.attachment_analyzer.analyze(parsed_email, raw_payload=raw_payload)
            )
            module_telemetry["records_attachment"] += 1

            # 6. Risk Scoring & Threat Classification (Risk Engine)
            score, tier, summary, assessment = self.risk_engine.evaluate(
                identity_result=identity_result,
                auth_result=auth_result,
                url_result=url_result,
                attachment_result=attachment_result,
            )
            module_telemetry["records_risk"] += 1

            is_detected = (tier in (RiskTier.MALICIOUS, RiskTier.SUSPICIOUS)) or (score >= 35.0)
            is_ground_truth_malicious = rec["canonical_label"] != CanonicalThreatLabel.BENIGN.value

            if is_ground_truth_malicious and is_detected:
                tp += 1
            elif not is_ground_truth_malicious and is_detected:
                fp += 1
            elif not is_ground_truth_malicious and not is_detected:
                tn += 1
            else:
                fn += 1

            details.append({
                "record_id": rec.get("record_id"),
                "subject": rec.get("subject"),
                "truth": rec["canonical_label"],
                "detected": is_detected,
                "risk_score": score,
                "risk_tier": tier.value if hasattr(tier, "value") else str(tier),
                "verdict_summary": summary,
                "contributing_signals": assessment.get("contributing_signals", []),
                "extracted_urls_count": len(parsed_email.urls),
                "attachments_count": len(parsed_email.attachments),
            })

        precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if tp == 0 and fp == 0 else 0.0)
        recall = tp / (tp + fn) if (tp + fn) > 0 else (1.0 if tp == 0 and fn == 0 else 0.0)
        specificity = tn / (tn + fp) if (tn + fp) > 0 else (1.0 if tn == 0 and fn == 0 else 0.0)
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        return {
            "category": category.value,
            "total_tested": len(eval_set),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "specificity": round(specificity, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
            "partition_fallback_applied": partition_fallback_applied,
            "evaluation_mode": evaluation_mode,
            "module_telemetry": module_telemetry,
            "details": details,
        }
