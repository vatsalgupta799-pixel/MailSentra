"""Cross-dataset evaluation engine connecting dataset adapters to MailSentra detection modules."""

import os
import json
import asyncio
import concurrent.futures
import email.message
import tarfile
from typing import Dict, List, Any, Optional
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


class DatasetEvaluator:
    """Executes genuine evaluation runs across normalized dataset samples using production modules."""

    def __init__(self, offline_auth: bool = True):
        self.offline_auth = offline_auth
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

        # 4. RFC 822 reconstruction from structured fields
        msg = email.message.EmailMessage()
        msg["From"] = rec.get("from") or rec.get("sender") or "unknown@sender.invalid"
        msg["To"] = rec.get("to") or "recipient@example.com"
        msg["Subject"] = rec.get("subject") or ""
        if rec.get("message_id"):
            msg["Message-ID"] = str(rec["message_id"])
        if rec.get("date"):
            msg["Date"] = str(rec["date"])
        if rec.get("return_path"):
            msg["Return-Path"] = str(rec["return_path"])

        body_html = rec.get("body_html")
        body_plain = rec.get("body_plain") or rec.get("body") or rec.get("text") or ""

        if body_html and body_plain:
            msg.set_content(body_plain)
            msg.add_alternative(body_html, subtype="html")
        elif body_html:
            msg.set_content(body_html, subtype="html")
        else:
            msg.set_content(body_plain)

        return msg.as_bytes()

    def evaluate_url_dataset(self, sample_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        adapter = UrlDatasetAdapter("DS-URL-EVAL", DatasetCategory.MALICIOUS_URLS, "Module 4")
        processed = self.pipeline.ingest_records(adapter, sample_records)
        train_set, test_set = self.pipeline.split_records(processed)

        tp, fp, tn, fn = 0, 0, 0, 0
        details = []

        # Run detection on test split
        for rec in test_set:
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
            "total_tested": len(test_set),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "specificity": round(specificity, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
            "details": details,
        }

    def evaluate_attachment_dataset(self, sample_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        adapter = AttachmentDatasetAdapter("DS-MA-EVAL", DatasetCategory.MALWARE_ATTACHMENTS, "Module 6")
        processed = self.pipeline.ingest_records(adapter, sample_records)
        train_set, test_set = self.pipeline.split_records(processed)

        tp, fp, tn, fn = 0, 0, 0, 0
        details = []

        for rec in test_set:
            filename = rec["filename"]
            ext = os.path.splitext(filename)[1].lstrip(".")
            size_bytes = rec.get("size_bytes")
            if size_bytes is None:
                size_bytes = len(rec["raw_bytes"]) if isinstance(rec.get("raw_bytes"), (bytes, bytearray)) else 1024

            att_meta = AttachmentMetadata(
                filename=filename,
                original_filename=filename,
                content_type=rec.get("content_type") or "application/octet-stream",
                file_extension=ext,
                size_bytes=size_bytes,
                sha256_hash=rec.get("file_sha256", ""),
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

            details.append({
                "filename": filename,
                "truth": rec["canonical_label"],
                "detected": is_detected_malicious,
                "severity": finding.severity,
            })

        precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if tp == 0 and fp == 0 else 0.0)
        recall = tp / (tp + fn) if (tp + fn) > 0 else (1.0 if tp == 0 and fn == 0 else 0.0)
        specificity = tn / (tn + fp) if (tn + fp) > 0 else (1.0 if tn == 0 and fp == 0 else 0.0)
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        return {
            "category": "malware_attachments",
            "total_tested": len(test_set),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "specificity": round(specificity, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
            "details": details,
        }

    def evaluate_email_dataset(
        self,
        category: DatasetCategory,
        sample_records: List[Dict[str, Any]],
        offline_auth: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Executes full production pipeline evaluation across normalized email records."""
        use_offline_auth = self.offline_auth if offline_auth is None else offline_auth
        adapter = EmailDatasetAdapter(f"DS-{category.value.upper()}-EVAL", category, "Module 1/2/5")
        processed = self.pipeline.ingest_records(adapter, sample_records)
        train_set, test_set = self.pipeline.split_records(processed)

        tp, fp, tn, fn = 0, 0, 0, 0
        details = []

        module_telemetry = {
            "records_parsed": 0,
            "records_identity": 0,
            "records_auth": 0,
            "records_url": 0,
            "records_attachment": 0,
            "records_risk": 0,
            "offline_auth_enforced": use_offline_auth,
        }

        for rec in test_set:
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
            "total_tested": len(test_set),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "specificity": round(specificity, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
            "module_telemetry": module_telemetry,
            "details": details,
        }
