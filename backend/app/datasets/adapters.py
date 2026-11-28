"""Dataset adapters and normalizers for MailSentra."""

import hashlib
from typing import Dict, Any, List, Optional
from app.datasets.contracts import CanonicalThreatLabel, DatasetCategory


class BaseDatasetAdapter:
    """Base class for all MailSentra dataset adapters."""

    def __init__(self, dataset_id: str, category: DatasetCategory, module_target: str):
        self.dataset_id = dataset_id
        self.category = category
        self.module_target = module_target

    def normalize_record(self, raw_record: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    def compute_record_hash(self, text_content: str) -> str:
        return hashlib.sha256(text_content.encode("utf-8")).hexdigest()


class EmailDatasetAdapter(BaseDatasetAdapter):
    """Adapter for email message datasets (Phishing, Spam, BEC, Social Eng, Benign)."""

    def normalize_record(self, raw_record: Dict[str, Any]) -> Dict[str, Any]:
        subject = raw_record.get("subject", "").strip()
        body = raw_record.get("body") or raw_record.get("body_plain") or raw_record.get("text") or ""
        body_html = raw_record.get("body_html")
        if not body and body_html:
            body = body_html.strip()
        else:
            body = body.strip()

        raw_label = str(raw_record.get("canonical_label") or raw_record.get("source_label") or raw_record.get("label", "")).lower()

        # Canonical mapping
        if self.category == DatasetCategory.BENIGN_CONTROLS or raw_label in ("0", "ham", "benign", "legitimate"):
            canonical_label = CanonicalThreatLabel.BENIGN
        elif self.category == DatasetCategory.PHISHING_EMAIL or raw_label in ("1", "phish", "phishing"):
            canonical_label = CanonicalThreatLabel.PHISHING
        elif self.category == DatasetCategory.SPAM_EMAIL or raw_label in ("spam",):
            canonical_label = CanonicalThreatLabel.SPAM
        elif self.category == DatasetCategory.BEC_FRAUD or "bec" in raw_label or "fraud" in raw_label:
            canonical_label = CanonicalThreatLabel.BEC
        elif self.category == DatasetCategory.SOCIAL_ENGINEERING:
            canonical_label = CanonicalThreatLabel.SOCIAL_ENGINEERING
        elif self.category == DatasetCategory.SENDER_SPOOFING:
            canonical_label = CanonicalThreatLabel.SPOOFING
        else:
            canonical_label = CanonicalThreatLabel.UNKNOWN

        content_for_hash = f"{subject}\n{body}"
        sender_val = raw_record.get("from") or raw_record.get("sender", "")
        return {
            "record_id": raw_record.get("record_id") or raw_record.get("id") or self.compute_record_hash(content_for_hash)[:16],
            "dataset_id": raw_record.get("dataset_id") or self.dataset_id,
            "category": self.category.value,
            "subject": subject,
            "body": body,
            "body_html": body_html,
            "body_plain": raw_record.get("body_plain") or body,
            "sender": sender_val,
            "from": sender_val,
            "to": raw_record.get("to", ""),
            "message_id": raw_record.get("message_id"),
            "date": raw_record.get("date"),
            "return_path": raw_record.get("return_path"),
            "campaign_cluster_id": raw_record.get("campaign_cluster_id"),
            "archive_member_path": raw_record.get("archive_member_path"),
            "parent_archive": raw_record.get("parent_archive"),
            "raw_bytes": raw_record.get("raw_bytes"),
            "raw_eml": raw_record.get("raw_eml"),
            "canonical_label": canonical_label.value,
            "original_label": raw_record.get("source_label") or raw_record.get("label"),
            "content_sha256": raw_record.get("content_sha256") or self.compute_record_hash(content_for_hash),
            "target_module": self.module_target,
        }


class UrlDatasetAdapter(BaseDatasetAdapter):
    """Adapter for URL threat datasets."""

    def normalize_record(self, raw_record: Dict[str, Any]) -> Dict[str, Any]:
        url = raw_record.get("url", "").strip()
        raw_label = str(raw_record.get("label", "")).lower()

        if self.category == DatasetCategory.BENIGN_CONTROLS or raw_label in ("0", "benign", "safe"):
            canonical_label = CanonicalThreatLabel.BENIGN
        elif "malware" in raw_label:
            canonical_label = CanonicalThreatLabel.MALWARE_ATTACHMENT
        elif "phish" in raw_label or self.category == DatasetCategory.MALICIOUS_URLS:
            canonical_label = CanonicalThreatLabel.MALICIOUS_URL
        else:
            canonical_label = CanonicalThreatLabel.SUSPICIOUS

        return {
            "record_id": raw_record.get("id") or self.compute_record_hash(url)[:16],
            "dataset_id": self.dataset_id,
            "category": self.category.value,
            "url": url,
            "canonical_label": canonical_label.value,
            "original_label": raw_record.get("label"),
            "content_sha256": self.compute_record_hash(url),
            "target_module": self.module_target,
        }


class AttachmentDatasetAdapter(BaseDatasetAdapter):
    """Adapter for attachment and malware file datasets (disarmed metadata)."""

    def normalize_record(self, raw_record: Dict[str, Any]) -> Dict[str, Any]:
        filename = raw_record.get("filename", "").strip()
        file_type = raw_record.get("file_type", "unknown").strip()
        raw_label = str(raw_record.get("label", "")).lower()

        if raw_label in ("0", "benign", "clean"):
            canonical_label = CanonicalThreatLabel.BENIGN
        else:
            canonical_label = CanonicalThreatLabel.MALWARE_ATTACHMENT

        raw_bytes_val = raw_record.get("raw_bytes")
        if raw_bytes_val is None:
            raw_bytes_val = raw_record.get("raw_payload")

        size_bytes = raw_record.get("size_bytes", raw_record.get("file_size"))
        if size_bytes is None and isinstance(raw_bytes_val, (bytes, bytearray)):
            size_bytes = len(raw_bytes_val)

        content_for_hash = f"{filename}_{file_type}_{raw_record.get('sha256', '')}"
        return {
            "record_id": raw_record.get("record_id") or raw_record.get("id") or self.compute_record_hash(content_for_hash)[:16],
            "dataset_id": self.dataset_id,
            "category": self.category.value,
            "filename": filename,
            "file_type": file_type,
            "file_sha256": raw_record.get("sha256", self.compute_record_hash(filename)),
            "features": raw_record.get("features", {}),
            "canonical_label": canonical_label.value,
            "original_label": raw_record.get("label"),
            "target_module": self.module_target,
            "size_bytes": size_bytes,
            "raw_bytes": raw_bytes_val,
            "raw_base64": raw_record.get("raw_base64") or raw_record.get("payload_base64"),
            "content_type": raw_record.get("content_type"),
        }
