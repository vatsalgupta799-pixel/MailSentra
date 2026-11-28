"""Dedicated Streaming TarBz2 Dataset Ingestion Adapter for MailSentra.

Extracts, normalizes, deduplicates, and redacts email records from authentic
tar.bz2 archives (such as Apache SpamAssassin Public Corpus) while enforcing
strict extraction security bounds and preserving provenance.
"""

import os
import re
import json
import email
import tarfile
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from email.message import Message

from app.datasets.contracts import CanonicalThreatLabel
from app.datasets.mbox_adapter import (
    safe_decode_header,
    redact_pii,
)


class TarExtractionSecurityError(Exception):
    """Raised when an archive member violates safe extraction security policies."""
    pass


class TarBz2DatasetAdapter:
    """Safe streaming ingestion adapter for tar.bz2 archives containing RFC-822 messages."""

    # Security limits
    MAX_ARCHIVE_SIZE_BYTES = 50 * 1024 * 1024        # 50 MB
    MAX_DECOMPRESSED_BYTES = 100 * 1024 * 1024       # 100 MB
    MAX_MEMBERS_COUNT = 10_000                       # 10,000 members
    MAX_PER_MESSAGE_BYTES = 10 * 1024 * 1024         # 10 MB per email

    def __init__(
        self,
        dataset_id: str = "DS-SP-01",
        parent_archive_name: str = "20050311_spam_2.tar.bz2",
        parent_archive_sha256: str = "44280a0e28bf7645b2279e8e42659271ad82c6f40bf8d364dbda7f1df344a765",
        canonical_label: CanonicalThreatLabel = CanonicalThreatLabel.SPAM,
        max_archive_size: int = MAX_ARCHIVE_SIZE_BYTES,
        max_decompressed_size: int = MAX_DECOMPRESSED_BYTES,
        max_members: int = MAX_MEMBERS_COUNT,
        max_per_message: int = MAX_PER_MESSAGE_BYTES,
    ):
        self.dataset_id = dataset_id
        self.parent_archive_name = parent_archive_name
        self.parent_archive_sha256 = parent_archive_sha256
        self.canonical_label = canonical_label

        self.max_archive_size = max_archive_size
        self.max_decompressed_size = max_decompressed_size
        self.max_members = max_members
        self.max_per_message = max_per_message

        # Deduplication and clustering state
        self.seen_raw_hashes: Dict[str, str] = {}
        self.seen_content_hashes: Dict[str, str] = {}
        self.campaign_clusters: Dict[str, List[str]] = {}

        # Parsing and security counters
        self.total_members_inspected = 0
        self.total_regular_files = 0
        self.total_directories_skipped = 0
        self.total_rejected_members = 0
        self.total_parsed = 0
        self.total_malformed = 0
        self.exact_duplicates = 0
        self.campaign_near_duplicates = 0
        self.unique_content_records = 0
        self.mime_anomaly_warnings_count = 0
        self.cumulative_decompressed_bytes = 0

        self.rejected_members_log: List[Dict[str, Any]] = []
        self.empty_body_counts = {
            "NORMAL": 0,
            "ATTACHMENT_ONLY": 0,
            "WHITESPACE_ONLY": 0,
            "EMPTY_MESSAGE": 0,
            "BODY_EXTRACTION_FAILURE": 0,
        }

    def validate_member(self, member: tarfile.TarInfo) -> Tuple[bool, Optional[str], Optional[str]]:
        """Validates a tar member against strict path-traversal, file-type, and size policies.

        Returns (is_valid, rejection_reason, action):
          - True, None, "PROCESS" for regular files to extract
          - False, reason, "SKIP" for benign non-message members (e.g. directories)
          - False, reason, "REJECT" for hazardous members violating security policies
        """
        name = member.name.replace("\\", "/")

        # 1. Absolute path check
        if name.startswith("/") or re.match(r"^[a-zA-Z]:", member.name):
            return False, f"Absolute path rejected: {member.name}", "REJECT"

        # 2. Directory traversal check
        parts = [p for p in name.split("/") if p]
        if ".." in parts:
            return False, f"Path traversal ('..') detected: {member.name}", "REJECT"

        # 3. Directory handling
        if member.isdir():
            return False, f"Directory member skipped: {member.name}", "SKIP"

        # 4. Member type checks: only regular files permitted
        if member.issym():
            return False, f"Symlink rejected: {member.name} -> {member.linkname}", "REJECT"
        if member.islnk():
            return False, f"Hard link rejected: {member.name} -> {member.linkname}", "REJECT"
        if member.ischr() or member.isblk():
            return False, f"Device file rejected: {member.name}", "REJECT"
        if member.isfifo():
            return False, f"FIFO pipe rejected: {member.name}", "REJECT"
        if not member.isreg():
            return False, f"Non-regular file type rejected: {member.name}", "REJECT"

        # 5. Per-message size limit
        if member.size > self.max_per_message:
            return False, f"Member size {member.size} bytes exceeds maximum allowed {self.max_per_message}", "REJECT"

        # 6. Cumulative decompression size limit
        if self.cumulative_decompressed_bytes + member.size > self.max_decompressed_size:
            return False, (
                f"Cumulative decompressed size ({self.cumulative_decompressed_bytes + member.size}) "
                f"would exceed maximum allowed ({self.max_decompressed_size})"
            ), "REJECT"

        return True, None, "PROCESS"

    def extract_body_and_attachments(self, msg: Message) -> Tuple[str, str, List[str]]:
        """Extracts text/plain, text/html, and attachment filenames from a MIME message."""
        plain_parts = []
        html_parts = []
        attachments = []

        try:
            if msg.is_multipart():
                for part in msg.walk():
                    content_disposition = str(part.get("Content-Disposition", ""))
                    filename = part.get_filename()
                    if filename:
                        attachments.append(safe_decode_header(filename))

                    content_type = part.get_content_type()
                    if content_type == "text/plain" and "attachment" not in content_disposition:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            try:
                                plain_parts.append(payload.decode(charset, errors="replace"))
                            except (LookupError, UnicodeDecodeError):
                                plain_parts.append(payload.decode("latin-1", errors="replace"))
                    elif content_type == "text/html" and "attachment" not in content_disposition:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            try:
                                html_parts.append(payload.decode(charset, errors="replace"))
                            except (LookupError, UnicodeDecodeError):
                                html_parts.append(payload.decode("latin-1", errors="replace"))
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    try:
                        text = payload.decode(charset, errors="replace")
                    except (LookupError, UnicodeDecodeError):
                        text = payload.decode("latin-1", errors="replace")
                    if msg.get_content_type() == "text/html":
                        html_parts.append(text)
                    else:
                        plain_parts.append(text)
        except Exception:
            pass

        return "\n".join(plain_parts), "\n".join(html_parts), attachments

    def process_tar_bz2(
        self,
        archive_path: str,
        output_jsonl_path: str,
        summary_json_path: str,
        max_records: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Safely streams members from archive_path, serializes normalized records to
        output_jsonl_path, and saves an audit summary to summary_json_path.
        """
        # Validate archive existence and size
        if not os.path.exists(archive_path):
            raise FileNotFoundError(f"Archive not found: {archive_path}")

        archive_size = os.path.getsize(archive_path)
        if archive_size > self.max_archive_size:
            raise TarExtractionSecurityError(
                f"Archive size {archive_size} exceeds maximum allowable {self.max_archive_size} bytes."
            )

        os.makedirs(os.path.dirname(output_jsonl_path), exist_ok=True)
        os.makedirs(os.path.dirname(summary_json_path), exist_ok=True)

        record_idx = 0
        with open(output_jsonl_path, "w", encoding="utf-8") as out_f:
            with tarfile.open(archive_path, "r:bz2") as tar:
                for member in tar:
                    self.total_members_inspected += 1

                    if self.total_members_inspected > self.max_members:
                        raise TarExtractionSecurityError(
                            f"Archive member count exceeded safety threshold ({self.max_members})"
                        )

                    is_valid, reason, action = self.validate_member(member)

                    if action == "SKIP":
                        self.total_directories_skipped += 1
                        continue

                    if action == "REJECT":
                        self.total_rejected_members += 1
                        self.rejected_members_log.append({
                            "member_name": member.name,
                            "reason": reason,
                            "type": str(member.type),
                        })
                        continue

                    # Process regular file
                    self.total_regular_files += 1
                    if max_records is not None and record_idx >= max_records:
                        break

                    # Stream bytes directly from memory without extracting to disk
                    f_obj = tar.extractfile(member)
                    if f_obj is None:
                        self.total_malformed += 1
                        continue

                    raw_bytes = f_obj.read()
                    self.cumulative_decompressed_bytes += len(raw_bytes)
                    raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()

                    try:
                        # Parse RFC-822 message
                        msg = email.message_from_bytes(raw_bytes)

                        # Message-ID identification
                        raw_msg_id = msg.get("Message-ID", "")
                        clean_msg_id = safe_decode_header(raw_msg_id).strip("<>").strip()
                        if not clean_msg_id:
                            clean_msg_id = f"NO-MSG-ID-{self.dataset_id}-{os.path.basename(member.name)}"

                        # Headers extraction
                        subject = safe_decode_header(msg.get("Subject", ""))
                        from_header = safe_decode_header(msg.get("From", ""))
                        to_header = safe_decode_header(msg.get("To", ""))
                        date_header = safe_decode_header(msg.get("Date", ""))
                        return_path = safe_decode_header(msg.get("Return-Path", ""))

                        # MIME anomaly detection and recovery (Content-Transfer-Encoding folded in Content-Type)
                        raw_ct = str(msg.get("Content-Type", ""))
                        normalized_ct = msg.get_content_type()
                        parser_warnings = []

                        ct_folding_match = re.match(
                            r"^(text/html|text/plain)\s+content-transfer-encoding:\s*([^\r\n]+)",
                            raw_ct,
                            flags=re.IGNORECASE,
                        )
                        if ct_folding_match:
                            recovered_ct = ct_folding_match.group(1).lower()
                            recovered_enc = re.split(r"[\s\r\n\\]+", ct_folding_match.group(2))[0].strip()
                            normalized_ct = recovered_ct
                            self.mime_anomaly_warnings_count += 1
                            parser_warnings.append({
                                "warning_type": "MALFORMED_CONTENT_TYPE_FOLDING",
                                "description": "Historical spam software folded Content-Transfer-Encoding into Content-Type header on a single line.",
                                "original_header": raw_ct,
                                "recovered_content_type": recovered_ct,
                                "recovered_transfer_encoding": recovered_enc,
                            })

                        # Extract bodies
                        plain_body, html_body, attachments = self.extract_body_and_attachments(msg)
                        primary_body = plain_body if plain_body.strip() else html_body

                        # Empty body classification
                        has_extracted_body = bool(plain_body.strip()) or bool(html_body.strip())
                        if has_extracted_body:
                            body_classification = "NORMAL"
                            body_classification_reason = "Extracted non-empty textual content from MIME parts."
                        else:
                            if len(attachments) > 0:
                                body_classification = "ATTACHMENT_ONLY"
                                body_classification_reason = f"Message body is empty/whitespace; payload is an attachment lure ({', '.join(attachments)})."
                            else:
                                if msg.is_multipart():
                                    body_parts = [
                                        p.get_payload() for p in msg.walk()
                                        if p.get_content_type() in ("text/plain", "text/html")
                                    ]
                                    combined = "".join(str(bp or "") for bp in body_parts)
                                    if len(combined.strip()) == 0 and len(combined) > 0:
                                        body_classification = "WHITESPACE_ONLY"
                                        body_classification_reason = f"Multipart message contains only whitespace/newline characters ({len(combined)} bytes)."
                                    elif len(combined) == 0:
                                        body_classification = "EMPTY_MESSAGE"
                                        body_classification_reason = "Multipart message parts contain 0 payload bytes."
                                    else:
                                        body_classification = "BODY_EXTRACTION_FAILURE"
                                        body_classification_reason = "Multipart message text payload could not be extracted or decoded."
                                else:
                                    single_payload = msg.get_payload()
                                    single_str = str(single_payload or "")
                                    if single_payload is None or len(single_str) == 0:
                                        body_classification = "EMPTY_MESSAGE"
                                        body_classification_reason = "Singlepart message contains null or zero-length payload."
                                    elif len(single_str.strip()) == 0 and len(single_str) > 0:
                                        body_classification = "WHITESPACE_ONLY"
                                        body_classification_reason = f"Singlepart message contains only whitespace/newline characters ({len(single_str)} bytes)."
                                    else:
                                        body_classification = "BODY_EXTRACTION_FAILURE"
                                        body_classification_reason = "Singlepart message payload could not be extracted or decoded."

                        self.empty_body_counts[body_classification] = self.empty_body_counts.get(body_classification, 0) + 1

                        # Normalized content fingerprint (subject + body)
                        norm_content = f"{subject.lower().strip()}\n{primary_body.strip()}"
                        content_sha256 = hashlib.sha256(norm_content.encode("utf-8", errors="replace")).hexdigest()

                        # Deduplication and campaign grouping within the corpus
                        is_exact_dup = False
                        is_campaign_dup = False
                        duplicate_of = None
                        campaign_cluster_id = content_sha256[:16]

                        if raw_sha256 in self.seen_raw_hashes:
                            is_exact_dup = True
                            duplicate_of = self.seen_raw_hashes[raw_sha256]
                            self.exact_duplicates += 1
                        else:
                            self.seen_raw_hashes[raw_sha256] = clean_msg_id

                        if content_sha256 in self.seen_content_hashes:
                            is_campaign_dup = True
                            if not duplicate_of:
                                duplicate_of = self.seen_content_hashes[content_sha256]
                            self.campaign_near_duplicates += 1
                        else:
                            self.seen_content_hashes[content_sha256] = clean_msg_id
                            self.unique_content_records += 1

                        if campaign_cluster_id not in self.campaign_clusters:
                            self.campaign_clusters[campaign_cluster_id] = []
                        self.campaign_clusters[campaign_cluster_id].append(clean_msg_id)

                        # Extract historical authentication headers with UNKNOWN safety marker
                        auth_headers = {}
                        for h_name in ["Authentication-Results", "Received-SPF", "DKIM-Signature", "X-DKIM", "Received"]:
                            vals = msg.get_all(h_name, [])
                            if vals:
                                auth_headers[h_name] = [safe_decode_header(v) for v in vals]

                        # Redacted preview for safe routine evaluation and reporting
                        redacted_preview = {
                            "subject": redact_pii(subject),
                            "from": redact_pii(from_header),
                            "to": redact_pii(to_header),
                            "body_preview": redact_pii(primary_body[:300]),
                        }

                        record = {
                            "dataset_id": self.dataset_id,
                            "parent_archive": self.parent_archive_name,
                            "parent_archive_sha256": self.parent_archive_sha256,
                            "archive_member_path": member.name,
                            "message_index": record_idx,
                            "message_id": clean_msg_id,
                            "date": date_header,
                            "from": from_header,
                            "to": to_header,
                            "return_path": return_path,
                            "subject": subject,
                            "body_plain": plain_body,
                            "body_html": html_body,
                            "attachment_filenames": attachments,
                            "raw_content_type": raw_ct,
                            "normalized_content_type": normalized_ct,
                            "parser_warnings": parser_warnings,
                            "body_classification": body_classification,
                            "body_classification_reason": body_classification_reason,
                            "raw_message_sha256": raw_sha256,
                            "content_sha256": content_sha256,
                            "campaign_cluster_id": campaign_cluster_id,
                            "is_exact_duplicate": is_exact_dup,
                            "is_campaign_duplicate": is_campaign_dup,
                            "duplicate_of": duplicate_of,
                            "source_label": "spam",
                            "canonical_label": self.canonical_label.value,
                            "auth_status": "UNKNOWN",
                            "auth_status_note": "UNVERIFIED_HISTORICAL_HEADER: Must not be trusted without trusted-boundary validation.",
                            "historical_auth_headers": auth_headers,
                            "label_limitations": "Historical spam corpus (SpamAssassin 2005 archive); reflects 2001-2005 commercial spam, nigerian 419, pharmaceutical, and adult spam lures.",
                            "parsing_status": "PARSED_SUCCESS",
                            "redacted_preview": redacted_preview,
                        }

                        out_f.write(json.dumps(record) + "\n")
                        self.total_parsed += 1
                        record_idx += 1

                    except Exception:
                        self.total_malformed += 1

        summary = {
            "dataset_id": self.dataset_id,
            "parent_archive": self.parent_archive_name,
            "parent_archive_sha256": self.parent_archive_sha256,
            "archive_size_bytes": archive_size,
            "cumulative_decompressed_bytes": self.cumulative_decompressed_bytes,
            "total_members_inspected": self.total_members_inspected,
            "total_regular_files": self.total_regular_files,
            "total_directories_skipped": self.total_directories_skipped,
            "total_rejected_members": self.total_rejected_members,
            "rejected_members": self.rejected_members_log,
            "total_parsed": self.total_parsed,
            "total_malformed": self.total_malformed,
            "exact_duplicates": self.exact_duplicates,
            "campaign_near_duplicates": self.campaign_near_duplicates,
            "unique_content_records": self.unique_content_records,
            "campaign_clusters_count": len(self.campaign_clusters),
            "mime_anomaly_warnings_count": self.mime_anomaly_warnings_count,
            "empty_body_classification_counts": self.empty_body_counts,
            "output_jsonl": os.path.abspath(output_jsonl_path),
        }

        with open(summary_json_path, "w", encoding="utf-8") as sum_f:
            json.dump(summary, sum_f, indent=2)

        return summary
