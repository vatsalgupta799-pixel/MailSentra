"""Dedicated MBOX Dataset Ingestion Adapter for MailSentra.

Extracts, normalizes, deduplicates, and redacts email records from authentic
MBOX archives (such as Nazario Phishing Corpus) while strictly preserving provenance.
"""

import os
import re
import json
import mailbox
import hashlib
from email.header import decode_header
from typing import Dict, Any, List, Optional, Tuple
from app.datasets.contracts import CanonicalThreatLabel


def safe_decode_header(header_value: Optional[str]) -> str:
    """Safely decodes RFC-2047 MIME-encoded headers with robust charset fallbacks."""
    if not header_value:
        return ""
    try:
        parts = decode_header(header_value)
        decoded_fragments = []
        for fragment, encoding in parts:
            if isinstance(fragment, bytes):
                enc = encoding or "utf-8"
                try:
                    decoded_fragments.append(fragment.decode(enc, errors="replace"))
                except (LookupError, UnicodeDecodeError):
                    decoded_fragments.append(fragment.decode("latin-1", errors="replace"))
            else:
                decoded_fragments.append(str(fragment))
        return " ".join(decoded_fragments).strip()
    except Exception:
        return str(header_value).strip()


def decode_bounded_quoted_printable_and_url(text: str) -> str:
    """Performs bounded context-aware decoding of quoted-printable and URL encoded email tokens.
    Does not decode arbitrarily large or deeply nested payloads.
    """
    if not text:
        return ""

    # 1. In-place RFC-2047 decode without injecting extraneous whitespace
    def _replace_rfc2047(match):
        raw = match.group(0)
        try:
            parts = decode_header(raw)
            frags = []
            for frag, enc in parts:
                if isinstance(frag, bytes):
                    frags.append(frag.decode(enc or "utf-8", errors="replace"))
                else:
                    frags.append(str(frag))
            return "".join(frags)
        except Exception:
            return raw

    text = re.sub(r"=\?[\w-]+\?[bBqQ]\?[^?]+\?=", _replace_rfc2047, text)

    # 2. Decode context-aware =40 (QP @ symbol) in email patterns
    text = re.sub(r"([a-zA-Z0-9_.+-]+)=40([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", r"\1@\2", text, flags=re.IGNORECASE)
    # 3. Decode context-aware %40 (URL-encoded @ symbol) in email patterns
    text = re.sub(r"([a-zA-Z0-9_.+-]+)%40([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", r"\1@\2", text, flags=re.IGNORECASE)
    return text


def redact_pii(text: Optional[str]) -> str:
    """Masks email local-parts and sensitive identifier tokens for preview/reporting
    while protecting against false positives on dates, IP addresses, and version tokens.
    """
    if not text:
        return ""

    # Step 1: Decode bounded QP / URL-encoded tokens
    normalized = decode_bounded_quoted_printable_and_url(text)

    # Step 2: Redact email addresses (including standard, mailto:, and decoded QP/URL)
    email_pattern = r"\b([a-zA-Z0-9_.+-])[a-zA-Z0-9_.+-]*@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b"
    redacted = re.sub(email_pattern, r"\1***@\2", normalized)

    # Step 3: Redact telephone numbers (NANP and International formats)
    # Must NOT match ISO dates (YYYY-MM-DD), IPv4 addresses (d.d.d.d), or semantic versions (vX.Y.Z)
    
    # 3A: International phone numbers with leading '+' (e.g., +1 (800) 555-1234, +44 20 7946 0958, +33 1 23 45 67 89)
    intl_phone = r"(?<![\w.])\+\d{1,3}[-.\s]?(?:\(?\d{1,4}\)?[-.\s]?)?(?:\d{1,4}[-.\s]?){2,5}\b(?![\w.])"
    redacted = re.sub(intl_phone, "[REDACTED_PHONE]", redacted)

    # 3B: North American formats without '+' (e.g. 1-800-555-1234, (800) 555-1234, 800-555-1234, 800.555.1234)
    # Area code is 3 digits (200-999). Year in date is 4 digits.
    nanp_phone = r"(?<![\w.])(?:1[-.\s])?\(?[2-9]\d{2}\)?[-.\s]\d{3}[-.\s]\d{4}\b(?![\w.])"
    redacted = re.sub(nanp_phone, "[REDACTED_PHONE]", redacted)

    return redacted


class MboxDatasetAdapter:
    """Adapter for ingesting and normalizing MBOX multi-email archives."""

    def __init__(
        self,
        dataset_id: str = "DS-PE-01",
        parent_archive_name: str = "phishing3.mbox",
        parent_archive_sha256: str = "b29336d2e31c2dff19639415e98ed2aced5b4d63675ea5e29bea1a7d4e452841",
        canonical_label: CanonicalThreatLabel = CanonicalThreatLabel.PHISHING,
    ):
        self.dataset_id = dataset_id
        self.parent_archive_name = parent_archive_name
        self.parent_archive_sha256 = parent_archive_sha256
        self.canonical_label = canonical_label

        # Deduplication and clustering state
        self.seen_raw_hashes: Dict[str, str] = {}
        self.seen_content_hashes: Dict[str, str] = {}
        self.campaign_clusters: Dict[str, List[str]] = {}

        # Parsing counters
        self.total_discovered = 0
        self.total_parsed = 0
        self.total_malformed = 0
        self.total_truncated = 0
        self.total_unsupported = 0
        self.exact_duplicates = 0
        self.campaign_near_duplicates = 0
        self.unique_content_records = 0
        self.mime_anomaly_warnings_count = 0
        self.empty_body_counts = {
            "NORMAL": 0,
            "ATTACHMENT_ONLY": 0,
            "WHITESPACE_ONLY": 0,
            "EMPTY_MESSAGE": 0,
            "BODY_EXTRACTION_FAILURE": 0,
        }

    def extract_body_and_attachments(self, msg: mailbox.mboxMessage) -> Tuple[str, str, List[str]]:
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

    def process_mbox(
        self,
        mbox_path: str,
        output_jsonl_path: str,
        summary_json_path: str,
        max_records: Optional[int] = None
    ) -> Dict[str, Any]:
        """Parses all messages in mbox_path, serializes normalized records to output_jsonl_path,
        and saves complete parsing/deduplication summary to summary_json_path.
        """
        os.makedirs(os.path.dirname(output_jsonl_path), exist_ok=True)
        os.makedirs(os.path.dirname(summary_json_path), exist_ok=True)

        mbox = mailbox.mbox(mbox_path)
        self.total_discovered = len(mbox)
        limit = max_records if max_records is not None else self.total_discovered

        records = []
        with open(output_jsonl_path, "w", encoding="utf-8") as out_f:
            for idx in range(min(limit, self.total_discovered)):
                try:
                    msg = mbox[idx]
                except Exception as e:
                    self.total_malformed += 1
                    continue

                try:
                    # Message-ID identification
                    raw_msg_id = msg.get("Message-ID", "")
                    clean_msg_id = safe_decode_header(raw_msg_id).strip("<>").strip()
                    if not clean_msg_id:
                        clean_msg_id = f"NO-MSG-ID-{self.dataset_id}-{idx:05d}"

                    # Headers extraction
                    subject = safe_decode_header(msg.get("Subject", ""))
                    from_header = safe_decode_header(msg.get("From", ""))
                    to_header = safe_decode_header(msg.get("To", ""))
                    date_header = safe_decode_header(msg.get("Date", ""))
                    return_path = safe_decode_header(msg.get("Return-Path", ""))

                    # MIME anomaly detection and deterministic recovery
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
                                body_parts = [p.get_payload() for p in msg.walk() if p.get_content_type() in ("text/plain", "text/html")]
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

                    # Raw byte serialization and hash calculation
                    try:
                        raw_bytes = msg.as_bytes()
                    except Exception:
                        raw_bytes = str(msg).encode("utf-8", errors="replace")

                    raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()

                    # Normalized content fingerprint (subject + body)
                    norm_content = f"{subject.lower().strip()}\n{primary_body.strip()}"
                    content_sha256 = hashlib.sha256(norm_content.encode("utf-8", errors="replace")).hexdigest()

                    # Deduplication & Campaign Grouping
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

                    # Redacted preview for safe routine evaluation and display
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
                        "message_index": idx,
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
                        "source_label": "phishing",
                        "canonical_label": self.canonical_label.value,
                        "auth_status": "UNKNOWN",
                        "auth_status_note": "UNVERIFIED_HISTORICAL_HEADER: Must not be trusted without trusted-boundary validation.",
                        "historical_auth_headers": auth_headers,
                        "label_limitations": "Historical phishing corpus (August 2007 archive); reflects 2005-2007 financial, credential, and brand impersonation lures.",
                        "parsing_status": "PARSED_SUCCESS",
                        "redacted_preview": redacted_preview,
                    }

                    out_f.write(json.dumps(record) + "\n")
                    self.total_parsed += 1

                except Exception as parse_err:
                    self.total_malformed += 1
                    err_record = {
                        "dataset_id": self.dataset_id,
                        "message_index": idx,
                        "parsing_status": "MALFORMED",
                        "error": str(parse_err),
                    }
                    out_f.write(json.dumps(err_record) + "\n")

        summary = {
            "dataset_id": self.dataset_id,
            "parent_archive": self.parent_archive_name,
            "parent_archive_sha256": self.parent_archive_sha256,
            "total_discovered": self.total_discovered,
            "total_parsed": self.total_parsed,
            "total_malformed": self.total_malformed,
            "total_truncated": self.total_truncated,
            "total_unsupported": self.total_unsupported,
            "exact_duplicates": self.exact_duplicates,
            "campaign_near_duplicates": self.campaign_near_duplicates,
            "unique_content_records": self.unique_content_records,
            "total_campaign_clusters": len(self.campaign_clusters),
            "mime_anomaly_warnings_count": self.mime_anomaly_warnings_count,
            "empty_body_classifications": self.empty_body_counts,
            "label_distribution": {
                "phishing": self.total_parsed,
                "ham": 0,
                "unknown": 0,
            },
            "output_jsonl_path": os.path.relpath(output_jsonl_path, os.path.abspath(".")).replace("\\", "/"),
            "summary_json_path": os.path.relpath(summary_json_path, os.path.abspath(".")).replace("\\", "/"),
        }

        with open(summary_json_path, "w", encoding="utf-8") as sf:
            json.dump(summary, sf, indent=2)

        return summary
