"""Email Parsing and Normalization Engine.

Converts raw RFC 5322 byte streams into structured, normalized ParsedEmail models.
Implements robust MIME multipart traversal, RFC 2047 header decoding, character encoding
resilience, safe HTML-to-text conversion, URL extraction, and attachment metadata hashing.
"""

import email
import email.policy
from datetime import datetime, timezone
from typing import Dict, List, Optional
from app.core.config import settings
from app.core.logging import logger
from app.modules.base import BaseDetectionModule
from app.modules.contracts import EmailHeader, ParsedEmail, RawEmailPayload
from app.modules.parser.attachment_parser import extract_attachments_from_message
from app.modules.parser.body_parser import decode_payload_bytes, extract_clean_text_from_html
from app.modules.parser.header_parser import (
    decode_rfc2047,
    parse_address_list,
    parse_date_header,
    parse_email_address,
    parse_received_hops,
)
from app.modules.parser.url_extractor import extract_urls


class EmailParser(BaseDetectionModule):
    """Core RFC 5322 Email Parser and Normalization Engine."""

    @property
    def module_name(self) -> str:
        return "parser"

    @property
    def version(self) -> str:
        return "1.0.0-phase2"

    async def analyze(self, raw_payload: RawEmailPayload) -> ParsedEmail:
        """Asynchronous interface satisfying BaseDetectionModule."""
        return self.parse(raw_payload)

    def parse(self, raw_payload: RawEmailPayload) -> ParsedEmail:
        """Parses a RawEmailPayload into an immutable normalized ParsedEmail."""
        warnings: List[str] = []
        raw_bytes = raw_payload.raw_bytes

        # Strip UTF-8 BOM if present so email.message_from_bytes can recognize RFC 5322 headers
        if raw_bytes.startswith(b"\xef\xbb\xbf"):
            raw_bytes = raw_bytes[3:]
            warnings.append("Leading UTF-8 Byte Order Mark (BOM) was detected and safely stripped.")

        # 1. Parse raw bytes into email.message.Message using default policy
        msg = None
        try:
            msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        except Exception as e:
            warnings.append(f"Standard email parser failed: {str(e)}. Falling back to compat32 parser.")
            try:
                msg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)
            except Exception as e_compat:
                warnings.append(f"Compat parser also encountered an error: {str(e_compat)}")
                # Create empty message
                msg = email.message.Message()

        # 2. Extract and decode all headers
        headers_list: List[EmailHeader] = []
        headers_map: Dict[str, List[str]] = {}

        try:
            for k, v in msg.items():
                decoded_val = decode_rfc2047(str(v))
                headers_list.append(EmailHeader(name=k, value=decoded_val, raw_value=str(v)))
                norm_key = k.lower()
                if norm_key not in headers_map:
                    headers_map[norm_key] = []
                headers_map[norm_key].append(decoded_val)
        except Exception as e_hdr:
            warnings.append(f"Error while enumerating headers: {str(e_hdr)}")

        # Core Headers
        subject_raw = msg.get("Subject")
        subject = decode_rfc2047(subject_raw) if subject_raw is not None else None

        message_id = msg.get("Message-ID")
        if message_id:
            message_id = str(message_id).strip()

        # Sender & Addresses
        from_raw = msg.get("From")
        from_sender = parse_email_address(str(from_raw)) if from_raw else None

        reply_to_raw = msg.get("Reply-To")
        reply_to = parse_email_address(str(reply_to_raw)) if reply_to_raw else None

        # Parse all mailboxes across all From and Reply-To headers
        all_from_senders: List[EmailAddress] = []
        for raw_f in headers_map.get("from", []):
            all_from_senders.extend(
                parse_address_list(raw_f, max_addresses=settings.MAX_RECIPIENT_ADDRESSES)
            )
        if not all_from_senders and from_sender:
            all_from_senders.append(from_sender)

        all_reply_to: List[EmailAddress] = []
        for raw_rt in headers_map.get("reply-to", []):
            all_reply_to.extend(
                parse_address_list(raw_rt, max_addresses=settings.MAX_RECIPIENT_ADDRESSES)
            )
        if not all_reply_to and reply_to:
            all_reply_to.append(reply_to)

        return_path = msg.get("Return-Path")
        if return_path:
            return_path = str(return_path).strip().strip("<>")

        to_recipients = (
            parse_address_list(str(msg.get("To")), max_addresses=settings.MAX_RECIPIENT_ADDRESSES)
            if msg.get("To")
            else []
        )
        cc_recipients = (
            parse_address_list(str(msg.get("Cc")), max_addresses=settings.MAX_RECIPIENT_ADDRESSES)
            if msg.get("Cc")
            else []
        )
        bcc_recipients = (
            parse_address_list(str(msg.get("Bcc")), max_addresses=settings.MAX_RECIPIENT_ADDRESSES)
            if msg.get("Bcc")
            else []
        )

        # Dates
        date_raw, date_utc = parse_date_header(str(msg.get("Date"))) if msg.get("Date") else (None, None)

        # Received Hops
        received_raw_list = headers_map.get("received", [])
        received_hops = parse_received_hops(received_raw_list, max_hops=settings.MAX_RECEIVED_HOPS)

        # Cryptographic / Authentication Headers
        auth_results = headers_map.get("authentication-results", [])
        received_spf = headers_map.get("received-spf", [])
        dkim_signatures = headers_map.get("dkim-signature", [])

        # 3. Extract Body Content (Plain text and HTML)
        body_plain_parts: List[str] = []
        body_html_parts: List[str] = []

        try:
            part_count = 0
            for part in msg.walk():
                part_count += 1
                if part_count > settings.MAX_MIME_PARTS:
                    warnings.append(
                        f"MIME part count limit of {settings.MAX_MIME_PARTS} exceeded; remaining parts truncated."
                    )
                    break

                if part.is_multipart():
                    continue

                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", "")).lower()

                # If it's explicitly marked as an attachment, skip from body parsing
                if "attachment" in content_disposition:
                    continue

                part_filename = part.get_filename()
                if part_filename:
                    # Has an explicit filename; treated as an attachment
                    continue

                charset = part.get_content_charset()
                try:
                    payload = part.get_payload(decode=True)
                    if payload is None:
                        continue
                    text_decoded = decode_payload_bytes(payload, charset)
                except Exception as e_body:
                    warnings.append(f"Failed to decode body part with content-type '{content_type}': {str(e_body)}")
                    continue

                if content_type == "text/plain":
                    body_plain_parts.append(text_decoded)
                elif content_type == "text/html":
                    body_html_parts.append(text_decoded)
        except Exception as e_walk:
            warnings.append(f"MIME walk traversal encountered an anomaly: {str(e_walk)}")

        body_plain = "\n\n".join(body_plain_parts) if body_plain_parts else None
        body_html = "\n\n".join(body_html_parts) if body_html_parts else None

        # Safe HTML-to-text extraction
        body_extracted_text = extract_clean_text_from_html(body_html) if body_html else None

        # 4. Extract URLs (with bounded extraction limit)
        urls = extract_urls(
            plain_text=body_plain,
            html_content=body_html,
            max_urls=settings.MAX_EXTRACTED_URLS,
        )

        # 5. Extract Attachments (with bounded count and size limits)
        attachments, att_warnings = extract_attachments_from_message(
            msg,
            max_attachments=settings.MAX_ATTACHMENTS,
            max_payload_bytes=settings.MAX_ATTACHMENT_SIZE_BYTES,
        )
        warnings.extend(att_warnings)

        return ParsedEmail(
            message_id=message_id,
            subject=subject,
            date_raw=date_raw,
            date_utc=date_utc,
            processing_timestamp=datetime.now(timezone.utc),
            from_sender=from_sender,
            reply_to=reply_to,
            return_path=return_path,
            all_from_senders=all_from_senders,
            all_reply_to=all_reply_to,
            to_recipients=to_recipients,
            cc_recipients=cc_recipients,
            bcc_recipients=bcc_recipients,
            headers=headers_list,
            headers_map=headers_map,
            received_hops=received_hops,
            authentication_results=auth_results,
            received_spf=received_spf,
            dkim_signatures=dkim_signatures,
            body_plain=body_plain,
            body_html=body_html,
            body_extracted_text=body_extracted_text,
            urls=urls,
            attachments=attachments,
            parsing_warnings=warnings,
        )
