"""Header integrity detection rules (RFC 5322 compliance and header consistency)."""

import email.utils
from typing import List
from app.modules.contracts import ImpersonationFinding, ParsedEmail
from app.modules.identity.config import IdentityAnalysisConfig
from app.modules.identity.domain_utils import is_subdomain_of, normalize_domain


def validate_mailbox_syntax(addr: str) -> bool:
    """Validates mailbox syntax according to RFC 5322 §3.4.1 addr-spec grammar.

    Supports both standard dot-atom and quoted-string local-parts (e.g. "john smith"@example.com).
    """
    if not addr or "@" not in addr:
        return False

    # Check for quoted local-part vs dot-atom
    if addr.startswith('"'):
        # Quoted local-part: find matching unescaped closing quote
        closing_quote_idx = -1
        i = 1
        while i < len(addr):
            if addr[i] == "\\":
                i += 2  # skip escaped character
                continue
            if addr[i] == '"':
                closing_quote_idx = i
                break
            i += 1

        if closing_quote_idx == -1:
            return False  # unclosed quote

        local_part = addr[: closing_quote_idx + 1]
        rest = addr[closing_quote_idx + 1 :]
        if not rest.startswith("@"):
            return False  # closing quote must be immediately followed by @
        domain_part = rest[1:]
    else:
        # Unquoted: must have exactly one @
        parts = addr.split("@")
        if len(parts) != 2:
            return False
        local_part, domain_part = parts

        if not local_part or len(local_part) > 64:
            return False
        if local_part.startswith(".") or local_part.endswith(".") or ".." in local_part:
            return False

        # Prohibited unquoted characters in dot-atom local-part
        prohibited = set(" \t\r\n<>(),:;[]\\\"")
        if any(c in prohibited for c in local_part):
            return False

    # Validate domain part
    if not domain_part or len(domain_part) > 255:
        return False
    if domain_part.startswith(".") or domain_part.endswith(".") or ".." in domain_part:
        return False

    prohibited_domain = set(" \t\r\n<>(),:;[]\\\"")
    if any(c in prohibited_domain for c in domain_part):
        return False

    # Standard hostname must contain at least one dot (unless domain-literal)
    if "." not in domain_part and not (domain_part.startswith("[") and domain_part.endswith("]")):
        return False

    return True


def check_header_integrity(
    parsed_email: ParsedEmail,
    config: IdentityAnalysisConfig,
) -> List[ImpersonationFinding]:
    """Evaluates RFC 5322 header constraints for From, Sender, and Reply-To headers."""
    findings: List[ImpersonationFinding] = []

    from_headers = parsed_email.headers_map.get("from", [])
    reply_to_headers = parsed_email.headers_map.get("reply-to", [])
    sender_headers = parsed_email.headers_map.get("sender", [])

    # 1. Missing From header
    if parsed_email.from_sender is None and len(from_headers) == 0:
        findings.append(
            ImpersonationFinding(
                indicator="MISSING_FROM_HEADER",
                target_name=None,
                similarity_score=0.0,
                description="Email is missing mandatory RFC 5322 From header.",
                is_vip=False,
            )
        )
        return findings

    # 2. Duplicate From header lines (distinct from multiple mailboxes in one header)
    if len(from_headers) > 1:
        findings.append(
            ImpersonationFinding(
                indicator="DUPLICATE_FROM_HEADER",
                target_name=None,
                similarity_score=0.0,
                description=f"Email contains {len(from_headers)} separate 'From' headers. RFC 5322 requires exactly one From header field.",
                is_vip=False,
            )
        )

    # 3. Duplicate Reply-To header lines
    if len(reply_to_headers) > 1:
        findings.append(
            ImpersonationFinding(
                indicator="DUPLICATE_REPLY_TO_HEADER",
                target_name=None,
                similarity_score=0.0,
                description=f"Email contains {len(reply_to_headers)} separate 'Reply-To' headers. RFC 5322 permits at most one Reply-To header field.",
                is_vip=False,
            )
        )

    # 4. Empty or Malformed Sender Address Validation (across all senders)
    senders_to_validate = []
    if parsed_email.from_sender:
        senders_to_validate.append(parsed_email.from_sender)
    for s in parsed_email.all_from_senders:
        if s not in senders_to_validate:
            senders_to_validate.append(s)

    for sender_obj in senders_to_validate:
        raw_val = sender_obj.raw or ""
        addr = sender_obj.address or ""

        is_malformed = False
        if not validate_mailbox_syntax(addr):
            is_malformed = True
        elif raw_val.count("<") != raw_val.count(">"):
            is_malformed = True
        elif raw_val.startswith("<<<") or ">>>" in raw_val:
            is_malformed = True

        if is_malformed:
            findings.append(
                ImpersonationFinding(
                    indicator="MALFORMED_SENDER_ADDRESS",
                    target_name=raw_val[: config.max_input_length],
                    similarity_score=0.0,
                    description=f"Sender address '{raw_val[:100]}' does not conform to RFC 5322 mailbox syntax.",
                    is_vip=False,
                )
            )

    # 5. Multiple mailboxes in From header & Sender consistency
    raw_from_line = from_headers[0] if from_headers else (parsed_email.from_sender.raw if parsed_email.from_sender else "")
    parsed_mailboxes = email.utils.getaddresses([raw_from_line]) if raw_from_line else []
    valid_mailboxes = [addr for name, addr in parsed_mailboxes if addr.strip()]

    if len(valid_mailboxes) > 1:
        if not sender_headers:
            # RFC 5322 §3.6.2: If from contains >1 mailbox, sender is mandatory
            findings.append(
                ImpersonationFinding(
                    indicator="MISSING_SENDER_HEADER",
                    target_name=None,
                    similarity_score=0.0,
                    description=f"From header contains multiple mailboxes ({len(valid_mailboxes)}), but mandatory RFC 5322 Sender header is missing.",
                    is_vip=False,
                )
            )
        else:
            # Compliant when Sender is present
            findings.append(
                ImpersonationFinding(
                    indicator="MULTIPLE_FROM_MAILBOXES",
                    target_name=sender_headers[0][: config.max_input_length],
                    similarity_score=0.0,
                    description=f"From header contains multiple mailboxes ({len(valid_mailboxes)}). Transmitting agent is designated in Sender header: '{sender_headers[0][:100]}'.",
                    is_vip=False,
                )
            )

    # 6. Duplicate Sender headers
    if len(sender_headers) > 1:
        findings.append(
            ImpersonationFinding(
                indicator="DUPLICATE_SENDER_HEADER",
                target_name=None,
                similarity_score=0.0,
                description=f"Email contains {len(sender_headers)} 'Sender' headers. RFC 5322 permits at most one Sender header.",
                is_vip=False,
            )
        )
    elif len(sender_headers) == 1 and parsed_email.from_sender and len(valid_mailboxes) <= 1:
        # Check consistency when single mailbox From is present with Sender
        s_name, s_addr = email.utils.parseaddr(sender_headers[0])
        s_domain = normalize_domain(s_addr.split("@")[-1]) if "@" in s_addr else ""
        from_domain = normalize_domain(parsed_email.from_sender.domain)

        if s_domain and from_domain and s_domain != from_domain:
            in_same_org = False
            for org_dom in config.protected_domains:
                if is_subdomain_of(s_domain, org_dom) and is_subdomain_of(from_domain, org_dom):
                    in_same_org = True
                    break

            if not in_same_org and not (is_subdomain_of(s_domain, from_domain) or is_subdomain_of(from_domain, s_domain)):
                findings.append(
                    ImpersonationFinding(
                        indicator="SENDER_FROM_MISMATCH",
                        target_name=s_addr[: config.max_input_length],
                        similarity_score=0.0,
                        description=f"Sender header domain '{s_domain[:100]}' does not match From header domain '{from_domain[:100]}'. Note: Observed discrepancy may represent legitimate administrative delegation, automated calendar invites, or mailing list distribution.",
                        is_vip=False,
                    )
                )

    return findings
