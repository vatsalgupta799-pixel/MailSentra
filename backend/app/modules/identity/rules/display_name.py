"""Display-name analysis rules (embedded email, VIP matching, role impersonation)."""

import re
import unicodedata
from typing import List, Tuple
from app.modules.contracts import ImpersonationFinding, ParsedEmail
from app.modules.identity.config import IdentityAnalysisConfig
from app.modules.identity.domain_utils import (
    detect_suspicious_unicode,
    extract_email_from_text,
    is_subdomain_of,
    normalize_domain,
)

COMMON_AUTHORITY_FOLLOWERS = re.compile(
    r"^(of\b|\'s\b|office\b|department\b|admin(istrator)?\b|support\b|desk\b|helpdesk\b|team\b|staff\b|security\b|center\b|services\b|division\b)",
    re.IGNORECASE,
)
COMMON_AUTHORITY_PRECEDERS = re.compile(
    r"(office\s+of\s+the|the|university|associate|assistant|acting|executive|campus|student|faculty)\s*$",
    re.IGNORECASE,
)


def is_role_claimed(display_name: str, role: str) -> bool:
    """Safely determines if display_name genuinely asserts the organizational role.

    Prevents false-positive substring matches (e.g., 'IT' in 'Smith', or 'Dean' in 'Dean Martin').
    """
    role_clean = role.strip()
    if not role_clean:
        return False

    # Word-boundary matching with regex-escaped role
    pattern = rf"\b{re.escape(role_clean)}\b"
    match = re.search(pattern, display_name, re.IGNORECASE)
    if not match:
        return False

    words = role_clean.split()
    # Multi-word configured roles (e.g. 'Office of the Dean', 'IT Helpdesk', 'IT Administrator')
    # are sufficiently distinct with word boundary match.
    if len(words) > 1:
        return True

    start, end = match.span()
    after = display_name[end:].strip()
    before = display_name[:start].strip()

    # If the role is the entire display name: e.g. 'Dean' or 'IT'
    if not before and not after:
        return True

    # If followed by known authority prepositions or nouns: 'Dean of Students', 'Dean's Office'
    if COMMON_AUTHORITY_FOLLOWERS.match(after):
        return True

    # If preceded by known authority markers: 'University Dean', 'Office of the Dean'
    if COMMON_AUTHORITY_PRECEDERS.search(before):
        return True

    # If set off by punctuation or delimiters: 'John Doe, Dean', 'John Doe (Dean)'
    if before.endswith((",", "-", "(", "/", ":")) or after.startswith((")", ",", "-", "/")):
        return True

    # Acronyms such as 'IT', 'HR': check if coupled with authority terms or delimited
    if role_clean.upper() in {"IT", "HR", "PR", "IR", "IS"}:
        return bool(
            COMMON_AUTHORITY_FOLLOWERS.match(after)
            or COMMON_AUTHORITY_PRECEDERS.search(before)
            or not after
        )

    # For single capitalized names/titles (e.g. 'Dean') followed by a standard personal name
    # without any authority marker (e.g. 'Dean Martin', 'Dean Winchester'), do not classify as impersonation.
    if after and re.match(r"^[A-Za-z]+", after):
        return False

    return True


def check_display_name(
    parsed_email: ParsedEmail,
    config: IdentityAnalysisConfig,
) -> Tuple[bool, List[ImpersonationFinding]]:
    """Analyzes sender display names for embedded email addresses and impersonation indicators.

    Returns:
        (display_name_spoofed, findings)
    """
    findings: List[ImpersonationFinding] = []
    display_name_spoofed = False

    # Collect senders to inspect (from_sender and any additional in all_from_senders)
    senders = []
    if parsed_email.from_sender:
        senders.append(parsed_email.from_sender)
    for s in parsed_email.all_from_senders:
        if s not in senders:
            senders.append(s)

    if not senders:
        return display_name_spoofed, findings

    for sender in senders:
        raw_display = sender.display_name or ""
        display_name = str(raw_display)[: config.max_input_length].strip()
        if not display_name:
            continue

        # Check for suspicious Unicode control or invisible characters
        has_suspicious, susp_names = detect_suspicious_unicode(display_name)
        if has_suspicious:
            findings.append(
                ImpersonationFinding(
                    indicator="SUSPICIOUS_UNICODE_CHARACTERS",
                    target_name=None,
                    similarity_score=0.0,
                    description=f"Display name contains suspicious Unicode control or invisible characters: {', '.join(susp_names)}.",
                    is_vip=False,
                )
            )

        # 1. Embedded Email Address in Display Name
        embedded_email = extract_email_from_text(display_name, max_len=config.max_input_length)
        if embedded_email:
            actual_addr = (sender.address or "").strip().lower()
            if embedded_email != actual_addr:
                display_name_spoofed = True
                findings.append(
                    ImpersonationFinding(
                        indicator="DISPLAY_NAME_EMAIL_MISMATCH",
                        target_name=embedded_email[: config.max_input_length],
                        similarity_score=1.0,
                        description=f"Display name contains embedded email address '{embedded_email}' that does not match actual sender address '{actual_addr[:100]}'.",
                        is_vip=False,
                    )
                )

        # Normalized display name for VIP token / title comparison
        norm_disp = unicodedata.normalize("NFKC", display_name).lower()
        from_domain = normalize_domain(sender.domain)

        # 2. Configurable VIP Identity Matching
        for vip in config.vip_identities:
            vip_name_lower = vip.name.lower().strip()
            if not vip_name_lower:
                continue
            # Token / word-boundary check for VIP name
            pattern = rf"\b{re.escape(vip_name_lower)}\b"
            if re.search(pattern, norm_disp):
                is_authorized = False
                for allowed_dom in vip.allowed_domains:
                    norm_allowed = normalize_domain(allowed_dom)
                    if from_domain == norm_allowed or is_subdomain_of(from_domain, norm_allowed):
                        is_authorized = True
                        break

                if not is_authorized:
                    display_name_spoofed = True
                    findings.append(
                        ImpersonationFinding(
                            indicator="VIP_IMPERSONATION",
                            target_name=vip.name[: config.max_input_length],
                            similarity_score=1.0,
                            description=f"Sender display name matches configured VIP identity '{vip.name}', but sending domain '{from_domain[:100]}' is not authorized for this identity.",
                            is_vip=True,
                        )
                    )

        # 3. Configurable Organizational Role Impersonation
        if config.organizational_roles:
            is_protected_org = False
            for prot_dom in config.protected_domains:
                norm_prot = normalize_domain(prot_dom)
                if from_domain == norm_prot or is_subdomain_of(from_domain, norm_prot):
                    is_protected_org = True
                    break

            if not is_protected_org:
                for role in config.organizational_roles:
                    if is_role_claimed(display_name, role):
                        display_name_spoofed = True
                        findings.append(
                            ImpersonationFinding(
                                indicator="ORGANIZATIONAL_ROLE_IMPERSONATION",
                                target_name=role[: config.max_input_length],
                                similarity_score=1.0,
                                description=f"Display name claims configured organizational role '{role}', but message originated from external domain '{from_domain[:100]}'.",
                                is_vip=False,
                            )
                        )
                        break

    return display_name_spoofed, findings
