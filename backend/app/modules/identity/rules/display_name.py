"""Display-name analysis rules (embedded email, VIP matching, role impersonation, brand impersonation)."""

import re
import unicodedata
from typing import List, Optional, Set, Tuple
from app.modules.contracts import ImpersonationFinding, ParsedEmail
from app.modules.identity.config import IdentityAnalysisConfig, ProtectedBrand
from app.modules.identity.domain_utils import (
    SUSPICIOUS_UNICODE_CODEPOINTS,
    _OFFLINE_EXTRACTOR,
    detect_suspicious_unicode,
    extract_email_from_text,
    get_registered_domain_offline,
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

BRAND_AUTHORITY_INDICATORS = {
    "support", "service", "services", "security", "team", "desk", "helpdesk",
    "help", "center", "care", "billing", "account", "accounts", "alert", "alerts",
    "notice", "notification", "notifications", "update", "updates", "verify",
    "verification", "fraud", "department", "division", "admin", "administrator",
    "online", "prime", "id", "store", "bank", "banking", "card", "cards", "credit",
    "financial", "inc", "corp", "corporation", "llc", "ltd", "group", "co",
    "official", "portal", "pay", "payment", "payments", "customer", "dept",
}

NON_IMPERSONATION_PREFIX = re.compile(
    r"^\s*(newsletter\s+on|discussion\s+(about|on)|review\s+of|reviews\s+of|survey\s+on|tips\s+for|guide\s+to|podcast\s+about|talking\s+about)\b",
    re.IGNORECASE,
)
NON_IMPERSONATION_SUFFIX = re.compile(
    r"\b([a-z0-9_-]+\s+)?(club|discussion\s+group|users?\s+group|community\s+forum)\s*$",
    re.IGNORECASE,
)


def normalize_display_name(display_name: str, max_len: int = 255) -> str:
    """Safely normalizes a display name: strips quotes/spaces, NFKC Unicode normalization, zero-width removal."""
    if not display_name:
        return ""
    bounded = str(display_name)[:max_len].strip().strip("\"' ")
    if not bounded:
        return ""
    norm = unicodedata.normalize("NFKC", bounded)
    # Strip zero-width and invisible control characters
    cleaned = "".join(
        ch for ch in norm
        if ord(ch) not in SUSPICIOUS_UNICODE_CODEPOINTS
        or "ZERO WIDTH" not in SUSPICIOUS_UNICODE_CODEPOINTS.get(ord(ch), "")
    )
    return cleaned.strip()


def is_brand_claimed_in_display_name(clean_disp: str, brand: ProtectedBrand) -> Tuple[bool, Optional[str]]:
    """Determines if clean_disp claims the protected brand with false-positive safeguards for ambiguous terms."""
    if not clean_disp or len(clean_disp) < 2:
        return False, None

    lower_disp = clean_disp.lower()

    # Safeguard: Non-impersonation contextual markers (e.g. "Review of Amazon Products", "Discussion on PayPal API")
    if NON_IMPERSONATION_PREFIX.search(lower_disp) or NON_IMPERSONATION_SUFFIX.search(lower_disp):
        return False, None

    all_variations = [brand.name.lower()] + [v.lower() for v in brand.variations]
    # Match longest multi-word variation first
    all_variations = sorted(set(all_variations), key=lambda x: -len(x))

    for var in all_variations:
        pattern = rf"\b{re.escape(var)}\b"
        match = re.search(pattern, lower_disp)
        if not match:
            continue

        start, end = match.span()
        after = lower_disp[end:].strip()
        before = lower_disp[:start].strip()

        # If brand is marked ambiguous (e.g. "Chase", "Apple" which can be ordinary personal names)
        if brand.is_ambiguous:
            # Full exact match e.g. "Chase" or "Apple"
            if lower_disp == var:
                return True, var

            # Check if authority / corporate / banking / service terms are present
            words_in_disp = set(re.findall(r"\b[a-z0-9]+\b", lower_disp))
            if any(kw in words_in_disp for kw in BRAND_AUTHORITY_INDICATORS):
                return True, var

            # Check authority preceders or followers
            if COMMON_AUTHORITY_FOLLOWERS.match(after) or COMMON_AUTHORITY_PRECEDERS.search(before):
                return True, var

            # If followed by a standard personal name (e.g. "Chase Miller") or preceded by a name ("Fiona Apple"),
            # do not classify as impersonation
            continue

        # For non-ambiguous brands (e.g. PayPal, Microsoft, Amazon, Netflix, etc.):
        # A word boundary match in the display name confirms brand claim
        return True, var

    return False, None


def is_domain_authorized_for_brand(domain: str, brand: ProtectedBrand) -> bool:
    """Verifies if the sender domain belongs to or is authorized for the protected brand."""
    from_norm = normalize_domain(domain)
    if not from_norm:
        return False

    # 1. Exact domain match or subdomain of configured brand domain
    for bd in brand.domains:
        norm_bd = normalize_domain(bd)
        if not norm_bd:
            continue
        if from_norm == norm_bd or is_subdomain_of(from_norm, norm_bd):
            return True

    # 2. Registered domain match via offline PSL
    from_reg = get_registered_domain_offline(from_norm)
    if from_reg:
        for bd in brand.domains:
            norm_bd = normalize_domain(bd)
            if not norm_bd:
                continue
            bd_reg = get_registered_domain_offline(norm_bd)
            if bd_reg and from_reg == bd_reg:
                return True

    # 3. Check explicitly configured allowed subdomains or third-party service domains
    for allowed_sub in brand.allowed_subdomains:
        norm_sub = normalize_domain(allowed_sub)
        if norm_sub and (from_norm == norm_sub or is_subdomain_of(from_norm, norm_sub)):
            return True

    return False


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
    seen_brand_sender: Set[Tuple[str, str]] = set()

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

        # 4. Configurable & Default Protected Brand Impersonation
        effective_brands = (
            config.get_effective_protected_brands()
            if hasattr(config, "get_effective_protected_brands")
            else []
        )
        norm_display_clean = normalize_display_name(display_name, max_len=config.max_input_length)
        if effective_brands and norm_display_clean:
            for brand in effective_brands:
                is_claimed, matched_var = is_brand_claimed_in_display_name(norm_display_clean, brand)
                if is_claimed:
                    if not is_domain_authorized_for_brand(from_domain, brand):
                        brand_key = (brand.name.lower(), (sender.address or "").lower())
                        if brand_key not in seen_brand_sender:
                            seen_brand_sender.add(brand_key)
                            display_name_spoofed = True
                            from_reg = get_registered_domain_offline(from_domain)
                            findings.append(
                                ImpersonationFinding(
                                    indicator="DISPLAY_NAME_BRAND_IMPERSONATION",
                                    target_name=brand.name[: config.max_input_length],
                                    similarity_score=1.0,
                                    description=(
                                        f"Sender display name '{display_name}' claims protected brand '{brand.name}', "
                                        f"but sending domain '{from_domain[:100]}' does not belong to this brand "
                                        f"(registered domain: '{from_reg or from_domain}')."
                                    ),
                                    is_vip=False,
                                )
                            )
                            break

    return display_name_spoofed, findings
