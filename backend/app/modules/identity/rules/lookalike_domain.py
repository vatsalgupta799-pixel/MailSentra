"""Lookalike domain detection rules (Punycode, IDNA decoding, mixed-script, typosquatting)."""

from typing import List, Set, Tuple
from app.modules.contracts import ImpersonationFinding, ParsedEmail
from app.modules.identity.config import IdentityAnalysisConfig
from app.modules.identity.domain_utils import (
    calculate_domain_similarity,
    damerau_levenshtein_distance,
    decode_idna_safely,
    detect_mixed_scripts,
    detect_suspicious_unicode,
    get_registered_domain_offline,
    is_subdomain_of,
    normalize_domain,
)


def check_lookalike_domains(
    parsed_email: ParsedEmail,
    config: IdentityAnalysisConfig,
) -> Tuple[bool, bool, bool, List[ImpersonationFinding]]:
    """Inspects all sender domains for Punycode, mixed-script, and typosquatting indicators.

    Returns:
        (punycode_detected, homoglyph_detected, typosquatting_detected, findings)
    """
    findings: List[ImpersonationFinding] = []
    punycode_detected = False
    homoglyph_detected = False
    typosquatting_detected = False

    # Collect domains across all From senders (inspect all mailboxes, not just first)
    domains_to_check: Set[str] = set()
    if parsed_email.from_sender and parsed_email.from_sender.domain:
        norm_d = normalize_domain(parsed_email.from_sender.domain)
        if norm_d:
            domains_to_check.add(norm_d)

    for sender in parsed_email.all_from_senders:
        if sender and sender.domain:
            norm_d = normalize_domain(sender.domain)
            if norm_d:
                domains_to_check.add(norm_d)

    if not domains_to_check:
        return punycode_detected, homoglyph_detected, typosquatting_detected, findings

    for domain in sorted(domains_to_check):
        # 1. Punycode label detection & Safe IDNA decoding
        has_punycode, decoded_domain = decode_idna_safely(domain)
        if has_punycode:
            punycode_detected = True
            findings.append(
                ImpersonationFinding(
                    indicator="PUNYCODE_DOMAIN_LABEL",
                    target_name=domain[: config.max_input_length],
                    similarity_score=0.0,
                    description=f"Sender domain '{domain[:100]}' contains Punycode label (IDN representation: '{decoded_domain[:100]}'). Note: Punycode is a standard internationalized domain encoding and requires context.",
                    is_vip=False,
                )
            )

        # 2. Mixed-script detection (in decoded domain string)
        is_mixed, scripts_found = detect_mixed_scripts(decoded_domain)
        if is_mixed:
            homoglyph_detected = True
            findings.append(
                ImpersonationFinding(
                    indicator="MIXED_SCRIPT_DOMAIN",
                    target_name=decoded_domain[: config.max_input_length],
                    similarity_score=0.0,
                    description=f"Domain '{decoded_domain[:100]}' contains mixed Unicode scripts ({', '.join(scripts_found)}), which may indicate visual lookalike spoofing.",
                    is_vip=False,
                )
            )

        # 3. Suspicious Unicode in domain string
        has_suspicious, susp_names = detect_suspicious_unicode(domain)
        if has_suspicious:
            homoglyph_detected = True
            findings.append(
                ImpersonationFinding(
                    indicator="SUSPICIOUS_UNICODE_CHARACTERS",
                    target_name=domain[: config.max_input_length],
                    similarity_score=0.0,
                    description=f"Domain string '{domain[:100]}' contains suspicious Unicode control or invisible characters: {', '.join(susp_names)}.",
                    is_vip=False,
                )
            )

        # 4. Configured protected-domain lookalike checks (Typosquatting)
        if config.protected_domains:
            # Extract registered base domain using offline PSL snapshot
            reg_domain = get_registered_domain_offline(domain)

            for protected_dom in config.protected_domains:
                norm_prot = normalize_domain(protected_dom)
                if not norm_prot:
                    continue

                # Legitimate protected domain or its subdomain is clean
                if domain == norm_prot or is_subdomain_of(domain, norm_prot):
                    continue

                reg_prot = get_registered_domain_offline(norm_prot)
                # If registered domains match, it is a legitimate subdomain of the protected domain
                if reg_domain and reg_prot and reg_domain == reg_prot:
                    continue

                # Compare registered domains if available, otherwise compare full domains
                comp_sender = reg_domain if reg_domain else domain
                comp_prot = reg_prot if reg_prot else norm_prot

                # Avoid false positives on excessively short domain strings
                if (
                    len(comp_sender) < config.typosquatting_min_domain_length
                    or len(comp_prot) < config.typosquatting_min_domain_length
                ):
                    continue

                # Compute Damerau-Levenshtein edit distance and similarity
                dist = damerau_levenshtein_distance(comp_sender, comp_prot)
                similarity = calculate_domain_similarity(comp_sender, comp_prot)

                if (
                    dist <= config.typosquatting_max_distance
                    and similarity >= config.typosquatting_min_similarity
                ):
                    typosquatting_detected = True
                    findings.append(
                        ImpersonationFinding(
                            indicator="TYPOSQUATTING_LOOKALIKE_DOMAIN",
                            target_name=norm_prot[: config.max_input_length],
                            similarity_score=similarity,
                            description=f"Sender domain '{domain[:100]}' closely resembles configured protected domain '{norm_prot[:100]}' (registered domain: '{comp_sender}' vs '{comp_prot}', edit distance: {dist}, similarity: {similarity:.2f}).",
                            is_vip=False,
                        )
                    )

    return punycode_detected, homoglyph_detected, typosquatting_detected, findings
