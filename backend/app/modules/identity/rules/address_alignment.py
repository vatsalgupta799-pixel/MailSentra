"""Address alignment detection rules (From vs Reply-To and From vs Return-Path)."""

from typing import List, Optional, Set, Tuple
from app.modules.contracts import ImpersonationFinding, ParsedEmail
from app.modules.identity.config import IdentityAnalysisConfig
from app.modules.identity.domain_utils import is_subdomain_of, normalize_domain


def check_address_alignment(
    parsed_email: ParsedEmail,
    config: IdentityAnalysisConfig,
) -> Tuple[Optional[bool], List[ImpersonationFinding]]:
    """Compares From domain against Reply-To and Return-Path observed headers.

    Returns:
        (envelope_header_match, findings)
        envelope_header_match:
            - True: Confirmed domain alignment between From and Return-Path.
            - False: Confirmed domain discrepancy between From and Return-Path.
            - None: Unavailable / unverified (Return-Path is absent, empty, or From is missing).
    """
    findings: List[ImpersonationFinding] = []
    envelope_header_match: Optional[bool] = None

    if not parsed_email.from_sender or not parsed_email.from_sender.domain:
        return envelope_header_match, findings

    from_domain = normalize_domain(parsed_email.from_sender.domain)
    if not from_domain:
        return envelope_header_match, findings

    # 1. From vs Reply-To domain alignment (inspecting all Reply-To mailboxes)
    reply_to_list = []
    if parsed_email.reply_to:
        reply_to_list.append(parsed_email.reply_to)
    for rt in parsed_email.all_reply_to:
        if rt not in reply_to_list:
            reply_to_list.append(rt)

    inspected_reply_domains: Set[str] = set()
    for rt_obj in reply_to_list:
        if not rt_obj or not rt_obj.domain:
            continue
        reply_to_domain = normalize_domain(rt_obj.domain)
        if not reply_to_domain or reply_to_domain in inspected_reply_domains:
            continue
        inspected_reply_domains.add(reply_to_domain)

        is_reply_aligned = False
        if reply_to_domain == from_domain:
            is_reply_aligned = True
        elif is_subdomain_of(from_domain, reply_to_domain) or is_subdomain_of(reply_to_domain, from_domain):
            is_reply_aligned = True
        else:
            for org_dom in config.protected_domains:
                if is_subdomain_of(from_domain, org_dom) and is_subdomain_of(reply_to_domain, org_dom):
                    is_reply_aligned = True
                    break

        if not is_reply_aligned:
            findings.append(
                ImpersonationFinding(
                    indicator="FROM_REPLYTO_MISMATCH",
                    target_name=reply_to_domain[: config.max_input_length],
                    similarity_score=0.0,
                    description=f"Reply-To domain '{reply_to_domain[:100]}' does not match From domain '{from_domain[:100]}'. Note: Mismatch is an identity discrepancy and may occur in legitimate ticketing, support, and marketing services.",
                    is_vip=False,
                )
            )

    # 2. From vs Return-Path domain alignment
    return_path_raw = parsed_email.return_path
    if return_path_raw is None or str(return_path_raw).strip() in {"", "<>"}:
        envelope_header_match = None
        findings.append(
            ImpersonationFinding(
                indicator="EMPTY_RETURN_PATH",
                target_name=None,
                similarity_score=0.0,
                description="Observed Return-Path header is empty or absent. Note: Delivery status notifications and automated bounces typically use an empty envelope path.",
                is_vip=False,
            )
        )
    else:
        clean_rp = str(return_path_raw).strip().strip("<>\"' ")
        rp_domain = normalize_domain(clean_rp.split("@")[-1]) if "@" in clean_rp else normalize_domain(clean_rp)

        if not rp_domain:
            envelope_header_match = None
            findings.append(
                ImpersonationFinding(
                    indicator="EMPTY_RETURN_PATH",
                    target_name=None,
                    similarity_score=0.0,
                    description="Observed Return-Path header contains no parseable domain.",
                    is_vip=False,
                )
            )
        else:
            is_rp_aligned = False
            if rp_domain == from_domain:
                is_rp_aligned = True
            elif is_subdomain_of(from_domain, rp_domain) or is_subdomain_of(rp_domain, from_domain):
                is_rp_aligned = True
            else:
                for org_dom in config.protected_domains:
                    if is_subdomain_of(from_domain, org_dom) and is_subdomain_of(rp_domain, org_dom):
                        is_rp_aligned = True
                        break

            if is_rp_aligned:
                envelope_header_match = True
            else:
                # Confirmed mismatch: Return-Path domain differs from From domain
                envelope_header_match = False

                # Check if Return-Path uses a recognized ESP bounce domain
                is_recognized_esp = any(
                    rp_domain == esp or is_subdomain_of(rp_domain, esp)
                    for esp in config.recognized_esp_bounce_domains
                )

                if is_recognized_esp:
                    findings.append(
                        ImpersonationFinding(
                            indicator="RECOGNIZED_ESP_RETURN_PATH",
                            target_name=rp_domain[: config.max_input_length],
                            similarity_score=0.0,
                            description=f"Observed Return-Path uses recognized email service provider bounce domain '{rp_domain[:100]}', distinct from From domain '{from_domain[:100]}'. Note: Recognized ESP infrastructure indicates outsourced delivery and does not establish sender authenticity.",
                            is_vip=False,
                        )
                    )
                else:
                    findings.append(
                        ImpersonationFinding(
                            indicator="FROM_RETURN_PATH_MISMATCH",
                            target_name=rp_domain[: config.max_input_length],
                            similarity_score=0.0,
                            description=f"Observed Return-Path domain '{rp_domain[:100]}' does not match From domain '{from_domain[:100]}'. Note: Return-Path is an observed header and does not prove authenticated envelope identity.",
                            is_vip=False,
                        )
                    )

    return envelope_header_match, findings
