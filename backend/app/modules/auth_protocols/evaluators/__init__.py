"""Evaluator sub-package for MailSentra Authentication Protocols (Module 4)."""

from app.modules.auth_protocols.evaluators.auth_results import (
    AuthResultsGenerator,
    AuthResultsTrustEvaluator,
)
from app.modules.auth_protocols.evaluators.spf import SPFEvaluator
from app.modules.auth_protocols.evaluators.dkim import DKIMVerifier
from app.modules.auth_protocols.evaluators.dmarc import (
    DMARCDiscoveryResult,
    DMARCDiscoveryStatus,
    DMARCEvaluator,
    DMARCRecordDiscovery,
    check_domain_alignment,
    parse_dmarc_tags,
    parse_dmarc_tags_with_metadata,
)

__all__ = [
    "AuthResultsGenerator",
    "AuthResultsTrustEvaluator",
    "DKIMVerifier",
    "DMARCDiscoveryResult",
    "DMARCDiscoveryStatus",
    "DMARCEvaluator",
    "DMARCRecordDiscovery",
    "SPFEvaluator",
    "check_domain_alignment",
    "parse_dmarc_tags",
    "parse_dmarc_tags_with_metadata",
]
