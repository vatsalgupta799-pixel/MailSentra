"""Module 3: Sender Identity Verification Module."""

from app.modules.identity.analyzer import SenderIdentityAnalyzer
from app.modules.identity.config import IdentityAnalysisConfig, VIPIdentity

__all__ = [
    "SenderIdentityAnalyzer",
    "IdentityAnalysisConfig",
    "VIPIdentity",
]
