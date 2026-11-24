"""API Key Generation, Hashing, and Constant-Time Verification Utilities."""

import hashlib
import hmac
import secrets
from typing import Optional


def generate_api_key(prefix: str = "ms_live_") -> str:
    """Generates a cryptographically random, high-entropy 256-bit API key.

    Example: 'ms_live_4f8a9b2c...32bytes'
    """
    token = secrets.token_urlsafe(32)
    return f"{prefix}{token}"


def hash_api_key(api_key: str) -> str:
    """Computes a SHA-256 digest of the API key for secure storage."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def verify_api_key(provided_key: Optional[str], expected_key_or_hash: Optional[str]) -> bool:
    """Performs constant-time comparison of provided API key against expected secret.

    Supports:
    - Direct constant-time string comparison (e.g. against environment variable secret)
    - SHA-256 hashed constant-time comparison
    """
    if not provided_key or not expected_key_or_hash:
        return False

    clean_provided = provided_key.strip()
    clean_expected = expected_key_or_hash.strip()

    # Direct constant-time string comparison
    if secrets.compare_digest(clean_provided, clean_expected):
        return True

    # Check if expected is a SHA-256 hash (64 hex characters)
    if len(clean_expected) == 64:
        provided_hash = hash_api_key(clean_provided)
        if secrets.compare_digest(provided_hash, clean_expected):
            return True

    return False
