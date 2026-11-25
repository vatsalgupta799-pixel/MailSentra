"""Rule definitions for Sender Identity Analysis."""

from app.modules.identity.rules.address_alignment import check_address_alignment
from app.modules.identity.rules.display_name import check_display_name
from app.modules.identity.rules.header_integrity import check_header_integrity
from app.modules.identity.rules.lookalike_domain import check_lookalike_domains

__all__ = [
    "check_header_integrity",
    "check_address_alignment",
    "check_display_name",
    "check_lookalike_domains",
]
