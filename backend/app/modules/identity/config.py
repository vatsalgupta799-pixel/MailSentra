"""Configuration models and settings for Sender Identity Analysis."""

from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class VIPIdentity(BaseModel):
    """Represents a high-profile individual whose identity requires spoofing protection."""

    name: str = Field(..., description="Full name or display name of the VIP")
    titles: List[str] = Field(default_factory=list, description="Titles or designations, e.g. CEO, Dean")
    allowed_domains: List[str] = Field(
        default_factory=list, description="Authorized email domains for this VIP"
    )

    model_config = ConfigDict(frozen=True)


class IdentityAnalysisConfig(BaseModel):
    """Configuration settings for Module 3: Sender Identity Analysis."""

    # Protected organization configuration (defaults to empty)
    protected_domains: List[str] = Field(
        default_factory=list,
        description="Domains belonging to the protected organization",
    )
    organization_names: List[str] = Field(
        default_factory=list,
        description="Names of protected organizations or departments",
    )
    vip_identities: List[VIPIdentity] = Field(
        default_factory=list,
        description="Protected executive or VIP identities",
    )
    organizational_roles: List[str] = Field(
        default_factory=list,
        description="Organizational role keywords (e.g. Helpdesk, Payroll, Dean)",
    )

    # Email Service Providers (ESP) recognized bounce domains
    recognized_esp_bounce_domains: List[str] = Field(
        default_factory=lambda: [
            "sendgrid.net",
            "mailgun.org",
            "amazonses.com",
            "mcsv.net",
            "mcdlv.net",
            "constantcontact.com",
            "sparkpostmail.com",
            "postmarkapp.com",
            "mailjet.com",
            "salesforce.com",
            "zendesk.com",
        ],
        description="Known legitimate third-party ESP envelope bounce domains",
    )

    # Operational & Safety bounds
    max_findings: int = Field(default=20, ge=1, le=100)
    max_description_length: int = Field(default=500, ge=50, le=2000)
    max_input_length: int = Field(default=255, ge=50, le=1000)

    # Lookalike & Typosquatting thresholds
    typosquatting_max_distance: int = Field(default=2, ge=1, le=5)
    typosquatting_min_similarity: float = Field(default=0.80, ge=0.5, le=1.0)
    typosquatting_min_domain_length: int = Field(default=5, ge=3, le=20)

    model_config = ConfigDict(arbitrary_types_allowed=True)
