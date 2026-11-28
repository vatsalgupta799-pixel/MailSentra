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


class ProtectedBrand(BaseModel):
    """Represents a commercial or institutional brand for display-name impersonation protection."""

    name: str = Field(..., description="Canonical brand display name, e.g. 'PayPal'")
    variations: List[str] = Field(
        default_factory=list,
        description="Alternative brand names, acronyms, or stems, e.g. ['bofa', 'bank of america']",
    )
    domains: List[str] = Field(
        default_factory=list,
        description="Legitimate registered domains for this brand, e.g. ['paypal.com']",
    )
    allowed_subdomains: List[str] = Field(
        default_factory=list,
        description="Additional authorized subdomains or third-party service domains if any",
    )
    is_ambiguous: bool = Field(
        default=False,
        description="True for brand names that are also common personal names or dictionary words (e.g. 'Chase', 'Apple')",
    )

    model_config = ConfigDict(frozen=True)


DEFAULT_PROTECTED_BRANDS: List[ProtectedBrand] = [
    ProtectedBrand(
        name="PayPal",
        variations=["paypal"],
        domains=["paypal.com", "paypal.co.uk", "paypal.de", "paypal.fr", "paypal.com.au"],
        is_ambiguous=False,
    ),
    ProtectedBrand(
        name="Microsoft",
        variations=["microsoft", "microsoft 365", "office 365", "office365", "m365", "msft"],
        domains=[
            "microsoft.com",
            "microsoftonline.com",
            "office.com",
            "office365.com",
            "live.com",
            "outlook.com",
            "msn.com",
        ],
        is_ambiguous=False,
    ),
    ProtectedBrand(
        name="Amazon",
        variations=["amazon", "amazon prime", "aws", "amazon web services"],
        domains=[
            "amazon.com",
            "amazon.co.uk",
            "amazon.de",
            "amazon.ca",
            "amazon.fr",
            "amazon.co.jp",
            "amazonses.com",
        ],
        is_ambiguous=False,
    ),
    ProtectedBrand(
        name="Apple",
        variations=["apple", "apple inc", "icloud"],
        domains=["apple.com", "icloud.com", "email.apple.com"],
        is_ambiguous=True,
    ),
    ProtectedBrand(
        name="eBay",
        variations=["ebay"],
        domains=["ebay.com", "ebay.co.uk", "ebay.de"],
        is_ambiguous=False,
    ),
    ProtectedBrand(
        name="Chase",
        variations=["chase", "chase bank", "jpmorgan chase", "jp morgan chase", "jpmorgan"],
        domains=["chase.com", "jpmorganchase.com", "jpmorgan.com"],
        is_ambiguous=True,
    ),
    ProtectedBrand(
        name="National City",
        variations=["national city", "national city bank", "nationalcity"],
        domains=["nationalcity.com", "pnc.com"],
        is_ambiguous=False,
    ),
    ProtectedBrand(
        name="Wells Fargo",
        variations=["wells fargo", "wellsfargo"],
        domains=["wellsfargo.com"],
        is_ambiguous=False,
    ),
    ProtectedBrand(
        name="Bank of America",
        variations=["bank of america", "bofa", "bankofamerica"],
        domains=["bankofamerica.com", "bofa.com"],
        is_ambiguous=False,
    ),
    ProtectedBrand(
        name="Citi",
        variations=["citi", "citibank", "citigroup"],
        domains=["citi.com", "citibank.com", "citigroup.com"],
        is_ambiguous=False,
    ),
    ProtectedBrand(
        name="Netflix",
        variations=["netflix"],
        domains=["netflix.com"],
        is_ambiguous=False,
    ),
    ProtectedBrand(
        name="Facebook",
        variations=["facebook", "meta"],
        domains=["facebook.com", "facebookmail.com", "meta.com"],
        is_ambiguous=False,
    ),
    ProtectedBrand(
        name="Instagram",
        variations=["instagram"],
        domains=["instagram.com", "mail.instagram.com"],
        is_ambiguous=False,
    ),
    ProtectedBrand(
        name="LinkedIn",
        variations=["linkedin"],
        domains=["linkedin.com", "e.linkedin.com"],
        is_ambiguous=False,
    ),
    ProtectedBrand(
        name="Dropbox",
        variations=["dropbox"],
        domains=["dropbox.com", "dropboxmail.com"],
        is_ambiguous=False,
    ),
    ProtectedBrand(
        name="Yahoo",
        variations=["yahoo"],
        domains=["yahoo.com", "yahoo-inc.com"],
        is_ambiguous=False,
    ),
    ProtectedBrand(
        name="Google",
        variations=["google", "gmail"],
        domains=["google.com", "gmail.com", "googlemail.com"],
        is_ambiguous=False,
    ),
]


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

    # Protected brands configuration for display-name impersonation
    custom_protected_brands: List[ProtectedBrand] = Field(
        default_factory=list,
        description="Custom commercial or institutional brands to protect against display-name impersonation",
    )
    enable_default_brand_protection: bool = Field(
        default=True,
        description="Whether to include the default catalog of high-value protected brands",
    )

    def get_effective_protected_brands(self) -> List[ProtectedBrand]:
        """Returns union of default protected brands, custom configured brands, and organization brands."""
        brands: List[ProtectedBrand] = []
        seen_names = set()

        # 1. Custom brands take precedence
        for b in self.custom_protected_brands:
            if b.name and b.name.lower() not in seen_names:
                brands.append(b)
                seen_names.add(b.name.lower())

        # 2. Add default protected brands if enabled
        if self.enable_default_brand_protection:
            for b in DEFAULT_PROTECTED_BRANDS:
                if b.name.lower() not in seen_names:
                    brands.append(b)
                    seen_names.add(b.name.lower())

        # 3. Add dynamic brand entries for protected organization names if configured
        if self.organization_names and self.protected_domains:
            for org_name in self.organization_names:
                clean_org = org_name.strip()
                if clean_org and clean_org.lower() not in seen_names:
                    brands.append(
                        ProtectedBrand(
                            name=clean_org,
                            variations=[clean_org.lower()],
                            domains=list(self.protected_domains),
                            is_ambiguous=False,
                        )
                    )
                    seen_names.add(clean_org.lower())

        return brands

    model_config = ConfigDict(arbitrary_types_allowed=True)
