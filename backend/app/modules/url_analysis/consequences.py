"""Consequence Analysis & User Guidance Subsystem for URL Security.

Translates technical detection signals into clear, plain-language explanations
of potential risks and offers evidence-based post-click assistance for ordinary
students and non-technical users.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field
from app.modules.contracts import UrlRiskSeverity


class ThreatCategory(str, Enum):
    PHISHING_CREDENTIAL_THEFT = "PHISHING_CREDENTIAL_THEFT"
    MALWARE_DOWNLOAD = "MALWARE_DOWNLOAD"
    RANSOMWARE = "RANSOMWARE"
    PAYMENT_FRAUD = "PAYMENT_FRAUD"
    TRACKING_RECONNAISSANCE = "TRACKING_RECONNAISSANCE"
    EXPLOIT_VULNERABILITY = "EXPLOIT_VULNERABILITY"
    SUSPICIOUS_ANOMALY = "SUSPICIOUS_ANOMALY"
    SAFE = "SAFE"


class LinkConsequences(BaseModel):
    """Plain-language explanation of what could happen if a user interacts with a link."""
    threat_category: ThreatCategory = ThreatCategory.SAFE
    category_title: str
    risk_summary: str
    what_could_happen: List[str] = Field(default_factory=list)
    risk_distinctions: List[str] = Field(default_factory=list)


class PostClickScenario(str, Enum):
    VISITED_NO_INPUT = "VISITED_NO_INPUT"
    ENTERED_PASSWORD = "ENTERED_PASSWORD"
    DOWNLOADED_FILE = "DOWNLOADED_FILE"
    ENTERED_PAYMENT = "ENTERED_PAYMENT"
    GRANTED_ACCESS = "GRANTED_ACCESS"


class PostClickGuidance(BaseModel):
    """Tailored recovery steps if a user already interacted with a link."""
    scenario: PostClickScenario
    scenario_label: str
    recommended_actions: List[str] = Field(default_factory=list)
    urgency_level: str = "MEDIUM"  # "LOW", "MEDIUM", "HIGH", "CRITICAL"


class ConsequenceEvaluator:
    """Evaluates URL detection signals and synthesizes plain-language consequence analysis."""

    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".iso", ".img", ".dmg", ".pkg", ".apk", ".jar"
    }

    RANSOMWARE_INDICATORS = {
        "ransom", "decryptor", "locky", "crypt", "wannacry"
    }

    PAYMENT_TERMS = {
        "billing", "invoice", "payment", "card", "checkout", "bank", "wire", "transfer"
    }

    CREDENTIAL_TERMS = {
        "login", "signin", "sign-in", "log-in", "verify", "account", "security", "update", "password", "auth", "portal"
    }

    def evaluate(
        self,
        url: str,
        severity: UrlRiskSeverity,
        reason: str,
        signals: Optional[List[str]] = None,
    ) -> Optional[LinkConsequences]:
        """Synthesizes human-friendly consequence explanations strictly based on evidence."""
        if severity == UrlRiskSeverity.SAFE:
            return None

        url_lower = url.lower()
        reason_lower = (reason or "").lower()
        sig_list = [s.lower() for s in (signals or [])]
        combined_text = f"{url_lower} {reason_lower} {' '.join(sig_list)}"

        # 1. Check for Ransomware / Weaponized Payload (Requires explicit evidence)
        is_ransomware = any(term in combined_text for term in self.RANSOMWARE_INDICATORS)
        if is_ransomware:
            return LinkConsequences(
                threat_category=ThreatCategory.RANSOMWARE,
                category_title="Potential Ransomware Threat",
                risk_summary="This link references indicators associated with ransomware.",
                what_could_happen=[
                    "The website could attempt to deliver malicious software to your device.",
                    "If a malicious file is downloaded, opened, and executed, it could attempt to encrypt or lock your personal and school documents.",
                    "Recovery typically requires offline backups or professional security assistance.",
                ],
                risk_distinctions=[
                    "Clicking alone does not encrypt files. Actual harm requires downloading and executing a malicious file with system permissions.",
                    "Active antivirus and operating system protections may block untrusted execution.",
                ],
            )

        # 2. Check for Malware / Direct File Download (Requires explicit binary extension or payload signal)
        is_executable = any(url_lower.endswith(ext) or f"{ext}?" in url_lower or f"{ext}#" in url_lower for ext in self.SUSPICIOUS_EXTENSIONS)
        has_file_signal = "suspicious_file_ext" in combined_text or "payload" in combined_text or "malware" in combined_text

        if is_executable or has_file_signal:
            return LinkConsequences(
                threat_category=ThreatCategory.MALWARE_DOWNLOAD,
                category_title="Malicious Software (Malware) Download",
                risk_summary="This link points to an executable program or script disguised as an ordinary link.",
                what_could_happen=[
                    "The website could attempt to automatically download a suspicious file onto your computer or phone.",
                    "If the downloaded file is opened and run, it could attempt to monitor your activity, record keystrokes, or access stored documents.",
                    "An attacker could attempt to gain unauthorized background access to your device.",
                ],
                risk_distinctions=[
                    "Visiting the page or having a file sit unopened in your Downloads folder does not immediately infect your system.",
                    "Compromise requires running or opening the downloaded file and granting it permission to execute.",
                ],
            )

        # 3. Check for Payment / Financial Fraud
        is_payment = any(term in combined_text for term in self.PAYMENT_TERMS) and (
            "brand" in combined_text or "spoof" in combined_text or "impersonation" in combined_text or "tld" in combined_text or "ip" in combined_text
        )
        if is_payment:
            return LinkConsequences(
                threat_category=ThreatCategory.PAYMENT_FRAUD,
                category_title="Deceptive Payment / Financial Lure",
                risk_summary="This link leads to an unverified or deceptive destination requesting financial or payment information.",
                what_could_happen=[
                    "A fraudulent payment form could attempt to capture your credit/debit card numbers, expiration dates, or bank routing details.",
                    "Unauthorized charges or recurring transactions could be initiated using your stolen payment information.",
                    "Your personal billing information could be sold or shared across fraudulent networks.",
                ],
                risk_distinctions=[
                    "Merely loading the page does not charge your bank or leak card numbers.",
                    "Financial risk occurs when card details or bank credentials are submitted into forms on the deceptive website.",
                ],
            )

        # 4. Check for Phishing / Credential Harvesting (Brand Impersonation, Subdomain Hijacking, Typosquatting, Login Lures)
        is_phishing = (
            "brand" in combined_text
            or "impersonation" in combined_text
            or "homograph" in combined_text
            or "typosquatting" in combined_text
            or "embedded_credentials" in combined_text
            or any(term in combined_text for term in self.CREDENTIAL_TERMS)
        )
        if is_phishing:
            return LinkConsequences(
                threat_category=ThreatCategory.PHISHING_CREDENTIAL_THEFT,
                category_title="Phishing / Fake Login Page",
                risk_summary="This link appears to mimic a legitimate organization or service to harvest credentials.",
                what_could_happen=[
                    "A fake login page could capture your university, email, or work username and password.",
                    "An unauthorized party could use your stolen password to access your mailbox, student portal, or cloud files.",
                    "Attackers could attempt password reuse against other online services where you use the same credentials.",
                ],
                risk_distinctions=[
                    "Simply viewing the login screen does not compromise your account or transfer your password.",
                    "The primary risk occurs if you type your credentials into the form and submit them.",
                ],
            )

        # 5. Check for Tracking / Reconnaissance Links
        is_tracking = "known_shortener" in combined_text or "open_redirect" in combined_text or "tracking" in combined_text
        if is_tracking:
            return LinkConsequences(
                threat_category=ThreatCategory.TRACKING_RECONNAISSANCE,
                category_title="Tracking / Deceptive Redirector",
                risk_summary="This link conceals its final destination or monitors user click engagement.",
                what_could_happen=[
                    "The sender can verify that your email address is active and that an individual clicked the message.",
                    "The link may redirect your browser through intermediate servers to bypass standard security filters.",
                    "Information about your browser, operating system, and general IP location may be logged.",
                ],
                risk_distinctions=[
                    "Click tracking does not steal passwords or install software on its own.",
                    "However, the final destination page after redirection could present phishing or unwanted content.",
                ],
            )

        # 6. Default Fallback: Suspicious Anomaly (IP-literal hosts, suspicious TLDs, hex encodings)
        return LinkConsequences(
            threat_category=ThreatCategory.SUSPICIOUS_ANOMALY,
            category_title="Unverified / Suspicious Web Destination",
            risk_summary="This link exhibits technical anomalies (such as an unverified numeric IP address or high-risk domain suffix).",
            what_could_happen=[
                "You could be routed to an unmonitored server operating outside institutional security standards.",
                "The site may present unexpected pop-ups, deceptive download prompts, or unsolicited forms.",
                "Your IP address and browser technical details will be visible to the server host.",
            ],
            risk_distinctions=[
                "Loading the address alone does not mean your computer is compromised.",
                "Caution is advised: do not submit confidential information or accept unexpected file downloads.",
            ],
        )

    @classmethod
    def get_all_post_click_scenarios(cls) -> List[PostClickGuidance]:
        """Returns standard, user-friendly recovery instructions for all possible user actions."""
        return [
            PostClickGuidance(
                scenario=PostClickScenario.VISITED_NO_INPUT,
                scenario_label="I only opened the link, but entered no information and downloaded nothing.",
                recommended_actions=[
                    "Close the suspicious browser tab or window immediately.",
                    "Do not click any buttons, pop-ups, or 'Accept Cookies' prompts on that page.",
                    "Clear your browser's recent cache and temporary cookies if you want extra caution.",
                    "Take a breath: merely loading a webpage without typing credentials or opening downloads very rarely causes account compromise.",
                ],
                urgency_level="LOW",
            ),
            PostClickGuidance(
                scenario=PostClickScenario.ENTERED_PASSWORD,
                scenario_label="I entered my username and/or password on the page.",
                recommended_actions=[
                    "Immediately open a new, clean tab and navigate directly to the official service website (e.g. portal.university.edu or your provider).",
                    "Change your password immediately to a strong, unique passphrase.",
                    "If the service supports it, click 'Sign out of all other sessions' or 'Log out everywhere'.",
                    "Enable Multi-Factor Authentication (MFA / 2FA) if it is not already active.",
                    "If you reused this same password on any other account (banking, personal email, social media), change those passwords right away.",
                    "Report the incident to your institution's IT Helpdesk or Information Security office so they can protect your account.",
                ],
                urgency_level="CRITICAL",
            ),
            PostClickGuidance(
                scenario=PostClickScenario.DOWNLOADED_FILE,
                scenario_label="A file was downloaded to my device (or the page prompted me to save one).",
                recommended_actions=[
                    "Do NOT open, double-click, or extract the downloaded file.",
                    "Do NOT click 'Enable Content', 'Enable Macros', or bypass Windows Defender / macOS Gatekeeper warnings.",
                    "Delete the downloaded file from your Downloads folder and empty your Recycle Bin / Trash.",
                    "If you already opened or ran the file, immediately disconnect your device from Wi-Fi / Ethernet to isolate it, and contact your IT / security team for incident assistance.",
                ],
                urgency_level="HIGH",
            ),
            PostClickGuidance(
                scenario=PostClickScenario.ENTERED_PAYMENT,
                scenario_label="I submitted credit card numbers, banking details, or payment info.",
                recommended_actions=[
                    "Contact your bank or card issuer immediately using the trusted phone number on the back of your card or official banking app.",
                    "Request an immediate freeze or card replacement to prevent unauthorized charges.",
                    "Review recent transaction statements carefully for unrecognized pending charges.",
                    "File a fraud report with your financial institution if funds have already been moved.",
                ],
                urgency_level="CRITICAL",
            ),
            PostClickGuidance(
                scenario=PostClickScenario.GRANTED_ACCESS,
                scenario_label="I installed remote software or granted device permissions.",
                recommended_actions=[
                    "Immediately disconnect the computer from the internet (turn off Wi-Fi or unplug network cable).",
                    "Do not use the potentially compromised computer to change passwords; use a separate, trusted device (such as your phone).",
                    "Contact your organizational IT Security / Helpdesk immediately for physical device inspection.",
                ],
                urgency_level="CRITICAL",
            ),
        ]


# Singleton instance
consequence_evaluator = ConsequenceEvaluator()
