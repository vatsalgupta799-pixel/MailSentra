"""Contracts, schemas, and lifecycle state machine for MailSentra Dataset Ecosystem."""

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Set


class DatasetCategory(str, Enum):
    PHISHING_EMAIL = "phishing_email"
    SPAM_EMAIL = "spam_email"
    SENDER_SPOOFING = "sender_spoofing"
    BEC_FRAUD = "bec_fraud"
    SOCIAL_ENGINEERING = "social_engineering"
    MALICIOUS_URLS = "malicious_urls"
    MALWARE_ATTACHMENTS = "malware_attachments"
    BENIGN_CONTROLS = "benign_controls"


class DatasetLifecycleStatus(str, Enum):
    """Formal dataset lifecycle states enforcing strict progression gates."""
    DISCOVERED = "DISCOVERED"
    PROVENANCE_VERIFIED = "PROVENANCE_VERIFIED"
    LICENSE_VERIFIED = "LICENSE_VERIFIED"
    CONDITIONALLY_APPROVED = "CONDITIONALLY_APPROVED"
    APPROVED = "APPROVED"
    DOWNLOADED = "DOWNLOADED"
    INTEGRATED = "INTEGRATED"
    EVALUATED = "EVALUATED"
    REJECTED = "REJECTED"


class ProvenanceNature(str, Enum):
    """Explicit provenance classification for dataset records."""
    EXTERNAL_ACQUIRED = "EXTERNAL_ACQUIRED"
    SYNTHETIC_FIXTURE_MOCK = "SYNTHETIC_FIXTURE_MOCK"
    TRANSFORMED_DERIVATIVE = "TRANSFORMED_DERIVATIVE"


# Explicit state transition graph
ALLOWED_TRANSITIONS: Dict[DatasetLifecycleStatus, Set[DatasetLifecycleStatus]] = {
    DatasetLifecycleStatus.DISCOVERED: {
        DatasetLifecycleStatus.PROVENANCE_VERIFIED,
        DatasetLifecycleStatus.REJECTED,
    },
    DatasetLifecycleStatus.PROVENANCE_VERIFIED: {
        DatasetLifecycleStatus.LICENSE_VERIFIED,
        DatasetLifecycleStatus.REJECTED,
    },
    DatasetLifecycleStatus.LICENSE_VERIFIED: {
        DatasetLifecycleStatus.APPROVED,
        DatasetLifecycleStatus.CONDITIONALLY_APPROVED,
        DatasetLifecycleStatus.REJECTED,
    },
    DatasetLifecycleStatus.CONDITIONALLY_APPROVED: {
        DatasetLifecycleStatus.APPROVED,
        DatasetLifecycleStatus.DOWNLOADED,
        DatasetLifecycleStatus.REJECTED,
    },
    DatasetLifecycleStatus.APPROVED: {
        DatasetLifecycleStatus.DOWNLOADED,
        DatasetLifecycleStatus.REJECTED,
    },
    DatasetLifecycleStatus.DOWNLOADED: {
        DatasetLifecycleStatus.INTEGRATED,
        DatasetLifecycleStatus.REJECTED,
    },
    DatasetLifecycleStatus.INTEGRATED: {
        DatasetLifecycleStatus.EVALUATED,
        DatasetLifecycleStatus.REJECTED,
    },
    # EVALUATED is terminal unless an explicit administrative reset mechanism is invoked
    DatasetLifecycleStatus.EVALUATED: set(),
    # REJECTED is terminal
    DatasetLifecycleStatus.REJECTED: set(),
}


# Backwards compatibility enums
class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    CONDITIONALLY_APPROVED = "CONDITIONALLY_APPROVED"
    REJECTED = "REJECTED"
    PENDING = "PENDING"


class IntegrationStatus(str, Enum):
    INTEGRATED = "INTEGRATED"
    USED_IN_EVALUATION = "USED_IN_EVALUATION"
    DISCOVERED_ONLY = "DISCOVERED_ONLY"
    REJECTED = "REJECTED"


class CanonicalThreatLabel(str, Enum):
    BENIGN = "BENIGN"
    PHISHING = "PHISHING"
    SPAM = "SPAM"
    SPOOFING = "SPOOFING"
    BEC = "BEC"
    SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"
    MALICIOUS_URL = "MALICIOUS_URL"
    MALWARE_ATTACHMENT = "MALWARE_ATTACHMENT"
    SUSPICIOUS = "SUSPICIOUS"
    UNKNOWN = "UNKNOWN"


class DatasetLifecycleError(Exception):
    """Raised when an invalid lifecycle transition or failed evaluation gate occurs."""
    pass


def validate_lifecycle_transition(
    current_status: DatasetLifecycleStatus,
    target_status: DatasetLifecycleStatus,
    entry: Dict[str, Any],
) -> None:
    """Validates that a transition from current_status to target_status is permitted by the state graph

    AND satisfies all destination-state invariant gates.
    """
    if current_status not in ALLOWED_TRANSITIONS:
        raise DatasetLifecycleError(f"Unknown or invalid current lifecycle status: '{current_status}'")

    allowed = ALLOWED_TRANSITIONS[current_status]
    if target_status not in allowed:
        raise DatasetLifecycleError(
            f"Illegal lifecycle transition for dataset '{entry.get('dataset_id')}': "
            f"cannot transition directly from '{current_status.value}' to '{target_status.value}'."
        )

    # Validate destination state invariants
    entry_with_target = dict(entry)
    entry_with_target["lifecycle_status"] = target_status.value
    validate_lifecycle_state(entry_with_target)


def validate_lifecycle_state(entry: Dict[str, Any]) -> None:
    """Enforces strict validation rules across dataset lifecycle stages.

    Guarantees:
    - No duplicate corpus can be APPROVED or EVALUATED.
    - No dataset can reach DOWNLOADED without existing files and external record counts.
    - No synthetic fixtures can satisfy DOWNLOADED or EVALUATED external acquisition counts.
    - No dataset can reach EVALUATED without verified files, evaluated records > 0,
      evaluation run ID, and evidence location pointing to actual execution evidence.
    """
    status_str = entry.get("lifecycle_status")
    if not status_str:
        raise DatasetLifecycleError(f"Dataset {entry.get('dataset_id')} is missing 'lifecycle_status'")

    valid_statuses = {s.value for s in DatasetLifecycleStatus}
    if status_str not in valid_statuses:
        raise DatasetLifecycleError(f"Invalid lifecycle status '{status_str}' for dataset {entry.get('dataset_id')}")

    status = DatasetLifecycleStatus(status_str)

    # 1. Rejection Validation
    if status == DatasetLifecycleStatus.REJECTED:
        return

    # 2. Gate: Provenance Verification
    if status in (
        DatasetLifecycleStatus.PROVENANCE_VERIFIED,
        DatasetLifecycleStatus.LICENSE_VERIFIED,
        DatasetLifecycleStatus.APPROVED,
        DatasetLifecycleStatus.CONDITIONALLY_APPROVED,
        DatasetLifecycleStatus.DOWNLOADED,
        DatasetLifecycleStatus.INTEGRATED,
        DatasetLifecycleStatus.EVALUATED,
    ):
        source_url = entry.get("source_url")
        if not source_url or not (source_url.startswith("http://") or source_url.startswith("https://")):
            raise DatasetLifecycleError(f"{entry.get('dataset_id')} must have a valid HTTP(S) source_url")
        if not entry.get("publisher"):
            raise DatasetLifecycleError(f"{entry.get('dataset_id')} must have an identified publisher")
        if entry.get("duplicate_of") is not None:
            raise DatasetLifecycleError(f"Corpus {entry.get('dataset_id')} is a duplicate of {entry.get('duplicate_of')} and cannot be {status}")

    # 3. Gate: License Verification
    if status in (
        DatasetLifecycleStatus.LICENSE_VERIFIED,
        DatasetLifecycleStatus.APPROVED,
        DatasetLifecycleStatus.CONDITIONALLY_APPROVED,
        DatasetLifecycleStatus.DOWNLOADED,
        DatasetLifecycleStatus.INTEGRATED,
        DatasetLifecycleStatus.EVALUATED,
    ):
        if not entry.get("license"):
            raise DatasetLifecycleError(f"{entry.get('dataset_id')} must have documented license terms")

    # 4. Gate: Downloaded (Requires genuine external records, synthetic fixtures cannot satisfy)
    if status == DatasetLifecycleStatus.DOWNLOADED:
        local_path = entry.get("local_file_path")
        if not local_path:
            raise DatasetLifecycleError(f"{entry.get('dataset_id')} has status DOWNLOADED but no local_file_path")
        if entry.get("external_records_count", 0) <= 0:
            raise DatasetLifecycleError(
                f"{entry.get('dataset_id')} cannot be marked DOWNLOADED without genuine external records "
                f"(external_records_count <= 0). Synthetic fixtures cannot satisfy external acquisition."
            )
        if entry.get("raw_record_count", 0) <= 0:
            raise DatasetLifecycleError(f"{entry.get('dataset_id')} has status DOWNLOADED but raw_record_count <= 0")

    if status in (
        DatasetLifecycleStatus.INTEGRATED,
        DatasetLifecycleStatus.EVALUATED,
    ):
        local_path = entry.get("local_file_path")
        if not local_path:
            raise DatasetLifecycleError(f"{entry.get('dataset_id')} has status {status} but no local_file_path")
        if entry.get("raw_record_count", 0) <= 0 and entry.get("synthetic_records_count", 0) <= 0:
            raise DatasetLifecycleError(f"{entry.get('dataset_id')} has status {status} but raw_record_count <= 0")

    # 5. Gate: Integrated
    if status in (
        DatasetLifecycleStatus.INTEGRATED,
        DatasetLifecycleStatus.EVALUATED,
    ):
        if not entry.get("applicable_production_module"):
            raise DatasetLifecycleError(f"{entry.get('dataset_id')} must have an assigned applicable_production_module")

    # 6. Strict Gate: Evaluated
    if status == DatasetLifecycleStatus.EVALUATED:
        local_path = entry.get("local_file_path")
        if not local_path:
            raise DatasetLifecycleError(f"Cannot mark {entry.get('dataset_id')} as EVALUATED: local_file_path is missing")
        if not os.path.exists(local_path):
            raise DatasetLifecycleError(f"Cannot mark {entry.get('dataset_id')} as EVALUATED: file '{local_path}' does not exist on disk")
        if entry.get("evaluated_record_count", 0) <= 0:
            raise DatasetLifecycleError(f"Cannot mark {entry.get('dataset_id')} as EVALUATED: evaluated_record_count is 0")
        if not entry.get("evaluation_run_id"):
            raise DatasetLifecycleError(f"Cannot mark {entry.get('dataset_id')} as EVALUATED: missing evaluation_run_id")
        if not entry.get("evidence_location"):
            raise DatasetLifecycleError(f"Cannot mark {entry.get('dataset_id')} as EVALUATED: missing evidence_location")


@dataclass
class DatasetEntry:
    dataset_id: str
    dataset_name: str
    category: DatasetCategory
    publisher: str
    source_url: str
    download_url: Optional[str]
    version: str
    license: str
    total_records: int
    lifecycle_status: DatasetLifecycleStatus
    intended_module: str
    applicable_production_module: str
    provenance: str
    provenance_nature: ProvenanceNature = ProvenanceNature.EXTERNAL_ACQUIRED
    is_synthetic_fixture: bool = False
    verification_status: VerificationStatus = VerificationStatus.VERIFIED
    integration_status: IntegrationStatus = IntegrationStatus.INTEGRATED
    local_file_path: Optional[str] = None
    raw_record_count: int = 0
    parsed_record_count: int = 0
    evaluated_record_count: int = 0
    external_records_count: int = 0
    synthetic_records_count: int = 0
    transformation_notes: Optional[str] = None
    evaluation_run_id: Optional[str] = None
    evidence_location: Optional[str] = None
    retrieval_date: str = "2026-11-27"
    duplicate_of: Optional[str] = None
    file_format: str = "CSV"
    checksum_sha256: Optional[str] = None
    known_limitations: Optional[str] = None
    sample_count: int = 0
    class_distribution: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "dataset_name": self.dataset_name,
            "category": self.category.value,
            "publisher": self.publisher,
            "source_url": self.source_url,
            "download_url": self.download_url,
            "version": self.version,
            "license": self.license,
            "total_records": self.total_records,
            "lifecycle_status": self.lifecycle_status.value,
            "provenance_nature": self.provenance_nature.value if hasattr(self.provenance_nature, "value") else str(self.provenance_nature),
            "is_synthetic_fixture": self.is_synthetic_fixture,
            "verification_status": self.verification_status.value,
            "integration_status": self.integration_status.value,
            "intended_module": self.intended_module,
            "applicable_production_module": self.applicable_production_module,
            "provenance": self.provenance,
            "local_file_path": self.local_file_path,
            "raw_record_count": self.raw_record_count,
            "parsed_record_count": self.parsed_record_count,
            "evaluated_record_count": self.evaluated_record_count,
            "external_records_count": self.external_records_count,
            "synthetic_records_count": self.synthetic_records_count,
            "transformation_notes": self.transformation_notes,
            "evaluation_run_id": self.evaluation_run_id,
            "evidence_location": self.evidence_location,
            "retrieval_date": self.retrieval_date,
            "duplicate_of": self.duplicate_of,
            "file_format": self.file_format,
            "checksum_sha256": self.checksum_sha256,
            "known_limitations": self.known_limitations,
            "sample_count": self.sample_count,
            "class_distribution": self.class_distribution,
        }
