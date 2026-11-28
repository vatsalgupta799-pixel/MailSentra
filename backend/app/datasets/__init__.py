"""MailSentra Dataset Subsystem."""

from app.datasets.contracts import (
    DatasetCategory,
    DatasetLifecycleStatus,
    DatasetLifecycleError,
    validate_lifecycle_state,
    VerificationStatus,
    IntegrationStatus,
    CanonicalThreatLabel,
    DatasetEntry,
)
from app.datasets.adapters import (
    BaseDatasetAdapter,
    EmailDatasetAdapter,
    UrlDatasetAdapter,
    AttachmentDatasetAdapter,
)
from app.datasets.pipeline import DatasetValidationPipeline

__all__ = [
    "DatasetCategory",
    "DatasetLifecycleStatus",
    "DatasetLifecycleError",
    "validate_lifecycle_state",
    "VerificationStatus",
    "IntegrationStatus",
    "CanonicalThreatLabel",
    "DatasetEntry",
    "BaseDatasetAdapter",
    "EmailDatasetAdapter",
    "UrlDatasetAdapter",
    "AttachmentDatasetAdapter",
    "DatasetValidationPipeline",
]
