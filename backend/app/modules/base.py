"""Abstract base class for all MailSentra detection modules."""

from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseDetectionModule(ABC):
    """Base interface for all analytical security modules in MailSentra."""

    @property
    @abstractmethod
    def module_name(self) -> str:
        """Unique identifier for the module."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Module semantic version string."""
        pass

    @abstractmethod
    async def analyze(self, *args, **kwargs) -> Any:
        """Execute core analysis logic."""
        pass
