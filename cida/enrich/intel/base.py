"""Base interface for company-intel adapters."""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone

from cida.models import CompanyIntelSnapshot


class IntelSource(ABC):
    name: str

    @abstractmethod
    def fetch(self, org_name: str, country: str | None = None) -> CompanyIntelSnapshot:
        """Return an intel snapshot. MUST NOT raise; return empty snapshot on failure."""

    def _empty(self, org_name: str) -> CompanyIntelSnapshot:
        return CompanyIntelSnapshot(
            org_name=org_name, source=self.name, fetched_at=datetime.now(tz=timezone.utc)
        )
