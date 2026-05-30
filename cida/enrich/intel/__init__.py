"""External intelligence adapters (Proshare, BusinessDay Intelligence, HIBP).

These are SKELETONS with the correct interface. Wire them to live APIs/scraping
once subscription tiers / API keys are decided. All adapters return a
CompanyIntelSnapshot via `.fetch(org_name)`.
"""
from cida.enrich.intel.base import IntelSource
from cida.enrich.intel.proshare import ProshareAdapter
from cida.enrich.intel.businessday import BusinessDayAdapter
from cida.enrich.intel.orchestrator import (
    IntelImpact,
    derive_intel_impact,
    gather_company_intel,
)

__all__ = [
    "IntelSource",
    "ProshareAdapter",
    "BusinessDayAdapter",
    "IntelImpact",
    "derive_intel_impact",
    "gather_company_intel",
]
