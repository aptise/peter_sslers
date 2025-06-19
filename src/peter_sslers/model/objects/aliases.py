# pypi
from sqlalchemy.orm import aliased

# local
from .objects import AcmeOrder
from .objects import CoverageAssuranceEvent
from .objects import UniqueFQDNSet
from .objects import UniqueFQDNSet2Domain

# ==============================================================================


AcmeOrderAlt = aliased(AcmeOrder)
CoverageAssuranceEventAlt = aliased(CoverageAssuranceEvent)
UniqueFQDNSetAlt = aliased(UniqueFQDNSet)
UniqueFQDNSet2DomainAlt = aliased(UniqueFQDNSet2Domain)


# ==============================================================================


__all__ = (
    "AcmeOrderAlt",
    "CoverageAssuranceEventAlt",
    "UniqueFQDNSetAlt",
    "UniqueFQDNSet2DomainAlt",
)
