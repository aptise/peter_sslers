# pypi
from sqlalchemy.orm import aliased

# local
from .objects import AcmeOrder
from .objects import CoverageAssuranceEvent

# ==============================================================================


AcmeOrderAlt = aliased(AcmeOrder)
CoverageAssuranceEventAlt = aliased(CoverageAssuranceEvent)


# ==============================================================================


__all__ = (
    "AcmeOrder",
    "CoverageAssuranceEvent",
)
