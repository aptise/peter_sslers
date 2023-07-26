# stdlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyramid.config import Configurator

# ==============================================================================


def includeme(config: "Configurator") -> None:
    """
    Pyramid API hook
    """
    pass
