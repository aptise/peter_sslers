"""Shared types for the audit regression tests."""

from typing import Dict
from typing import List
from typing import Optional
from typing import TypeVar
from typing import Union

from typing_extensions import Protocol
from typing_extensions import TypeAlias

JSONValue: TypeAlias = Union[
    None, bool, int, float, str, List["JSONValue"], Dict[str, "JSONValue"]
]


class PollingClock(Protocol):
    current: float
    delays: List[float]

    def monotonic(self) -> float: ...
    def sleep(self, delay: float) -> None: ...


T = TypeVar("T")


def require_row(value: Optional[T]) -> T:
    """Assert that a fixture row exists while preserving its model type."""
    assert value is not None
    return value
