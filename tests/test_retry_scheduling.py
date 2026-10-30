from __future__ import annotations

from typing import TYPE_CHECKING


import datetime
from types import SimpleNamespace
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import cast
from unittest.mock import Mock

import pytest

from peter_sslers.lib import acme_v2
from peter_sslers.lib import errors
from peter_sslers.lib.acme_v2 import AriCheckResult
from peter_sslers.lib.acme_v2 import AuthenticatedUser
from peter_sslers.lib.db.create import create__AriCheck
from peter_sslers.lib.utils_datetime import retry_after_datetime
from peter_sslers.model.objects import X509Certificate

from ._typing import JSONValue
from ._typing import PollingClock

if TYPE_CHECKING:
    from peter_sslers.lib.context import ApiContext


NOW = datetime.datetime(2026, 10, 29, 12, tzinfo=datetime.timezone.utc)


@pytest.mark.parametrize(
    "value,seconds",
    [
        ("60", 60),
        ("0", 0),
        (" 12 ", 12),
        ("Thu, 29 Oct 2026 12:01:00 GMT", 60),
        ("Wed, 28 Oct 2026 12:00:00 GMT", 0),
    ],
)
def test_retry_after_seconds_and_dates(value: str, seconds: int) -> None:
    assert retry_after_datetime(value, NOW) == NOW + datetime.timedelta(seconds=seconds)


@pytest.mark.parametrize("value", [None, "", "bad", "-1", "1.5", "+2", "9" * 100])
def test_invalid_retry_after_is_ignored(value: Optional[str]) -> None:
    assert retry_after_datetime(value, NOW) is None


@pytest.mark.parametrize(
    "payload,valid",
    [
        (
            {
                "suggestedWindow": {
                    "start": "2026-10-29T12:00:00Z",
                    "end": "2026-10-30T12:00:00Z",
                },
                "explanationURL": "https://ca.example/renew",
            },
            True,
        ),
        ({}, False),
        (None, False),
        ([], False),
        ({"suggestedWindow": {"start": "bad", "end": "bad"}}, False),
        (
            {
                "suggestedWindow": {
                    "start": "2026-10-30T12:00:00Z",
                    "end": "2026-10-29T12:00:00Z",
                }
            },
            False,
        ),
    ],
)
def test_ari_records_valid_window_or_preserves_failed_payload(
    payload: JSONValue, valid: bool
) -> None:
    context = SimpleNamespace(timestamp=NOW, dbSession=Mock())
    result = {"status_code": 200, "payload": payload, "headers": {"Retry-After": "60"}}
    record = create__AriCheck(
        cast("ApiContext", context),
        cast(X509Certificate, SimpleNamespace(id=1)),
        cast(AriCheckResult, result),
    )
    assert record.ari_check_status is valid
    assert record.timestamp_retry_after == NOW + datetime.timedelta(seconds=60)
    if valid:
        assert record.explanation_url == "https://ca.example/renew"
        assert record.suggested_window_start is not None
        assert record.suggested_window_end is not None
        assert record.suggested_window_start < record.suggested_window_end
    else:
        assert record.raw_response is not None


def test_ari_error_keeps_http_date_retry_hint() -> None:
    context = SimpleNamespace(timestamp=NOW, dbSession=Mock())
    record = create__AriCheck(
        cast("ApiContext", context),
        cast(X509Certificate, SimpleNamespace(id=1)),
        cast(
            AriCheckResult,
            {
                "status_code": 503,
                "payload": {"detail": "unavailable"},
                "headers": {"Retry-After": "Thu, 29 Oct 2026 12:01:00 GMT"},
            },
        ),
    )
    assert record.ari_check_status is False
    assert record.timestamp_retry_after == NOW + datetime.timedelta(seconds=60)


@pytest.fixture
def polling(monkeypatch: pytest.MonkeyPatch) -> Tuple[AuthenticatedUser, PollingClock]:
    class Clock:
        current: float = 0.0
        delays: List[float] = []

        def monotonic(self) -> float:
            return self.current

        def sleep(self, delay: float) -> None:
            self.delays.append(delay)
            self.current += delay

    clock = Clock()
    clock.delays = []
    monkeypatch.setattr(acme_v2, "time", clock)
    monkeypatch.setattr(acme_v2, "SECONDS_POLLING_TIMEOUT", 10)
    user = object.__new__(acme_v2.AuthenticatedUser)
    setattr(user, "_send_signed_request", Mock())
    return user, clock


@pytest.mark.parametrize("hint,delay", [("5", 5), ("bad", 2)])
def test_polling_honors_retry_hint_or_default(
    polling: Tuple[AuthenticatedUser, PollingClock], hint: str, delay: float
) -> None:
    user, clock = polling
    cast(Mock, user._send_signed_request).side_effect = [
        (200, {"status": "pending"}, {"Retry-After": hint}),
        (200, {"status": "valid"}, {}),
    ]
    assert user._poll_until_not(
        "order", "https://ca.example/order", ["pending"], "test"
    ) == {"status": "valid"}
    assert clock.delays == [1, delay]


def test_polling_does_not_sleep_past_deadline_or_send_extra_request(
    polling: Tuple[AuthenticatedUser, PollingClock],
) -> None:
    user, clock = polling
    cast(Mock, user._send_signed_request).return_value = (
        200,
        {"status": "pending"},
        {"Retry-After": "300"},
    )
    with pytest.raises(errors.AcmePollingTooLong):
        user._poll_until_not("order", "https://ca.example/order", ["pending"], "test")
    assert clock.current == 10
    assert cast(Mock, user._send_signed_request).call_count == 1


@pytest.mark.parametrize("payload", [None, [], {}, {"status": None}])
def test_polling_malformed_response_is_communication_error(
    polling: Tuple[AuthenticatedUser, PollingClock], payload: JSONValue
) -> None:
    user, _ = polling
    cast(Mock, user._send_signed_request).return_value = (200, payload, {})
    with pytest.raises(errors.AcmeCommunicationError):
        user._poll_until_not("order", "https://ca.example/order", ["pending"], "test")


def test_late_terminal_poll_response_still_exceeds_budget(
    polling: Tuple[AuthenticatedUser, PollingClock],
) -> None:
    user, clock = polling

    def slow_response(
        *args: object, **kwargs: object
    ) -> Tuple[int, Dict[str, str], Dict[str, str]]:
        clock.current += 11
        return 200, {"status": "valid"}, {}

    cast(Mock, user._send_signed_request).side_effect = slow_response
    with pytest.raises(errors.AcmePollingTooLong):
        user._poll_until_not("order", "https://ca.example/order", ["pending"], "test")


@pytest.mark.parametrize(
    "end,explanation", [("2026-10-29T12:00:00Z", None), ("2026-10-30T12:00:00Z", {})]
)
def test_ari_rejects_zero_window_and_nonstring_explanation(
    end: str, explanation: JSONValue
) -> None:
    result = {
        "status_code": 200,
        "payload": {
            "suggestedWindow": {"start": "2026-10-29T12:00:00Z", "end": end},
            "explanationURL": explanation,
        },
        "headers": {},
    }
    record = create__AriCheck(
        cast("ApiContext", SimpleNamespace(timestamp=NOW, dbSession=Mock())),
        cast(X509Certificate, SimpleNamespace(id=1)),
        cast(AriCheckResult, result),
    )
    assert record.ari_check_status is False
    assert record.raw_response
