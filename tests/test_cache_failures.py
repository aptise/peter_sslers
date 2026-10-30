from __future__ import annotations

from types import SimpleNamespace
from typing import Union
from typing import cast
from unittest.mock import Mock

import pytest
from pyramid.request import Request
from redis.exceptions import ConnectionError

from peter_sslers.lib import utils_redis
from peter_sslers.model.objects import Domain


@pytest.mark.parametrize("style", ["1", "2"])
@pytest.mark.parametrize(
    "failure", [ConnectionError("cache unavailable"), ValueError("no certificate")]
)
def test_on_demand_cache_failures_are_nonfatal_for_both_styles(
    monkeypatch: pytest.MonkeyPatch, style: str, failure: Union[Exception, Mock]
) -> None:
    request = SimpleNamespace(
        api_context=SimpleNamespace(
            application_settings={
                "enable_redis": True,
                "redis.prime_style": style,
            }
        )
    )
    monkeypatch.setattr(utils_redis, "redis_connection_from_registry", Mock())
    monkeypatch.setattr(
        utils_redis, "redis_timeouts_from_registry", Mock(return_value={})
    )
    writer = (
        "redis_prime_logic__style_1_Domain"
        if style == "1"
        else "redis_prime_logic__style_2_domain"
    )
    monkeypatch.setattr(utils_redis, writer, Mock(side_effect=failure))
    with pytest.warns(UserWarning, match=str(failure)):
        assert (
            utils_redis.prime_redis_domain(
                cast(Request, request), cast(Domain, object())
            )
            is False
        )


@pytest.mark.parametrize("style", ["1", "2"])
def test_programming_errors_are_not_swallowed(
    monkeypatch: pytest.MonkeyPatch, style: str
) -> None:
    request = SimpleNamespace(
        api_context=SimpleNamespace(
            application_settings={
                "enable_redis": True,
                "redis.prime_style": style,
            }
        )
    )
    monkeypatch.setattr(utils_redis, "redis_connection_from_registry", Mock())
    monkeypatch.setattr(
        utils_redis, "redis_timeouts_from_registry", Mock(return_value={})
    )
    writer = (
        "redis_prime_logic__style_1_Domain"
        if style == "1"
        else "redis_prime_logic__style_2_domain"
    )
    monkeypatch.setattr(utils_redis, writer, Mock(side_effect=TypeError("bad payload")))
    with pytest.raises(TypeError, match="bad payload"):
        utils_redis.prime_redis_domain(cast(Request, request), cast(Domain, object()))


def test_inactive_preferred_certificate_uses_active_fallback() -> None:
    single = SimpleNamespace(is_active=True)
    domain = SimpleNamespace(
        domain_name="example.com",
        x509_certificate_id__latest_multi=1,
        x509_certificate_id__latest_single=2,
        x509_certificate__latest_multi=SimpleNamespace(is_active=False),
        x509_certificate__latest_single=single,
    )
    assert utils_redis._domain_certificate(cast(Domain, domain)) is single
    single.is_active = False
    with pytest.raises(ValueError, match="active certificate"):
        utils_redis._domain_certificate(cast(Domain, domain))
