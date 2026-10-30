from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from peter_sslers.web.views_admin import api


@pytest.mark.parametrize("style", ["1", "2"])
def test_bulk_cache_priming_visits_every_page_and_only_queries_active_keys(monkeypatch, style):
    settings = {
        "redis.prime_style": style, "redis.url": "redis://localhost/0",
        "redis.timeout.cert": 60, "redis.timeout.certcachain": 90,
        "redis.timeout.pkey": 45, "redis.timeout.domain": 30,
    }
    context = SimpleNamespace(
        _ensure_redis=Mock(), application_settings=settings,
        pyramid_transaction_commit=Mock(),
    )
    request = SimpleNamespace(api_context=context)
    cache = Mock()
    monkeypatch.setattr(api.utils_redis, "redis_connection_from_registry", Mock(return_value=cache))
    pages = {}
    for name in ("Domain", "PrivateKey", "X509CertificateTrustChain"):
        query = Mock(side_effect=[list(range(100)), [100]])
        pages[name] = query
        monkeypatch.setattr(api.lib_db.get, f"get__{name}__paginated", query)
    writers = {}
    for name in (
        "redis_prime_logic__style_1_PrivateKey",
        "redis_prime_logic__style_1_X509CertificateTrustChain",
        "redis_prime_logic__style_1_Domain", "redis_prime_logic__style_2_domain",
    ):
        writers[name] = Mock()
        monkeypatch.setattr(api.utils_redis, name, writers[name])
    event = Mock()
    monkeypatch.setattr(api.lib_db.logger, "log__OperationsEvent", Mock(return_value=event))
    returned_event, totals = api.actual__prime_redis(request, acknowledge_transaction_commits=True)
    assert returned_event is event
    assert totals["domain"] == totals["cert"] == 101
    assert [call.kwargs["offset"] for call in pages["Domain"].call_args_list] == [0, 100]
    if style == "1":
        assert totals["pkey"] == totals["certcachain"] == 101
        for call in pages["PrivateKey"].call_args_list:
            assert call.kwargs["active_usage_only"] is True
        assert [call.kwargs["offset"] for call in pages["PrivateKey"].call_args_list] == [0, 100]
    else:
        pages["PrivateKey"].assert_not_called()
        pages["X509CertificateTrustChain"].assert_not_called()
    writer = writers[f"redis_prime_logic__style_{style}_" + ("Domain" if style == "1" else "domain")]
    assert writer.call_count == 101
    assert writer.call_args.args[2] == {
        "cert": 60, "certcachain": 90, "pkey": 45, "domain": 30,
    }
    context.pyramid_transaction_commit.assert_called_once_with()
