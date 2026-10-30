from types import SimpleNamespace
from unittest.mock import Mock

from peter_sslers.lib.utils_redis import redis_default_connection


def test_cache_connection_is_reused_and_has_bounded_defaults():
    request = SimpleNamespace(registry=SimpleNamespace())
    factory = Mock()
    first = redis_default_connection(request, "redis://localhost/0", redis_client=factory)
    assert redis_default_connection(request, redis_client=factory) is first
    factory.from_url.assert_called_once_with(
        "redis://localhost/0", socket_connect_timeout=3.05, socket_timeout=10
    )
    factory.assert_not_called()


def test_explicit_cache_connection_timeouts_are_preserved():
    request = SimpleNamespace(registry=SimpleNamespace())
    factory = Mock()
    redis_default_connection(
        request, redis_client=factory, socket_connect_timeout=2, socket_timeout=4
    )
    factory.assert_called_once_with(socket_connect_timeout=2, socket_timeout=4)


def test_url_query_overrides_default_cache_connection_timeouts():
    request = SimpleNamespace(registry=SimpleNamespace())
    client = redis_default_connection(
        request, "redis://localhost/0?socket_connect_timeout=2&socket_timeout=4"
    )
    try:
        options = client.connection_pool.connection_kwargs
        assert options["socket_connect_timeout"] == 2
        assert options["socket_timeout"] == 4
    finally:
        client.close()
