from types import SimpleNamespace

import pytest

from peter_sslers.lib.config_utils import ApplicationSettings
from peter_sslers.lib.utils_redis import redis_timeouts_from_registry


def test_redis_connection_and_ttl_defaults_are_individual_settings():
    settings = ApplicationSettings()
    for key in (
        "redis.url",
        "redis.timeout.cert",
        "redis.timeout.certcachain",
        "redis.timeout.domain",
        "redis.timeout.pkey",
    ):
        assert key in settings
        assert settings[key] is None


@pytest.mark.parametrize("suffix", ["cert", "certcachain", "domain", "pkey"])
def test_configured_cache_ttl_reaches_runtime_settings(tmp_path, suffix):
    key = f"redis.timeout.{suffix}"
    settings = ApplicationSettings()
    settings.from_settings_dict({"data_dir": str(tmp_path), key: "60"})
    assert settings[key] == 60
    request = SimpleNamespace(api_context=SimpleNamespace(application_settings=settings))
    assert redis_timeouts_from_registry(request)[suffix] == 60
    # Settings normalization may be invoked more than once.
    settings.from_settings_dict({"data_dir": str(tmp_path), key: settings[key]})
    assert settings[key] == 60


@pytest.mark.parametrize("value", ["0", "-1", "invalid"])
@pytest.mark.parametrize("suffix", ["cert", "certcachain", "domain", "pkey"])
def test_invalid_cache_ttl_fails_at_configuration(tmp_path, suffix, value):
    with pytest.raises(ValueError):
        ApplicationSettings().from_settings_dict({
            "data_dir": str(tmp_path), f"redis.timeout.{suffix}": value,
        })


def test_numeric_nginx_timeout_is_accepted(tmp_path):
    settings = ApplicationSettings()
    settings.from_settings_dict({"data_dir": str(tmp_path), "nginx.timeout": 3})
    assert settings["nginx.timeout"] == 3
