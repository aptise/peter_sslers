from peter_sslers.lib.config_utils import ApplicationSettings


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
