from . import acme_v2
from . import cert_utils
from ..model import objects as model_objects
from ..model import utils as model_utils


# ------------------------------------------------------------------------------


class ApplicationSettings(dict):
    def __init__(self):
        for _opt in (
            "admin_prefix",
            "api_host",
            "certificate_authorities_enable",
            "certificate_authority_directory",
            "certificate_authority_protocol",
            "certificate_authority_testing",
            "certificate_authority",
            "cleanup_pending_authorizations",
            "enable_acme_flow",
            "enable_views_admin",
            "enable_views_public",
            "enable_nginx",
            "enable_redis",
            "exception_redirect",
            "expiring_days",
            "nginx.reset_path",
            "nginx.servers_pool_allow_invalid",
            "nginx.servers_pool",
            "nginx.status_path",
            "nginx.timeout",
            "nginx.userpass",
            "openssl_path_conf",
            "openssl_path",
            "queue_domains_max_per_cert",
            "queue_domains_min_per_cert",
            "redis.prime_style",
            "redis.url",
            "redis.timeout.cacert"
            "redis.timeout.cert"
            "redis.timeout.pkey"
            "redis.timeout.domain"
            "requests.disable_ssl_warning",
        ):
            self[_opt] = None

    def from_settings_dict(self, settings):
        """
        * parses a `settings` dict (which Pyramid would natively have in `main`)
        * invokes `self.validate()`
        """

        # do this before setting routes!
        admin_prefix = settings.get("admin_prefix", None)
        if admin_prefix is None:
            self["admin_prefix"] = "/.well-known/admin"

        # update the module data based on settings
        if "openssl_path" in settings:
            cert_utils.openssl_path = self["openssl_path"] = settings["openssl_path"]
        if "openssl_path_conf" in settings:
            cert_utils.openssl_path_conf = self["openssl_path_conf"] = settings[
                "openssl_path_conf"
            ]

        # should we cleanup challenges
        self["cleanup_pending_authorizations"] = set_bool_setting(
            settings, "cleanup_pending_authorizations", default=True
        )

        # will we redirect on error?
        self["exception_redirect"] = set_bool_setting(settings, "exception_redirect")

        # this is an int
        self["expiring_days"] = set_int_setting(settings, "expiring_days", default=30)

        # enable/disable the acme-flow system
        self["enable_acme_flow"] = set_bool_setting(settings, "enable_acme_flow")

        # Queue Domains Config
        self["queue_domains_max_per_cert"] = set_int_setting(
            settings, "queue_domains_max_per_cert", default=100
        )
        self["queue_domains_min_per_cert"] = set_int_setting(
            settings, "queue_domains_min_per_cert", default=1
        )

        # redis
        self["enable_redis"] = set_bool_setting(settings, "enable_redis")
        if self["enable_redis"]:
            # try to load, otherwise error out
            import redis  # noqa

            if "redis.url" not in settings:
                raise ValueError("No `redis.url` is configured")

            if "redis.prime_style" not in settings:
                raise ValueError("No `redis.prime_style` is configured")

            self["redis.url"] = settings["redis.url"]
            self["redis.prime_style"] = settings["redis.prime_style"]

        # disable the ssl warning from requests?
        self["requests.disable_ssl_warning"] = set_bool_setting(
            settings, "requests.disable_ssl_warning"
        )
        if self["requests.disable_ssl_warning"]:
            import requests.packages.urllib3

            requests.packages.urllib3.disable_warnings()

        self["enable_nginx"] = set_bool_setting(settings, "enable_nginx")
        self["nginx.reset_path"] = (
            settings.get("nginx.reset_path")
            or "/.peter_sslers/nginx/shared_cache/expire"
        )
        self["nginx.status_path"] = (
            settings.get("nginx.status_path")
            or "/.peter_sslers/nginx/shared_cache/status"
        )
        self["nginx.userpass"] = settings.get("nginx.userpass")
        self["nginx.timeout"] = settings.get("nginx.timeout")
        if (self["nginx.timeout"] is None) or (self["nginx.timeout"].lower() == "none"):
            self["nginx.timeout"] = None
        else:
            self["nginx.timeout"] = set_int_setting(self, "nginx.timeout", default=1)
        self["nginx.servers_pool"] = settings.get("nginx.servers_pool")
        if self["nginx.servers_pool"] is not None:
            self["nginx.servers_pool"] = list(
                set([i.strip() for i in settings["nginx.servers_pool"].split(",")])
            )
            self["nginx.servers_pool_allow_invalid"] = set_bool_setting(
                settings, "nginx.servers_pool_allow_invalid"
            )

        # required, but validate later
        self["certificate_authority"] = settings.get("certificate_authority")

        self["certificate_authority_directory"] = settings.get(
            "certificate_authority_directory"
        )
        self["certificate_authority_protocol"] = settings.get(
            "certificate_authority_protocol"
        )

        self["certificate_authority_testing"] = set_bool_setting(
            settings, "certificate_authority_testing"
        )
        if self["certificate_authority_testing"]:
            acme_v2.TESTING_ENVIRONMENT = True
            model_objects.TESTING_ENVIRONMENT = True

        self["enable_views_admin"] = set_bool_setting(settings, "enable_views_admin")
        self["enable_views_public"] = set_bool_setting(settings, "enable_views_public")

        self["certificate_authorities_enable"] = [
            ca
            for ca in [
                i.strip()
                for i in settings.get("certificate_authorities_enable", "").split(",")
            ]
            if ca
        ]

        # let's try to validate it!
        self.validate()

    def validate(self):
        """
        Validates the settings.
        """
        if self["queue_domains_max_per_cert"] > 100:
            raise ValueError("The absolute max for `queue_domains_max_per_cert` is 100")
        if self["queue_domains_min_per_cert"] < 1:
            raise ValueError("The absolute min for `queue_domains_min_per_cert` is 1")
        _redis_prime_style = self.get("redis.prime_style")
        if _redis_prime_style and _redis_prime_style not in ("1", "2"):
            raise ValueError("`redis.prime_style` must be one of: (`1`, `2`)")

        ca_selected = self["certificate_authority"]
        if not ca_selected:
            raise ValueError("No `certificate_authority` selected")

        ca_protocol = self["certificate_authority_protocol"]
        if ca_protocol != "acme-v2":
            raise ValueError("invalid `certificate_authority_protocol` selected")


# ------------------------------------------------------------------------------


def set_bool_setting(settings, key, default=False):
    """
    originally designed to modify Pyramid's '`config.registry.settings` in-place
    modify's a setting in-place an returns it.
    """
    _bool = None
    if key in settings:
        if settings[key].lower() in ("1", "true"):
            _bool = True
        elif settings[key].lower() in ("0", "false"):
            _bool = False
    if _bool is None:
        _bool = default
    settings[key] = _bool
    return _bool


def set_int_setting(settings, key, default=None):
    """
    originally designed to modify Pyramid's '`config.registry.settings` in-place
    modify's a setting in-place an returns it.
    """
    value = default
    if key in settings:
        value = int(settings[key])
    else:
        value = int(default)
    settings[key] = value
    return value


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = (
    "set_bool_setting",
    "set_int_setting",
    "ApplicationSettings",
)
