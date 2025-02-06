# stdlib
import hashlib
import os
from typing import Dict
from typing import Optional
import uuid

# local
# from ..model import objects as model_objects
# from ..model import utils as model_utils

# ==============================================================================


def normalize_filepath(fpath: str) -> str:
    fpath = os.path.normpath(fpath)
    if fpath[-1] == "/":
        fpath = fpath[:-1]
    return fpath


class ApplicationSettings(dict):
    def __init__(
        self,
        config_uri: Optional[str] = None,
    ):
        """
        `config_url` might be empty in a test harness
        """
        for _opt in (
            "acme_dns_support",
            "admin_prefix",
            "api_host",
            "block_competing_challenges",
            "cleanup_pending_authorizations",
            "data_dir",
            "enable_nginx",
            "enable_redis",
            "enable_views_admin",
            "enable_views_public",
            "exception_redirect",
            "expiring_days",
            "nginx.ca_bundle_pem",
            "nginx.reset_path",
            "nginx.servers_pool_allow_invalid",
            "nginx.servers_pool",
            "nginx.status_path",
            "nginx.timeout",
            "nginx.userpass",
            "redis.prime_style",
            "redis.timeout.cert"
            "redis.timeout.certcachain"
            "redis.timeout.domain"
            "redis.timeout.pkey"
            "redis.url",
            "requests.disable_ssl_warning",
            # config_uri data
            "config_uri",
            "config_uri-path",
            "config_uri-contents",
        ):
            self[_opt] = None

        for _opt in ("precheck_acme_challenges",):
            self[_opt] = []

        if config_uri:
            self["config_uri"] = config_uri
            _hash = hashlib.md5(config_uri.encode()).hexdigest()
            self["config_uri-path"] = _hash
            with open(config_uri, "rb") as f:
                _contents = f.read()
                _hash = hashlib.md5(_contents).hexdigest()
                self["config_uri-contents"] = _hash
        mac = uuid.getnode()
        self["mac_uuid"] = str(uuid.UUID(int=mac))

    def from_settings_dict(self, settings: Dict) -> None:
        """
        * parses a `settings` dict (which Pyramid would natively have in `main`)
        * invokes `self.validate()`
        """

        # do this before setting routes!
        admin_prefix = settings.get("admin_prefix", None)
        if admin_prefix is None:
            self["admin_prefix"] = "/.well-known/peter_sslers"

        #
        if "acme_dns_support" in settings:
            if settings["acme_dns_support"] not in ("basic", "experimental"):
                settings["acme_dns_support"] = "basic"
        else:
            settings["acme_dns_support"] = "basic"

        # should we cleanup challenges
        self["cleanup_pending_authorizations"] = set_bool_setting(
            settings, "cleanup_pending_authorizations", default=True
        )

        data_dir = settings.get("data_dir", None)
        if data_dir is None:
            raise ValueError("`data_dir` is a required setting")
        data_dir = normalize_filepath(data_dir)
        if not os.path.exists(data_dir):
            os.mkdir(data_dir)
        self["data_dir"] = data_dir

        # will we redirect on error?
        self["exception_redirect"] = set_bool_setting(settings, "exception_redirect")

        # this is an int
        self["expiring_days"] = set_int_setting(settings, "expiring_days", default=30)

        # should challenges block?
        self["block_competing_challenges"] = set_bool_setting(
            settings, "block_competing_challenges", default=True
        )

        # redis
        self["enable_redis"] = set_bool_setting(settings, "enable_redis")
        if self["enable_redis"]:
            # try to load, otherwise error out
            import redis  # noqa: F401

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

        _ca_bundle_pem = settings.get("nginx.ca_bundle_pem")
        if _ca_bundle_pem:
            _ca_bundle_pem = normalize_filepath(_ca_bundle_pem)
            if not os.path.exists(_ca_bundle_pem):
                raise ValueError(
                    "`nginx.ca_bundle_pem=%s` does not exist" % _ca_bundle_pem
                )
            self["nginx.ca_bundle_pem"] = _ca_bundle_pem

        _precheck_acme_challenges = settings.get("precheck_acme_challenges")
        if _precheck_acme_challenges:
            _precheck_acme_challenges = [
                i.strip() for i in _precheck_acme_challenges.split(",")
            ]
        self["precheck_acme_challenges"] = _precheck_acme_challenges

        self["enable_views_admin"] = set_bool_setting(settings, "enable_views_admin")
        self["enable_views_public"] = set_bool_setting(settings, "enable_views_public")

        # let's try to validate it!
        self.validate()

    def validate(self):
        """
        Validates the settings.
        """

        _redis_prime_style = self.get("redis.prime_style")
        if _redis_prime_style and _redis_prime_style not in ("1", "2"):
            raise ValueError("`redis.prime_style` must be one of: (`1`, `2`)")


# ------------------------------------------------------------------------------


def set_bool_setting(
    settings: Dict,
    key: str,
    default: bool = False,
) -> bool:
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


def set_int_setting(
    settings: Dict,
    key: str,
    default: Optional[int] = None,
) -> Optional[int]:
    """
    originally designed to modify Pyramid's '`config.registry.settings` in-place
    modify's a setting in-place an returns it.
    """
    value = default
    if key in settings:
        _candidate = settings[key]
        if _candidate is not None:
            value = int(_candidate)
    else:
        if default is not None:
            value = int(default)
    settings[key] = value
    return value


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = (
    "set_bool_setting",
    "set_int_setting",
    "ApplicationSettings",
)
