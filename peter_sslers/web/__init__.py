# stdlib
import logging
import datetime

# pyramid
from pyramid.config import Configurator
from pyramid.tweens import EXCVIEW
from pyramid.events import BeforeRender

# pypi
import transaction
from sqlalchemy import engine_from_config

# local
from ..lib import acme_v2
from ..lib import cert_utils
from ..lib.utils import ApiContext
from ..lib.utils import url_to_server
from ..model import objects as model_objects
from ..model import utils as model_utils
from ..model import websafe as model_websafe
from .lib.config_utils import set_bool_setting
from .lib.config_utils import set_int_setting
from . import models


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def add_renderer_globals(event):
    """sticks the admin_prefix into the renderer's topline namespace"""
    event["admin_prefix"] = event["request"].registry.settings["admin_prefix"]
    event["admin_server"] = event["request"].admin_server
    event["model_websafe"] = model_websafe


def db_log_cleanup__tween_factory(handler, registry):
    def db_log_cleanup__tween(request):
        try:
            if request.environ.get("paste.command_request", None):
                # turn off logging
                # logging.Logger.manager.loggerDict
                logging.basicConfig(level=logging.WARNING)
                for l in [
                    l.strip()
                    for l in "peter_sslers, sqlalchemy, requests, sqlalchemy.engine.base.Engine".split(
                        ","
                    )
                ]:
                    logging.getLogger(l).setLevel(logging.WARNING)
                    logging.getLogger(l).propagate = False
            response = handler(request)
            return response
        except Exception as exc:
            raise

    return db_log_cleanup__tween


def api_host(request):
    """request method"""
    _api_host = request.registry.settings.get("api_host")
    if _api_host:
        return _api_host
    _scheme = request.environ.get("scheme", "http")
    return "%s://%s" % (_scheme, request.environ["HTTP_HOST"])


def admin_url(request):
    """request method"""
    return request.api_host + request.registry.settings["admin_prefix"]


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    config = Configurator(settings=settings)
    config.include("pyramid_mako")
    config.include("pyramid_formencode_classic")
    # config.add_static_view('static', 'static', cache_max_age=3600)

    # Parse settings

    # do this before setting routes!
    admin_prefix = settings.get("admin_prefix", None)
    if admin_prefix is None:
        config.registry.settings["admin_prefix"] = "/.well-known/admin"

    # update the module data based on settings
    if "openssl_path" in settings:
        cert_utils.openssl_path = settings["openssl_path"]
    if "openssl_path_conf" in settings:
        cert_utils.openssl_path_conf = settings["openssl_path_conf"]

    # will we redirect on error?
    set_bool_setting(config.registry.settings, "exception_redirect")

    # this is an int
    set_int_setting(config.registry.settings, "expiring_days", default=30)

    # enable/disable the acme-flow system
    set_bool_setting(config.registry.settings, "enable_acme_flow")

    # Queue Domains Config
    queue_domains_max_per_cert = set_int_setting(
        config.registry.settings, "queue_domains_max_per_cert", default=100
    )
    if queue_domains_max_per_cert > 100:
        raise ValueError("The absolute max for `queue_domains_max_per_cert` is 100")
    queue_domains_min_per_cert = set_int_setting(
        config.registry.settings, "queue_domains_min_per_cert", default=1
    )
    if queue_domains_min_per_cert < 1:
        raise ValueError("The absolute min for `queue_domains_min_per_cert` is 1")
    queue_domains_use_weekly_key = set_bool_setting(
        config.registry.settings, "queue_domains_use_weekly_key"
    )
    #

    _enable_redis = set_bool_setting(config.registry.settings, "enable_redis")
    if _enable_redis:
        # try to load, otherwise error out
        import redis  # noqa

        if "redis.prime_style" not in settings:
            raise ValueError("No `redis.prime_style` is configured")
        if settings["redis.prime_style"] not in ("1", "2"):
            raise ValueError("No `redis.prime_style` must be one of: (`1`, `2`)")

    # disable the ssl warning from requests?
    _disable_ssl_warning = set_bool_setting(
        config.registry.settings, "requests.disable_ssl_warning"
    )
    if _disable_ssl_warning:
        import requests.packages.urllib3

        requests.packages.urllib3.disable_warnings()

    _enable_nginx = set_bool_setting(config.registry.settings, "enable_nginx")
    if "nginx.reset_path" not in config.registry.settings:
        config.registry.settings[
            "nginx.reset_path"
        ] = "/.peter_sslers/nginx/shared_cache/expire"
    if "nginx.status_path" not in config.registry.settings:
        config.registry.settings[
            "nginx.status_path"
        ] = "/.peter_sslers/nginx/shared_cache/status"
    if "nginx.userpass" not in config.registry.settings:
        config.registry.settings["nginx.userpass"] = None
    if "nginx.timeout" in config.registry.settings:
        if config.registry.settings["nginx.timeout"].lower() == "none":
            config.registry.settings["nginx.timeout"] = None
        else:
            set_int_setting(config.registry.settings, "nginx.timeout", default=1)
    if "nginx.servers_pool" in config.registry.settings:
        config.registry.settings["nginx.servers_pool"] = list(
            set(
                [
                    i.strip()
                    for i in config.registry.settings["nginx.servers_pool"].split(",")
                ]
            )
        )
        _enable_nginx = True
        set_bool_setting(config.registry.settings, "nginx.servers_pool_allow_invalid")
    config.registry.settings["enable_nginx"] = _enable_nginx

    # let's extend the request too!
    if acme_v2.TESTING_ENVIRONMENT:
        config.add_request_method(
            lambda request: "selfsigned-1.example.com",
            "active_domain_name",
            reify=True,
        )
    else:
        config.add_request_method(
            lambda request: request.environ["HTTP_HOST"].split(":")[0],
            "active_domain_name",
            reify=True,
        )
    config.add_request_method(
        lambda request: request.registry.settings.get("admin_server", None)
        or request.environ["HTTP_HOST"],
        "admin_server",
        reify=True,
    )

    config.add_request_method(
        lambda request: True if request.matched_route.name.endswith("|json") else False,
        "wants_json",
        reify=True,
    )

    config.add_request_method(
        lambda request: datetime.datetime.utcnow(), "a_timestamp", reify=True
    )
    config.add_request_method(
        lambda request: ApiContext(
            timestamp=request.a_timestamp,
            dbSession=request.dbSession,
            dbSessionLogger=request.dbSessionLogger,
            request=request,
        ),
        "api_context",
        reify=True,
    )
    config.add_request_method(
        lambda request: "<li>%s</li><li>Peter SSLers</li>" % request.active_domain_name,
        "breadcrumb_prefix",
        reify=True,
    )
    config.add_request_method(api_host, "api_host", reify=True)
    config.add_request_method(admin_url, "admin_url", reify=True)

    # don't scan 'everything', only what is enabled
    # config.scan()

    config.add_tween(".db_log_cleanup__tween_factory", over=EXCVIEW)
    config.add_subscriber(add_renderer_globals, BeforeRender)

    # handle this before including the routes
    enable_views_admin = set_bool_setting(
        config.registry.settings, "enable_views_admin"
    )
    enable_views_public = set_bool_setting(
        config.registry.settings, "enable_views_public"
    )
    config.include(".routes")
    config.include(".models")
    config.scan(".views")  # shared views, currently just exception handling


    # after the models are included, setup the AcmeAccountProvider

    ca_selected = settings.get("certificate_authority")
    if not ca_selected:
        raise ValueError("No `certificate_authority` selected")
    
    dbEngine = models.get_engine(settings)
    with transaction.manager:
    
        session_factory = models.get_session_factory(dbEngine)
        dbSession = models.get_tm_session(None, session_factory, transaction.manager)
        
        dbAcmeAccountProvider = dbSession.query(model_objects.AcmeAccountProvider)\
            .filter(model_objects.AcmeAccountProvider.name == ca_selected)\
            .first()
        if not dbAcmeAccountProvider:
            print("Attempting to enroll new `AcmeAccountProvider`")
            
            _directory = settings.get("certificate_authority_directory")
            if not _directory or (not _directory.startswith('http://') and not _directory.startswith('https://')):
                raise ValueError("invalid directory")
            
            _protocol = settings.get("certificate_authority_protocol")
            if _protocol != "acme-v2":
                raise ValueError("invalid protocol")
        
            # ok, try to build one...
            dbAcmeAccountProvider = model_objects.AcmeAccountProvider()
            dbAcmeAccountProvider.timestamp_created = datetime.datetime.utcnow()
            dbAcmeAccountProvider.name = ca_selected
            dbAcmeAccountProvider.directory = _directory
            dbAcmeAccountProvider.is_default = None  # this will be toggled in a moment
            dbAcmeAccountProvider.is_enabled = True
            dbAcmeAccountProvider.protocol = _protocol
            dbAcmeAccountProvider.server = url_to_server(_directory)
            dbSession.add(dbAcmeAccountProvider)
            dbSession.flush(objects=[dbAcmeAccountProvider, ])
            print ("Enrolled new `AcmeAccountProvider`")

        if dbAcmeAccountProvider.protocol != "acme-v2":
            raise ValueError("`AcmeAccountProvider.protocol` is not `acme-v2`")
        acme_v2.CERTIFICATE_AUTHORITY = dbAcmeAccountProvider.directory
        config.registry.settings["CERTIFICATE_AUTHORITY"] = dbAcmeAccountProvider.directory

        if "certificate_authority_testing" in settings:
            certificate_authority_testing = set_bool_setting(
                config.registry.settings, "certificate_authority_testing"
            )
            if certificate_authority_testing:
                acme_v2.TESTING_ENVIRONMENT = True
                model_objects.TESTING_ENVIRONMENT = True

        if "certificate_authority_agreement" in settings:
            acme_v2.CERTIFICATE_AUTHORITY_AGREEMENT = settings[
                "certificate_authority_agreement"
            ]

        if not dbAcmeAccountProvider.is_default:
            dbAcmeAccountProvider_default = dbSession.query(model_objects.AcmeAccountProvider)\
                .filter(model_objects.AcmeAccountProvider.is_default.op("IS")(True))\
                .first()
            if dbAcmeAccountProvider_default:
                dbAcmeAccountProvider_default.is_default = False
                dbSession.flush()

            dbAcmeAccountProvider.is_default = True
            dbSession.flush()


    dbEngine.dispose()  # toss the connection in-case of multi-processing

    # exit early
    return config.make_wsgi_app()
