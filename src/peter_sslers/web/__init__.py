# stdlib
import datetime
import logging

# pypi
from pyramid.config import Configurator
from pyramid.events import BeforeRender
from pyramid.renderers import JSON
from pyramid.tweens import EXCVIEW
import transaction

# from sqlalchemy import engine_from_config

# local
from . import models
from ..lib.config_utils import ApplicationSettings
from ..lib.config_utils import set_bool_setting
from ..lib.db import _setup
from ..lib.db import get
from ..lib.utils import ApiContext
from ..lib.utils import unurlify
from ..model import websafe as model_websafe

# from ..lib import acme_v2
# from ..lib import cert_utils
# from ..lib.config_utils import set_int_setting
# from ..lib.db import create
# from ..lib.db import update
# from ..model import objects as model_objects
# from ..model import utils as model_utils

# ==============================================================================


def header_tween_factory(handler, registry):
    def header_tween(request):
        response = handler(request)
        response.headers["X-Peter-SSLers"] = "production"
        return response

    return header_tween


def add_renderer_globals(event):
    """sticks the admin_prefix into the renderer's topline namespace"""
    event["admin_prefix"] = event["request"].registry.settings["app_settings"][
        "admin_prefix"
    ]
    event["admin_server"] = event["request"].admin_server
    event["model_websafe"] = model_websafe
    event["unurlify"] = unurlify


def db_log_cleanup__tween_factory(handler, registry):
    def db_log_cleanup__tween(request):
        try:
            if request.environ.get("paste.command_request", None):
                # turn off logging
                # logging.Logger.manager.loggerDict
                logging.basicConfig(level=logging.WARNING)
                for l1 in [
                    l0.strip()
                    for l0 in "peter_sslers, sqlalchemy, requests, sqlalchemy.engine.base.Engine".split(
                        ","
                    )
                ]:
                    logging.getLogger(l1).setLevel(logging.WARNING)
                    logging.getLogger(l1).propagate = False
            response = handler(request)
            return response
        except Exception as exc:  # noqa: F841
            raise

    return db_log_cleanup__tween


def api_host(request):
    """request method"""
    _api_host = request.registry.settings["app_settings"].get("api_host")
    if _api_host:
        return _api_host
    _scheme = request.environ.get("scheme", "http")
    return "%s://%s" % (_scheme, request.environ["HTTP_HOST"])


def admin_url(request):
    """request method"""
    return request.api_host + request.registry.settings["app_settings"]["admin_prefix"]


def load_CertificateCAPreferences(request):
    """
    loads `model.objects.CertificateCAPreferences` onto the request
    """
    dbCertificateCAPreferences = get.get__CertificateCAPreference__paginated(
        request.api_context
    )
    return dbCertificateCAPreferences


def main(global_config, **settings):
    """This function returns a Pyramid WSGI application."""
    config = Configurator(settings=settings)
    config.add_tween(".header_tween_factory")
    config.include("pyramid_mako")
    config.include("pyramid_formencode_classic")
    # config.add_static_view('static', 'static', cache_max_age=3600)

    # custom datetime rendering
    json_renderer = JSON()

    def datetime_adapter(obj, request):
        return obj.isoformat()

    json_renderer.add_adapter(datetime.datetime, datetime_adapter)
    config.add_renderer("json", json_renderer)

    # Parse settings
    config_uri = settings.get("config_uri")
    if not config_uri:
        config_uri = global_config["__file__"] if global_config else None
    app_settings = ApplicationSettings(config_uri)
    app_settings.from_settings_dict(settings)
    config.registry.settings["app_settings"] = app_settings

    # let's extend the request too!
    config.add_request_method(
        lambda request: request.environ["HTTP_HOST"].split(":")[0],
        "active_domain_name",
        reify=True,
    )
    config.add_request_method(
        lambda request: request.registry.settings["app_settings"].get(
            "admin_server", None
        )
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
        lambda request: datetime.datetime.now(datetime.timezone.utc),
        "a_timestamp",
        reify=True,
    )
    config.add_request_method(
        lambda request: ApiContext(
            timestamp=request.a_timestamp,
            dbSession=request.dbSession,
            request=request,
            config_uri=config_uri,
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
    config.add_request_method(
        load_CertificateCAPreferences, "dbCertificateCAPreferences", reify=True
    )

    # don't scan 'everything', only what is enabled
    # config.scan()

    config.add_tween(".db_log_cleanup__tween_factory", over=EXCVIEW)
    config.add_subscriber(add_renderer_globals, BeforeRender)

    # handle this before including the routes
    enable_views_admin = set_bool_setting(  # noqa: F841
        config.registry.settings, "enable_views_admin"
    )
    enable_views_public = set_bool_setting(  # noqa: F841
        config.registry.settings, "enable_views_public"
    )
    config.include(".routes")
    config.include(".models")
    config.scan(".views")  # shared views, currently just exception handling

    # after the models are included, setup the AcmeServer
    dbEngine = models.get_engine(settings)
    dbSession = None
    with transaction.manager:
        session_factory = models.get_session_factory(dbEngine)
        dbSession = models.get_tm_session(None, session_factory, transaction.manager)

        ctx = ApiContext(
            timestamp=datetime.datetime.now(datetime.timezone.utc),
            dbSession=dbSession,
            request=None,
            config_uri=config_uri,
        )

        # this will do the heavy lifting
        _setup.startup_AcmeServers(ctx, app_settings)

    if dbSession:
        dbSession.close()
    dbEngine.dispose()  # toss the connection in-case of multi-processing

    # exit early
    return config.make_wsgi_app()
