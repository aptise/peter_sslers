# stdlib
import datetime
import logging
from typing import TYPE_CHECKING

# pypi
from pyramid.config import Configurator
from pyramid.events import BeforeRender
from pyramid.renderers import JSON
from pyramid.tweens import EXCVIEW
import transaction

# local
from . import models
from .lib.handler import admin_url
from .lib.handler import api_host
from .lib.handler import load_CertificateCAPreferences
from ..lib.config_utils import ApplicationSettings
from ..lib.config_utils import set_bool_setting
from ..lib.db import _setup
from ..lib.utils import ApiContext
from ..lib.utils import unurlify
from ..model import websafe as model_websafe

if TYPE_CHECKING:
    # from .utils import ApiContext
    # from ..model.objects import Domain
    from pyramid.request import Request


# ==============================================================================


def header_tween_factory(handler, registry):
    def header_tween(request):
        response = handler(request)
        response.headers["X-Peter-SSLers"] = "production"
        return response

    return header_tween


def add_renderer_globals(event):
    """sticks the admin_prefix into the renderer's topline namespace"""
    event["admin_prefix"] = event["request"].registry.settings["application_settings"][
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


def main(global_config, **settings):
    """This function returns a Pyramid WSGI application."""
    config = Configurator(settings=settings)
    config.add_tween(".header_tween_factory")
    config.include("pyramid_mako")
    config.include("pyramid_formencode_classic")
    # config.add_static_view('static', 'static', cache_max_age=3600)

    # custom datetime rendering
    json_renderer = JSON()

    def datetime_adapter(obj, request: "Request") -> str:
        return obj.isoformat()

    json_renderer.add_adapter(datetime.datetime, datetime_adapter)
    config.add_renderer("json", json_renderer)

    # Parse settings
    config_uri = settings.get("config_uri")
    if not config_uri:
        config_uri = global_config["__file__"] if global_config else None
    application_settings = ApplicationSettings(config_uri)
    application_settings.from_settings_dict(settings)
    config.registry.settings["application_settings"] = application_settings

    # let's extend the request too!
    config.add_request_method(
        lambda request: request.environ["HTTP_HOST"].split(":")[0],
        "active_domain_name",
        reify=True,
    )
    config.add_request_method(
        lambda request: request.api_context.application_settings.get(
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
        lambda request: ApiContext(
            dbSession=request.dbSession,
            request=request,
            config_uri=config_uri,
            application_settings=application_settings,
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
            dbSession=dbSession,
            request=None,
            config_uri=config_uri,
            application_settings=application_settings,
        )

        # this might do some heavy lifting, or nothing
        _setup.application_started(ctx, application_settings)

        # release anything
        del ctx

    if dbSession:
        dbSession.close()
    dbEngine.dispose()  # toss the connection in-case of multi-processing

    print(
        "PeterSSLers will be serving on:   "
        + config.registry.settings["admin_server"]
        + config.registry.settings["application_settings"]["admin_prefix"]
    )

    # exit early
    return config.make_wsgi_app()
