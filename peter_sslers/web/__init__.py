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
from ..lib.db import _setup
from ..lib.db import create
from ..lib.db import get
from ..lib.db import update
from ..lib.utils import ApiContext
from ..model import objects as model_objects
from ..model import utils as model_utils
from ..model import websafe as model_websafe
from ..lib.config_utils import set_bool_setting
from ..lib.config_utils import set_int_setting
from ..lib.config_utils import ApplicationSettings
from . import models


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def add_renderer_globals(event):
    """sticks the admin_prefix into the renderer's topline namespace"""
    event["admin_prefix"] = event["request"].registry.settings["app_settings"][
        "admin_prefix"
    ]
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
    _api_host = request.registry.settings["app_settings"].get("api_host")
    if _api_host:
        return _api_host
    _scheme = request.environ.get("scheme", "http")
    return "%s://%s" % (_scheme, request.environ["HTTP_HOST"])


def admin_url(request):
    """request method"""
    return request.api_host + request.registry.settings["app_settings"]["admin_prefix"]


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    config = Configurator(settings=settings)
    config.include("pyramid_mako")
    config.include("pyramid_formencode_classic")
    # config.add_static_view('static', 'static', cache_max_age=3600)

    # Parse settings
    app_settings = ApplicationSettings()
    app_settings.from_settings_dict(settings)
    app_settings.validate()
    config.registry.settings["app_settings"] = app_settings

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
    dbEngine = models.get_engine(settings)
    dbSession = None
    with transaction.manager:

        session_factory = models.get_session_factory(dbEngine)
        dbSession = models.get_tm_session(None, session_factory, transaction.manager)

        ctx = ApiContext(
            timestamp=datetime.datetime.utcnow(),
            dbSession=dbSession,
            dbSessionLogger=None,
            request=None,
        )

        dbAcmeAccountProvider = get.get__AcmeAccountProvider__by_name(
            ctx, app_settings["certificate_authority"]
        )
        if not dbAcmeAccountProvider:
            print("Attempting to enroll new `AcmeAccountProvider` from config >>>")
            dbAcmeAccountProvider = create.create__AcmeAccountProvider(
                ctx,
                name=app_settings["certificate_authority"],
                directory=app_settings["certificate_authority_directory"],
                protocol=app_settings["certificate_authority_protocol"],
            )
            print("<<< Enrolled new `AcmeAccountProvider` from config")

        if dbAcmeAccountProvider.protocol != "acme-v2":
            raise ValueError("`AcmeAccountProvider.protocol` is not `acme-v2`")

        if (
            dbAcmeAccountProvider.directory
            != app_settings["certificate_authority_directory"]
        ):
            raise ValueError(
                "`dbAcmeAccountProvider.directory` does not match `certificate_authority_directory`"
            )

        if not dbAcmeAccountProvider.is_default:
            update.update_AcmeAccountProvider__set_default(ctx, dbAcmeAccountProvider)

        dbAcmeAccountKey = get.get__AcmeAccountKey__GlobalDefault(ctx)
        if dbAcmeAccountKey and not dbAcmeAccountKey.acme_account_provider.is_default:
            dbAcmeAccountKey.is_global_default = False
            dbSession.flush()

    if dbSession:
        dbSession.close()
    dbEngine.dispose()  # toss the connection in-case of multi-processing

    # exit early
    return config.make_wsgi_app()
