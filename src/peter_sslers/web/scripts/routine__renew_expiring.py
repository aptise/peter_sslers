# stdlib
import datetime
import os
import sys

# pypi
from pyramid.paster import get_appsettings
from pyramid.paster import setup_logging
from pyramid.scripts.common import parse_vars

# local
from ..models import get_engine
from ..models import get_session_factory
from ...lib.config_utils import ApplicationSettings
from ...lib.http import StopableWSGIServer
from ...lib.utils import ApiContext
from ...model.objects import objects as model_objects
from ...model.meta import Base
from ...web import main as app_main

# from ...lib import db as lib_db
# from ...lib.config_utils import ApplicationSettings

# ==============================================================================


def usage(argv):
    cmd = os.path.basename(argv[0])
    print(
        "usage: %s <config_uri> [var=value]\n"
        '(example: "%s conf/example_development.ini")' % (cmd, cmd)
    )
    sys.exit(1)


def create_public_server(settings):
    """
    def tearDown(self):
        if self._testapp_wsgi is not None:
            self._testapp_wsgi.shutdown()
        AppTest.tearDown(self)
    """

    #
    # sanitize the settings
    #
    pryamid_bools = (
        "pyramid.debug_authorization"
        "pyramid.debug_notfound"
        "pyramid.debug_routematch"
    )
    for field in pryamid_bools:
        if field in settings:
            settings[field] = "false"
    if "pyramid.includes" in settings:
        settings["pyramid.includes"] = settings["pyramid.includes"].replace(
            "pyramid_debugtoolbar", ""
        )

    # ensure what the public can and can't see
    settings["enable_views_admin"] = "false"
    settings["enable_views_public"] = "true"

    app = app_main(global_config=None, **settings)
    app_wsgi = StopableWSGIServer.create(
        app,
        host="localhost",
        port=7202,
    )

    return app_wsgi


def main(argv=sys.argv):
    if len(argv) < 2:
        usage(argv)
    config_uri = argv[1]
    options = parse_vars(argv[2:])
    setup_logging(config_uri)

    settings = get_appsettings(config_uri, options=options)

    app_settings = ApplicationSettings(config_uri)
    app_settings.from_settings_dict(settings)

    engine = get_engine(settings)

    Base.metadata.create_all(engine)
    session_factory = get_session_factory(engine)

    # app_settings = ApplicationSettings(config_uri)
    # app_settings.from_settings_dict(settings)

    dbSession = session_factory()
    ctx = ApiContext(
        timestamp=datetime.datetime.now(datetime.timezone.utc),
        dbSession=dbSession,
        request=None,
        config_uri=config_uri,
        app_settings=app_settings,
    )

    expiring_certs = (
        ctx.dbSession.query(model_objects.CertificateSigned)
        .join(
            model_objects.AriCheck,
            model_objects.CertificateSigned.id
            == model_objects.AriCheck.certificate_signed_id,
        )
        .filter(
            model_objects.AriCheck.suggested_window_end < ctx.timestamp,
        )
        .all()
    )
    print(expiring_certs)

    if not expiring_certs:
        print("Nothing to renew")
        exit()

    wsgi_server = create_public_server(settings)
    for cert in expiring_certs:
        print("renewing...", cert)

    wsgi_server.shutdown()
    exit()
