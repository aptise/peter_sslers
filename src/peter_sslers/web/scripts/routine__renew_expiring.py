# stdlib
import os
import sys

# pypi
from pyramid.paster import get_appsettings
from pyramid.paster import setup_logging
from pyramid.scripts.common import parse_vars
import transaction

# local
from ..models import get_engine
from ..models import get_session_factory
from ..models import get_tm_session
from ...lib import db as lib_db
from ...lib.config_utils import ApplicationSettings
from ...lib.http import StopableWSGIServer
from ...lib.utils import ApiContext
from ...lib.utils import RequestCommandline
from ...model import utils as model_utils
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

    application_settings = ApplicationSettings(config_uri)
    application_settings.from_settings_dict(settings)

    engine = get_engine(settings)

    Base.metadata.create_all(engine)
    session_factory = get_session_factory(engine)

    # application_settings = ApplicationSettings(config_uri)
    # application_settings.from_settings_dict(settings)

    # dbSession = session_factory()
    dbSession = get_tm_session(None, session_factory, transaction.manager)

    ctx = ApiContext(
        dbSession=dbSession,
        request=RequestCommandline(
            dbSession, application_settings=application_settings
        ),
        config_uri=config_uri,
        application_settings=application_settings,
    )

    RENEWAL_RUN: str = "RenewExpiring[%s]" % ctx.timestamp

    expiring_certs = lib_db.get.get_CertificateSigneds_renew_now(ctx)

    if not expiring_certs:
        print("Nothing to renew")
        exit()

    wsgi_server = create_public_server(settings)
    for dbCertificateSigned in expiring_certs:
        if not dbCertificateSigned.acme_order:
            print("No RenewalConfiguration for: ", dbCertificateSigned.id)
        else:
            print(
                "Renewing...",
                dbCertificateSigned.id,
                "with RenewalConfiguration:",
                dbCertificateSigned.acme_order.renewal_configuration_id,
            )
            try:
                replaces_certificate_type = (
                    model_utils.CertificateType.to_CertificateType_Enum(
                        dbCertificateSigned.acme_order.certificate_type_id
                    )
                )
                dbAcmeOrderNew = lib_db.actions_acme.do__AcmeV2_AcmeOrder__new(
                    ctx,
                    dbRenewalConfiguration=dbCertificateSigned.acme_order.renewal_configuration,
                    processing_strategy="process_single",
                    acme_order_type_id=model_utils.AcmeOrderType.RENEWAL_CONFIGURATION_AUTOMATED,
                    note=RENEWAL_RUN,
                    replaces=dbCertificateSigned.ari_identifier,
                    replaces_type=model_utils.ReplacesType_Enum.AUTOMATIC,
                    replaces_certificate_type=replaces_certificate_type,
                )
                print("Renewal Result", "AcmeOrder", dbAcmeOrderNew)
                print(
                    "Renewal Result",
                    "CertificateSigned",
                    dbAcmeOrderNew.certificate_signed_id,
                )
            except Exception as exc:
                print("Exception", exc, "when processing AcmeOrder")
                raise

    wsgi_server.shutdown()
    exit()
