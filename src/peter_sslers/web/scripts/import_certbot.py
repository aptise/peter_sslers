# stdlib
import datetime
import os
import os.path
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
from ...lib.compat import certbot as compat_certbot
from ...lib.config_utils import ApplicationSettings
from ...lib.utils import ApiContext
from ...model.meta import Base

# ==============================================================================

# TESTING:
# import_certbot example_development.ini dir=/Volumes/Development/webserver/environments/certbot-persistent/etc/letsencrypt


def usage(argv):
    cmd = os.path.basename(argv[0])
    print(
        "usage: %s <config_uri> [dir=/etc/letsencrypt]\n"
        '(example: "%s example_development.ini")' % (cmd, cmd)
    )
    sys.exit(1)


def main(argv=sys.argv):
    if len(argv) < 2:
        usage(argv)
    config_uri = argv[1]
    options = parse_vars(argv[2:])
    certbot_dir = options.get("dir", "/etc/letsencrypt")
    compat_certbot.validate_certbot_dir(certbot_dir)

    setup_logging(config_uri)

    settings = get_appsettings(config_uri, options=options)

    engine = get_engine(settings)
    Base.metadata.create_all(engine)
    session_factory = get_session_factory(engine)

    app_settings = ApplicationSettings(config_uri)
    app_settings.from_settings_dict(settings)

    with transaction.manager:
        dbSession = get_tm_session(None, session_factory, transaction.manager)

        ctx = ApiContext(
            timestamp=datetime.datetime.now(datetime.UTC),
            dbSession=dbSession,
            request=None,
            config_uri=config_uri,
        )

        # load the db providers
        dbAcmeServers = lib_db.get.get__AcmeServers__paginated(ctx)
        providersMapping: compat_certbot.TYPE_MAPPING_AcmeServer = {
            i.server: i for i in dbAcmeServers
        }

        compat_certbot.import_certbot(
            ctx,
            certbot_dir,
            providersMapping,
        )

    transaction.commit()
