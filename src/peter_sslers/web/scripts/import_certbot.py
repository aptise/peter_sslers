from . import _disable_warnings  # noqa: F401

# stdlib
import os  # noqa: I100
import os.path
import sys

# pypi
from pyramid.scripts.common import parse_vars

# local
from ...lib import db as lib_db
from ...lib.compat import certbot as compat_certbot
from ...lib.utils import new_scripts_setup

# ==============================================================================

# TESTING:
# import_certbot example_development.ini dir=/Volumes/Development/webserver/environments/certbot-persistent/etc/letsencrypt


def usage(argv):
    cmd = os.path.basename(argv[0])
    print(
        "usage: %s <config_uri> [dir=/etc/letsencrypt]\n"
        '(example: "%s conf/example_development.ini")' % (cmd, cmd)
    )
    sys.exit(1)


def main(argv=sys.argv):
    if len(argv) < 2:
        usage(argv)
    config_uri = argv[1]
    options = parse_vars(argv[2:])
    certbot_dir = options.get("dir", "/etc/letsencrypt")
    compat_certbot.validate_certbot_dir(certbot_dir)

    ctx = new_scripts_setup(config_uri, options=options)

    # load the db providers
    dbAcmeServers = lib_db.get.get__AcmeServer__paginated(ctx)
    providersMapping: compat_certbot.TYPE_MAPPING_AcmeServer = {
        i.server: i for i in dbAcmeServers
    }

    compat_certbot.import_certbot(
        ctx,
        certbot_dir,
        providersMapping,
    )

    ctx.pyramid_transaction_commit()
