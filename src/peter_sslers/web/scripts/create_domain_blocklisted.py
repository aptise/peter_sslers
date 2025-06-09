from . import _disable_warnings  # noqa: F401

# stdlib
import os  # noqa: I100
import os.path
import sys

# pypi
import cert_utils
from pyramid.scripts.common import parse_vars

# local
from ...lib import db as lib_db
from ...lib.utils import new_scripts_setup

# ==============================================================================


def usage(argv):
    cmd = os.path.basename(argv[0])
    print(
        "usage: %s <config_uri>\n"
        '(example: "%s data_development/config.ini")' % (cmd, cmd)
    )
    sys.exit(1)


def main(argv=sys.argv):
    if len(argv) < 3:
        usage(argv)
    config_uri = argv[1]
    candidate = argv[2].strip()
    options = parse_vars(argv[3:])

    ctx = new_scripts_setup(config_uri, options=options)
    assert ctx.request

    if not cert_utils.utils.validate_domains(
        [candidate],
        allow_hostname=True,
        allow_ipv4=True,
        allow_ipv6=True,
        ipv6_require_compressed=True,
    ):
        raise ValueError("`%s` is not a valid hostname/ipv4/ipv6" % candidate)

    dbDomainBlocklisted, is_created = (
        lib_db.getcreate.getcreate__DomainBlocklisted__by_domainName(ctx, candidate)
    )
    ctx.pyramid_transaction_commit()

    print("Success.")
    if is_created:
        print("`%s` has been added to the blocklist." % candidate)
    else:
        print("`%s` is already on the blocklist." % candidate)
