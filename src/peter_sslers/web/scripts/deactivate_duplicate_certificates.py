from . import _disable_warnings  # noqa: F401

# stdlib
import os  # noqa: I100
import os.path
import sys

# pypi
from pyramid.scripts.common import parse_vars

# local
from ...lib import db as lib_db
from ...lib.utils import new_scripts_setup

# ==============================================================================


def usage(argv):
    cmd = os.path.basename(argv[0])
    print(
        "usage: %s <config_uri>\n"
        '(example: "%s conf/example_development.ini")' % (cmd, cmd)
    )
    sys.exit(1)


def main(argv=sys.argv):
    if len(argv) < 2:
        usage(argv)
    config_uri = argv[1]
    options = parse_vars(argv[2:])

    ctx = new_scripts_setup(config_uri, options=options)
    assert ctx.request

    items_paged = lib_db.get.get_CertificateSigneds_duplicatePairs__paginated(
        ctx,
        limit=None,
        offset=0,
    )

    for pair in items_paged:
        # the item can be deactivated earlier in the loop if there are multiples
        if pair[1].is_active:
            print("Deactiving CertificateSigned[%s]" % pair[1].id)
            event_status = (  # noqa: F841
                lib_db.update.update_CertificateSigned__unset_active(ctx, pair[1])
            )
    ctx.pyramid_transaction_commit()
