"""
This file is used to test out migrations
it is checked into source, but not an entrypoint
this is a development tool only

example:

    python -m peter_sslers.web.scripts.workspace_migrations data_development/config.ini

"""

from . import _disable_warnings  # noqa: F401

# stdlib
import os  # noqa: I100
import sys
import time
from typing import TYPE_CHECKING

# pypi
from pyramid.paster import get_appsettings
from pyramid.scripts.common import parse_vars
from typing_extensions import Literal

# local
from ...lib import db as lib_db  # noqa: F401
from ...lib.utils import new_scripts_setup
from ...lib.utils import validate_config_uri

if TYPE_CHECKING:
    from ...lib.context import ApiContext

# from ...lib.config_utils import ApplicationSettings

# ==============================================================================


def usage(argv):
    cmd = os.path.basename(argv[0])
    print(
        "usage: %s <config_uri> [var=value]\n"
        '(example: "%s data_development/config.ini")' % (cmd, cmd)
    )
    print(
        "python -m peter_sslers.web.scripts.workspace_migrations data_development/config.ini"
    )
    sys.exit(1)


def create_mocked_RateLimited(ctx: "ApiContext") -> Literal[True]:
    print("create_mocked_RateLimited")

    dbAcmeAccount = lib_db.get.get__AcmeAccount__by_id(ctx, 1)
    dbDomain, _created = lib_db.getcreate.getcreate__Domain__by_domainName(
        ctx, "example.com"
    )
    dbUniqueFQDNSet, _created = (
        lib_db.getcreate.getcreate__UniqueFQDNSet__by_domainObjects(ctx, [dbDomain])
    )

    if TYPE_CHECKING:
        assert dbAcmeAccount
        assert dbDomain
        assert dbUniqueFQDNSet

    # this mocks BuyPass
    for i in range(0, 5):
        rl = lib_db.create.create__RateLimited(  # noqa: F841
            ctx=ctx,
            dbAcmeServer=dbAcmeAccount.acme_server,
            dbAcmeAccount=dbAcmeAccount,
            dbUniqueFQDNSet=dbUniqueFQDNSet,
            server_response_body={
                "type": "urn:ietf:params:acme:error:rateLimited",
                "title": "Too Many Requests",
                "status": 429,
                "detail": "Too many certificates issued already for requested domains",
                "instance": "/acme/new-order",
            },
            server_response_headers={},
        )
        time.sleep(1)
    ctx.pyramid_transaction_commit()
    return True


def search_RateLimited(ctx: "ApiContext") -> Literal[True]:
    print("search_RateLimited")

    dbAcmeAccount = lib_db.get.get__AcmeAccount__by_id(ctx, 1)
    dbDomain, _created = lib_db.getcreate.getcreate__Domain__by_domainName(
        ctx, "example.com"
    )
    dbUniqueFQDNSet, _created = (
        lib_db.getcreate.getcreate__UniqueFQDNSet__by_domainObjects(ctx, [dbDomain])
    )

    dbDomainAlt, _created = lib_db.getcreate.getcreate__Domain__by_domainName(
        ctx, "a.example.com"
    )
    dbUniqueFQDNSetAlt, _created = (
        lib_db.getcreate.getcreate__UniqueFQDNSet__by_domainObjects(
            ctx, [dbDomain, dbDomainAlt]
        )
    )

    ctx.pyramid_transaction_commit()

    if TYPE_CHECKING:
        assert dbAcmeAccount
        assert dbDomain
        assert dbUniqueFQDNSet
        assert dbDomainAlt
        assert dbUniqueFQDNSetAlt

    print(
        "get__RateLimited__by__acmeAccountId",
        lib_db.get.get__RateLimited__by__acmeAccountId(ctx, dbAcmeAccount.id),
    )
    print(
        "get__RateLimited__by__acmeServerId",
        lib_db.get.get__RateLimited__by__acmeServerId(
            ctx, dbAcmeAccount.acme_server_id
        ),
    )
    print(
        "get__RateLimited__by__acmeServerId(exclude_accounts=False)",
        lib_db.get.get__RateLimited__by__acmeServerId(
            ctx, dbAcmeAccount.acme_server_id, exclude_accounts=False
        ),
    )
    print(
        "get__RateLimited__by__acmeServerId_uniqueFqdnSetId(dbUniqueFQDNSet)",
        lib_db.get.get__RateLimited__by__acmeServerId_uniqueFqdnSetId(
            ctx, dbAcmeAccount.acme_server_id, dbUniqueFQDNSet.id
        ),
    )
    print(
        "get__RateLimited__by__acmeServerId_uniqueFqdnSetId(dbUniqueFQDNSetAlt)",
        lib_db.get.get__RateLimited__by__acmeServerId_uniqueFqdnSetId(
            ctx, dbAcmeAccount.acme_server_id, dbUniqueFQDNSetAlt.id
        ),
    )
    return True


def update_CertificateSigned_duration(ctx: "ApiContext") -> Literal[True]:
    print("update_CertificateSigned_duration")
    from ...model.objects import CertificateSigned

    cs = ctx.dbSession.query(CertificateSigned).all()
    for c in cs:
        _duration = c.timestamp_not_after - c.timestamp_not_before
        _duration_seconds = _duration.total_seconds()
        _duration_hours = int(_duration_seconds / 3600)
        c.duration_hours = _duration_hours
    ctx.pyramid_transaction_commit()
    return True


def main(argv=sys.argv):
    """
    python -m peter_sslers.web.scripts.workspace_migrations data_development/config.ini
    """
    if len(argv) < 2:
        usage(argv)
    config_uri = argv[1]
    config_uri = validate_config_uri(config_uri)
    options = parse_vars(argv[2:])

    settings = get_appsettings(config_uri, options=options)  # noqa: F841

    ctx = new_scripts_setup(config_uri, options=options)

    if False:
        update_CertificateSigned_duration(ctx)

    # create_mocked_RateLimited(ctx)
    search_RateLimited(ctx)

    exit()


main()
