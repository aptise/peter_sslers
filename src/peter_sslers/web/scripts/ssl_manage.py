# stdlib
import os
import pprint
import sys
from typing import Callable

# pypi
from pyramid.paster import get_app
from pyramid.request import Request
import pyramid.scripting
from pyramid.scripts.common import parse_vars
from webob.multidict import MultiDict

# local
from ..lib import formhandling
from ..lib.forms import Form_AcmeAccount_new__auth
from ..lib.forms import Form_AcmeDnsServer_new
from ..views_admin import acme_account as v_acme_account
from ..views_admin import acme_dns_server as v_acme_dns_server
from ..views_admin import enrollment_factory as v_enrollment_factory
from ...lib import db as lib_db  # noqa: F401

# from ..lib.forms import Form_EnrollmentFactory_edit_new

# ==============================================================================

COMMANDS = {
    "acme-account": {
        "list",
        "new",
    },
    "acme-dns-server": {
        "list",
        "new",
    },
    "acme-server": {
        "list",
    },
    "enrollment-factory": {
        "list",
        "new",
    },
}


def usage(argv):
    cmd = os.path.basename(argv[0])
    print(
        "usage: %s <config_uri> <command> <subcommand> [var=value]\n"
        '(example: "%s conf/example_development.ini")' % (cmd, cmd)
    )
    print("valid commands:")
    pprint.pprint(COMMANDS)
    sys.exit(1)


def main(argv=sys.argv):
    if len(argv) < 4:
        usage(argv)
    config_uri = argv[1]
    command = argv[2]
    subcommand = argv[3]
    options = parse_vars(argv[4:])

    if command not in COMMANDS:
        print("`%s` is not a valid command" % command)
        exit()
    if subcommand not in COMMANDS[command]:
        print("`%s` is not a valid subcommand for `%s`" % (subcommand, command))
        exit()

    # don't use this, as we need a real pyramid request
    # ctx = new_scripts_setup(config_uri, options=options)

    app = get_app(config_uri, options=options)
    request = Request.blank("/", POST=MultiDict(**options))
    with pyramid.scripting.prepare(registry=app.app.registry, request=request) as env:
        _request = env["request"]
        assert request == _request

        # generic function
        def _list_items(f_paginated: Callable):
            dbItems = f_paginated(request.api_context)
            for _dbItem in dbItems:
                print("-----")
                pprint.pprint(_dbItem.as_json)

        # !!!: distpatch[acme-account]
        if command == "acme-account":
            if subcommand == "list":
                print("ACME Accounts:")
                _list_items(lib_db.get.get__AcmeAccount__paginated)
            elif subcommand == "new":
                if "help" in options:
                    pprint.pprint(Form_AcmeAccount_new__auth.fields)
                    exit()
                try:
                    _dbAcmeAccount, _is_created = v_acme_account.submit__new_auth(
                        request,
                        acknowledge_transaction_commits=True,
                    )
                    print("success")
                    print(_dbAcmeAccount.as_json)
                    exit()
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    pprint.pprint(exc.formStash.errors)
                    exit()
        # !!!: distpatch[acme-dns-server]
        elif command == "acme-dns-server":
            if subcommand == "list":
                print("acme-dns Servers:")
                _list_items(lib_db.get.get__AcmeDnsServer__paginated)
            elif subcommand == "new":
                if "help" in options:
                    pprint.pprint(Form_AcmeDnsServer_new.fields)
                    exit()
                try:
                    _dbAcmeDnsServer, _is_created = v_acme_dns_server.submit__new(
                        request,
                        acknowledge_transaction_commits=True,
                    )
                    print("success")
                    print(_dbAcmeDnsServer.as_json)
                    exit()
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    pprint.pprint(exc.formStash.errors)
                    exit()
        # !!!: distpatch[acme-server]
        elif command == "acme-server":
            if subcommand == "list":
                print("ACME Servers:")
                _list_items(lib_db.get.get__AcmeServer__paginated)
        # !!!: distpatch[enrollment-factory]
        elif command == "enrollment-factory":
            if subcommand == "list":
                print("Enrollment Factories:")
                _list_items(lib_db.get.get__EnrollmentFactory__paginated)
            elif subcommand == "new":
                try:
                    _dbEnrollmentFactory = v_enrollment_factory.submit__new(
                        request,
                        acknowledge_transaction_commits=True,
                    )
                    print("success")
                    print(_dbEnrollmentFactory.as_json)
                    exit()
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    pprint.pprint(exc.formStash.errors)
                    exit()

    exit()
