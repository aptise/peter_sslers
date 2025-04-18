# stdlib
import os
import pprint
import sys
from typing import Callable
from typing import Optional
from typing import TYPE_CHECKING

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
from ..lib.forms import Form_RenewalConfig_new
from ..lib.forms import Form_RenewalConfig_new_enrollment
from ..views_admin import acme_account as v_acme_account
from ..views_admin import acme_dns_server as v_acme_dns_server
from ..views_admin import enrollment_factory as v_enrollment_factory
from ..views_admin import renewal_configuration as v_renewal_configuration
from ...lib import db as lib_db  # noqa: F401
from ...model import objects as model_objects

# from ..lib.forms import Form_EnrollmentFactory_edit_new

if TYPE_CHECKING:
    from ...model.objects import AcmeAccount
    from ...model.objects import AcmeDnsServer
    from ...model.objects import EnrollmentFactory
    from ...model.objects import RenewalConfiguration

# ==============================================================================

COMMANDS = {
    "acme-account": {
        "list",
        "new",
        "authenticate",
        "check",
    },
    "acme-dns-server": {
        "list",
        "new",
        "check",
    },
    "acme-server": {
        "list",
    },
    "enrollment-factory": {
        "list",
        "new",
    },
    "renewal-configuration": {
        "list",
        "new-enrollment",
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

        # generic functions
        def _list_items(f_paginated: Callable, is_extended=True):
            dbItems = f_paginated(request.api_context)
            for _dbItem in dbItems:
                print("-----")
                if is_extended:
                    if isinstance(_dbItem, model_objects.EnrollmentFactory):
                        pprint.pprint(_dbItem.as_json_docs)
                        continue
                    elif isinstance(_dbItem, model_objects.RenewalConfiguration):
                        pprint.pprint(_dbItem.as_json_docs)
                        continue
                pprint.pprint(_dbItem.as_json)

        # !!!: distpatch[acme-account]
        if command == "acme-account":
            _dbAcmeAccount: Optional["AcmeAccount"]
            # !!!: list
            if subcommand == "list":
                print("ACME Accounts:")
                _list_items(lib_db.get.get__AcmeAccount__paginated)
            # !!!: new
            elif subcommand == "new":
                if "help" in options:
                    pprint.pprint(Form_AcmeAccount_new__auth.fields)
                    exit()
                try:
                    _dbAcmeAccount, _is_created = v_acme_account.submit__new_auth(
                        request,
                        acknowledge_transaction_commits=True,
                    )
                    print("success", "[CREATED]" if _is_created else "")
                    print(_dbAcmeAccount.as_json)
                    exit()
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    pprint.pprint(exc.formStash.errors)
                    exit()
            # !!!: authenticate
            elif subcommand in (
                "authenticate",
                "check",
            ):
                if "help" in options:
                    print('%s id="{INT}' % subcommand)
                    exit()
                id_ = options["id"]
                _dbAcmeAccount = lib_db.get.get__AcmeAccount__by_id(
                    request.api_context, id_
                )
                if not _dbAcmeAccount:
                    print("invalid `AcmeAccount`")
                    exit()
                if subcommand == "authenticate":
                    _result, _err = v_acme_account.submit__authenticate(
                        request,
                        dbAcmeAccount=_dbAcmeAccount,
                        acknowledge_transaction_commits=True,
                    )
                elif subcommand == "check":
                    _result, _err = v_acme_account.submit__check(
                        request,
                        dbAcmeAccount=_dbAcmeAccount,
                        acknowledge_transaction_commits=True,
                    )
                if _result:
                    print("successful %s" % subcommand)
                    exit()
                print("error", _err)
                exit()

        # !!!: distpatch[acme-dns-server]
        elif command == "acme-dns-server":
            _dbAcmeDnsServer: Optional["AcmeDnsServer"]
            # !!!: list
            if subcommand == "list":
                print("acme-dns Servers:")
                _list_items(lib_db.get.get__AcmeDnsServer__paginated)
            # !!!: new
            elif subcommand == "new":
                if "help" in options:
                    pprint.pprint(Form_AcmeDnsServer_new.fields)
                    exit()
                try:
                    _dbAcmeDnsServer, _is_created = v_acme_dns_server.submit__new(
                        request,
                        acknowledge_transaction_commits=True,
                    )
                    print("success", "[CREATED]" if _is_created else "")
                    print(_dbAcmeDnsServer.as_json)
                    exit()
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    pprint.pprint(exc.formStash.errors)
                    exit()
            # !!!: check
            elif subcommand == "check":
                if "help" in options:
                    print('check id="{INT}')
                    exit()
                id_ = options["id"]
                _dbAcmeDnsServer = lib_db.get.get__AcmeDnsServer__by_id(
                    request.api_context, id_
                )
                if not _dbAcmeDnsServer:
                    print("invalid `AcmeDnsServer`")
                    exit()
                _result = v_acme_dns_server.submit__check(  # noqa: F841
                    request,
                    dbAcmeDnsServer=_dbAcmeDnsServer,
                )
                print("successful check")

        # !!!: distpatch[acme-server]
        elif command == "acme-server":
            # !!!: list
            if subcommand == "list":
                print("ACME Servers:")
                _list_items(lib_db.get.get__AcmeServer__paginated)

        # !!!: distpatch[enrollment-factory]
        elif command == "enrollment-factory":
            _dbEnrollmentFactory: Optional["EnrollmentFactory"]

            # !!!: list
            if subcommand == "list":
                print("Enrollment Factories:")
                _list_items(lib_db.get.get__EnrollmentFactory__paginated)
            # !!!: new
            elif subcommand == "new":
                try:
                    _dbEnrollmentFactory = v_enrollment_factory.submit__new(
                        request,
                        acknowledge_transaction_commits=True,
                    )
                    print(_dbEnrollmentFactory.as_json_docs)
                    exit()
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    pprint.pprint(exc.formStash.errors)
                    exit()

        # !!!: distpatch[renewal-configuration]
        elif command == "renewal-configuration":
            _dbRenewalConfiguration: "RenewalConfiguration"

            # !!!: list
            if subcommand == "list":
                print("Renewal Configurations:")
                _list_items(lib_db.get.get__RenewalConfiguration__paginated)
            # !!!: new-enrollment
            elif subcommand == "new":
                if "help" in options:
                    pprint.pprint(Form_RenewalConfig_new.fields)
                    exit()
                try:
                    _dbRenewalConfiguration, _is_duplicate = (
                        v_renewal_configuration.submit__new(
                            request,
                            acknowledge_transaction_commits=True,
                        )
                    )
                    print("success", "[DUPLICATE]" if _is_duplicate else "")
                    print(_dbRenewalConfiguration.as_json)
                    exit()
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    pprint.pprint(exc.formStash.errors)
                    exit()
            # !!!: new-enrollment
            elif subcommand == "new-enrollment":
                if "help" in options:
                    pprint.pprint(Form_RenewalConfig_new_enrollment.fields)
                    exit()
                enrollment_factory_id = options["enrollment_factory_id"]
                _dbEnrollmentFactory = lib_db.get.get__EnrollmentFactory__by_id(
                    request.api_context, enrollment_factory_id
                )
                if not _dbEnrollmentFactory:
                    print("invalid `EnrollmentFactory`")
                    exit()
                try:
                    _dbRenewalConfiguration, _is_duplicate = (
                        v_renewal_configuration.submit__new_enrollment(
                            request,
                            dbEnrollmentFactory=_dbEnrollmentFactory,
                            acknowledge_transaction_commits=True,
                        )
                    )
                    print("success", "[DUPLICATE]" if _is_duplicate else "")
                    print(_dbRenewalConfiguration.as_json)
                    exit()
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    pprint.pprint(exc.formStash.errors)
                    exit()

    exit()
