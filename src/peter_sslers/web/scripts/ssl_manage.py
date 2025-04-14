# stdlib
import os
import pprint
import sys
from typing import Callable
from typing import Dict
from typing import List
from typing import NoReturn
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
from ..lib.forms import Form_RenewalConfig_new_configuration
from ..lib.forms import Form_RenewalConfig_new_enrollment
from ..lib.forms import Form_RenewalConfig_new_order
from ..lib.forms import Form_RenewalConfiguration_mark
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

# Dict of valid commands
COMMANDS: Dict[str, List[str]] = {
    "acme-account": [
        "authenticate",
        "check",
        "list",
        "new",
    ],
    "acme-dns-server": [
        "check",
        "list",
        "new",
    ],
    "acme-server": [
        "list",
    ],
    "enrollment-factory": [
        "list",
        "new",
    ],
    "renewal-configuration": [
        "list",
        "mark",
        "new",
        "new-configuration",
        "new-enrollment",
        "new-order",
    ],
}


def usage(argv) -> NoReturn:
    cmd = os.path.basename(argv[0])
    print(
        "usage: %s <config_uri> <command> <subcommand> [var=value]\n"
        '(example: "%s conf/example_development.ini")' % (cmd, cmd)
    )
    print("valid commands:")
    pprint.pprint(COMMANDS)
    sys.exit(0)


def main(argv=sys.argv):
    if len(argv) < 4:
        usage(argv)
    config_uri = argv[1]
    command = argv[2]
    subcommand = argv[3]
    options = parse_vars(argv[4:])

    if command not in COMMANDS:
        print("`%s` is not a valid command" % command)
        exit(1)
    if subcommand not in COMMANDS[command]:
        print("`%s` is not a valid subcommand for `%s`" % (subcommand, command))
        exit(1)

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
                    exit(0)
                try:
                    _dbAcmeAccount, _is_created = v_acme_account.submit__new_auth(
                        request,
                        acknowledge_transaction_commits=True,
                    )
                    print("success", "[CREATED]" if _is_created else "")
                    print(_dbAcmeAccount.as_json)
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    pprint.pprint(exc.formStash.errors)
            # !!!: authenticate
            elif subcommand in (
                "authenticate",
                "check",
            ):
                if "help" in options:
                    print('%s id="{INT}' % subcommand)
                    exit(0)
                acme_account_id = options["id"]
                _dbAcmeAccount = lib_db.get.get__AcmeAccount__by_id(
                    request.api_context, acme_account_id
                )
                if not _dbAcmeAccount:
                    print("invalid `AcmeAccount`")
                    exit(1)
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
                    exit(0)
                print("error", _err)

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
                    exit(0)
                try:
                    _dbAcmeDnsServer, _is_created = v_acme_dns_server.submit__new(
                        request,
                        acknowledge_transaction_commits=True,
                    )
                    print("success", "[CREATED]" if _is_created else "")
                    print(_dbAcmeDnsServer.as_json)
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    pprint.pprint(exc.formStash.errors)
                    exit(1)
            # !!!: check
            elif subcommand == "check":
                if "help" in options:
                    print('check id="{INT}')
                    exit(0)
                acme_dns_server_id = options["id"]
                _dbAcmeDnsServer = lib_db.get.get__AcmeDnsServer__by_id(
                    request.api_context, acme_dns_server_id
                )
                if not _dbAcmeDnsServer:
                    print("invalid `AcmeDnsServer`")
                    exit(1)
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
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    pprint.pprint(exc.formStash.errors)
                    exit(1)

        # !!!: distpatch[renewal-configuration]
        elif command == "renewal-configuration":
            _dbRenewalConfiguration: Optional["RenewalConfiguration"]

            # !!!: list
            if subcommand == "list":
                print("Renewal Configurations:")
                _list_items(lib_db.get.get__RenewalConfiguration__paginated)
            # !!!: mark
            elif subcommand == "mark":
                if "help" in options:
                    pprint.pprint(Form_RenewalConfiguration_mark.fields)
                    exit(0)
                renewal_configuration_id = options["id"]
                _dbRenewalConfiguration = lib_db.get.get__RenewalConfiguration__by_id(
                    request.api_context, renewal_configuration_id
                )
                if not _dbRenewalConfiguration:
                    print("invalid `RenewalConfiguration`")
                    exit(1)
                try:
                    _dbRenewalConfiguration, _action = (
                        v_renewal_configuration.submit__mark(
                            request,
                            dbRenewalConfiguration=_dbRenewalConfiguration,
                            acknowledge_transaction_commits=True,
                        )
                    )
                    print("success", _action)
                    print(_dbRenewalConfiguration.as_json)
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    pprint.pprint(exc.formStash.errors)
                    exit(1)
            # !!!: new
            elif subcommand == "new":
                if "help" in options:
                    pprint.pprint(Form_RenewalConfig_new.fields)
                    exit(0)
                try:
                    _dbRenewalConfiguration, _is_duplicate = (
                        v_renewal_configuration.submit__new(
                            request,
                            acknowledge_transaction_commits=True,
                        )
                    )
                    print("success", "[DUPLICATE]" if _is_duplicate else "")
                    print(_dbRenewalConfiguration.as_json)
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    pprint.pprint(exc.formStash.errors)
                    exit(1)
            # !!!: new-configuration
            elif subcommand == "new-configuration":
                if "help" in options:
                    print("MUST submit `id`")
                    pprint.pprint(Form_RenewalConfig_new_configuration.fields)
                    exit(0)
                renewal_configuration_id = options["id"]
                _dbRenewalConfiguration = lib_db.get.get__RenewalConfiguration__by_id(
                    request.api_context, renewal_configuration_id
                )
                if not _dbRenewalConfiguration:
                    print("invalid `RenewalConfiguration`")
                    exit(1)
                try:
                    _dbRenewalConfigurationNew, _is_duplicate = (
                        v_renewal_configuration.submit__new_configuration(
                            request,
                            dbRenewalConfiguration=_dbRenewalConfiguration,
                            acknowledge_transaction_commits=True,
                        )
                    )
                    print("success", "[DUPLICATE]" if _is_duplicate else "")
                    print(_dbRenewalConfigurationNew.as_json)
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    pprint.pprint(exc.formStash.errors)
            # !!!: new-enrollment
            elif subcommand == "new-enrollment":
                if "help" in options:
                    print("MUST submit `enrollment_factory_id`")
                    pprint.pprint(Form_RenewalConfig_new_enrollment.fields)
                    exit(0)
                enrollment_factory_id = options["enrollment_factory_id"]
                _dbEnrollmentFactory = lib_db.get.get__EnrollmentFactory__by_id(
                    request.api_context, enrollment_factory_id
                )
                if not _dbEnrollmentFactory:
                    print("invalid `EnrollmentFactory`")
                    exit(1)
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
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    pprint.pprint(exc.formStash.errors)
            # !!!: new-order
            elif subcommand == "new-order":
                if "help" in options:
                    print("MUST submit `renewal_configuration_id`")
                    pprint.pprint(Form_RenewalConfig_new_order.fields)
                    exit(0)
                renewal_configuration_id = options["renewal_configuration_id"]
                _dbRenewalConfiguration = lib_db.get.get__RenewalConfiguration__by_id(
                    request.api_context, renewal_configuration_id
                )
                if not _dbRenewalConfiguration:
                    print("invalid `RenewalConfiguration`")
                    exit(1)
                try:
                    import pdb

                    pdb.set_trace()
                    exit()
                    _dbAcmeOrder, _excAcmeOrder, _is_duplicate = (
                        v_renewal_configuration.submit__new_order(
                            request,
                            dbRenewalConfiguration=_dbRenewalConfiguration,
                            acknowledge_transaction_commits=True,
                        )
                    )
                    print(
                        "success",
                        "[NonFatalError: %s]" % _excAcmeOrder if _excAcmeOrder else "",
                    )
                    print(_dbAcmeOrder.as_json)
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    pprint.pprint(exc.formStash.errors)
