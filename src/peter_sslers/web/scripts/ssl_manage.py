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
from ..lib.forms import Form_SystemConfiguration_edit
from ..lib.forms import Form_SystemConfiguration_Global_edit
from ..views_admin import acme_account as v_acme_account
from ..views_admin import acme_dns_server as v_acme_dns_server
from ..views_admin import enrollment_factory as v_enrollment_factory
from ..views_admin import renewal_configuration as v_renewal_configuration
from ..views_admin import system_configuration as v_system_configuration
from ...lib import db as lib_db  # noqa: F401
from ...model import objects as model_objects


if TYPE_CHECKING:
    from ...model.objects import AcmeAccount
    from ...model.objects import AcmeDnsServer
    from ...model.objects import AcmeOrder
    from ...model.objects import EnrollmentFactory
    from ...model.objects import RenewalConfiguration
    from ...model.objects import SystemConfiguration

# ==============================================================================

# Dict of valid commands
COMMANDS: Dict[str, List[str]] = {
    "acme-account": [
        "authenticate",
        "check",
        "focus",
        "list",
        "new",
    ],
    "acme-dns-server": [
        "check",
        "list",
        "new",
    ],
    "acme-order": [
        "focus",
        "list",
    ],
    "acme-server": [
        "list",
    ],
    "enrollment-factory": [
        "focus",
        "list",
        "new",
    ],
    "rate-limited": [
        "clear",
        "list",
    ],
    "renewal-configuration": [
        "focus",
        "list",
        "mark",
        "new",
        "new-configuration",
        "new-enrollment",
        "new-order",
    ],
    "system-configuration": [
        "list",
        "edit",
    ],
}


def usage(argv) -> NoReturn:
    cmd = os.path.basename(argv[0])
    print(
        "usage: %s <config_uri> <command> <subcommand> [var=value]\n"
        '(example: "%s data_development/config.ini")' % (cmd, cmd)
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
    
    options:dict = {}
    try:
        if len(argv) == 5:
            if argv[4].lower() in ("help", "help=1"):
                options["help"] = "1"
                raise GeneratorExit()
        options = parse_vars(argv[4:])
    except GeneratorExit:
        pass

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
        def _list_items(
            f_count: Optional[Callable], f_paginated: Callable, is_extended=True
        ):
            offset = 0
            limit = None
            dbItemsCount: Optional[int]
            if f_count:
                offset = options.get("offset", 0)
                limit = options.get("limit", 10)
                dbItemsCount = f_count(request.api_context)
            else:
                dbItemsCount = None
            dbItems = f_paginated(request.api_context, offset=offset, limit=limit)
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
            print("Total Items: %s" % dbItemsCount)
            print("Showing: offset %s, limit %s" % (offset, limit))

        def _get_AcmeAccount(arg: str = "id", required: bool = True) -> "AcmeAccount":
            acme_account_id = options[arg]
            _dbAcmeAccount = lib_db.get.get__AcmeAccount__by_id(
                request.api_context, acme_account_id
            )
            if not _dbAcmeAccount:
                print("invalid `AcmeAccount`")
                exit(1)
            return _dbAcmeAccount

        def _get_AcmeDnsServer(
            arg: str = "id", required: bool = True
        ) -> "AcmeDnsServer":
            acme_dns_server_id = options[arg]
            _dbAcmeDnsServer = lib_db.get.get__AcmeDnsServer__by_id(
                request.api_context, acme_dns_server_id
            )
            if not _dbAcmeDnsServer:
                print("invalid `AcmeDnsServer`")
                exit(1)
            return _dbAcmeDnsServer

        def _get_AcmeOrder(arg: str = "id", required: bool = True) -> "AcmeOrder":
            acme_ord_id = options[arg]
            _dbAcmeOrder = lib_db.get.get__AcmeOrder__by_id(
                request.api_context, acme_ord_id
            )
            if not _dbAcmeOrder:
                print("invalid `AcmeOrder`")
                exit(1)
            return _dbAcmeOrder

        def _get_EnrollmentFactory(
            arg: str = "id", required: bool = True
        ) -> "EnrollmentFactory":
            enrollment_factory_id = options[arg]
            _dbEnrollmentFactory = lib_db.get.get__EnrollmentFactory__by_id(
                request.api_context, enrollment_factory_id
            )
            if not _dbEnrollmentFactory:
                print("invalid `EnrollmentFactory`")
                exit(1)
            return _dbEnrollmentFactory

        def _get_RenewalConfiguration(
            arg: str = "id", required: bool = True
        ) -> "RenewalConfiguration":
            renewal_configuration_id = options[arg]
            _dbRenewalConfiguration = lib_db.get.get__RenewalConfiguration__by_id(
                request.api_context, renewal_configuration_id
            )
            if not _dbRenewalConfiguration:
                print("invalid `RenewalConfiguration`")
                exit(1)
            return _dbRenewalConfiguration

        def _get_SystemConfiguration(
            arg: str = "id", required: bool = True
        ) -> "SystemConfiguration":
            system_configuration_id = options[arg]
            _dbSystemConfiguration = lib_db.get.get__SystemConfiguration__by_id(
                request.api_context, system_configuration_id
            )
            if not _dbSystemConfiguration:
                print("invalid `SystemConfiguration`")
                exit(1)
            return _dbSystemConfiguration

        # !!!: distpatch[acme-account]
        if command == "acme-account":
            _dbAcmeAccount: Optional["AcmeAccount"]
            # !!!: focus
            if subcommand == "focus":
                _dbAcmeAccount = _get_AcmeAccount()
                print(_dbAcmeAccount.as_json)
            # !!!: - list
            elif subcommand == "list":
                print("ACME Accounts:")
                _list_items(
                    lib_db.get.get__AcmeAccount__count,
                    lib_db.get.get__AcmeAccount__paginated,
                )
            # !!!: - new
            elif subcommand == "new":
                # !!!: - new - help
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
            # !!!: - authenticate/check
            elif subcommand in (
                "authenticate",
                "check",
            ):
                # !!!: - authenticate/check - help
                if "help" in options:
                    print('%s id="{INT}' % subcommand)
                    exit(0)
                _dbAcmeAccount = _get_AcmeAccount()
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
            # !!!: - list
            if subcommand == "list":
                print("acme-dns Servers:")
                _list_items(
                    lib_db.get.get__AcmeDnsServer__count,
                    lib_db.get.get__AcmeDnsServer__paginated,
                )
            # !!!: - new
            elif subcommand == "new":
                # !!!: - new - help
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
            # !!!: - check
            elif subcommand == "check":
                # !!!: - check - help
                if "help" in options:
                    print('check id="{INT}')
                    exit(0)
                _dbAcmeDnsServer = _get_AcmeDnsServer()
                _result = v_acme_dns_server.submit__check(  # noqa: F841
                    request,
                    dbAcmeDnsServer=_dbAcmeDnsServer,
                )
                print("successful check")
        # !!!: distpatch[acme-order]
        elif command == "acme-order":
            # !!!: - focus
            if command == "focus":
                _dbAcmeOrder = _get_AcmeOrder()
                print(_dbAcmeOrder.as_json)
            # !!!: - list
            elif subcommand == "list":
                print("ACME Orders:")
                _list_items(
                    lib_db.get.get__AcmeOrder__count,
                    lib_db.get.get__AcmeOrder__paginated,
                )
        # !!!: distpatch[acme-server]
        elif command == "acme-server":
            # !!!: - list
            if subcommand == "list":
                print("ACME Servers:")
                _list_items(
                    None,
                    lib_db.get.get__AcmeServer__paginated,
                )
        # !!!: distpatch[enrollment-factory]
        elif command == "enrollment-factory":
            _dbEnrollmentFactory: Optional["EnrollmentFactory"]
            # !!!: focus
            if subcommand == "focus":
                _dbEnrollmentFactory = _get_EnrollmentFactory()
                print(_dbEnrollmentFactory.as_json)
            # !!!: - list
            elif subcommand == "list":
                print("Enrollment Factories:")
                _list_items(
                    lib_db.get.get__EnrollmentFactory__count,
                    lib_db.get.get__EnrollmentFactory__paginated,
                )
            # !!!: - new
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

        # !!!: distpatch[rate-limited]
        elif command == "rate-limited":
            # !!!: - list
            if subcommand == "list":
                print("RateLimiteds:")
                _list_items(
                    None,
                    lib_db.get.get__RateLimited__paginated,
                )
            # !!!: - clear
            elif subcommand == "clear":
                # !!!: - clear - help
                if "help" in options:
                    print("submit either `acme_account_id=INT` or `acme_server_id=INT`")
                    exit(0)
                acme_account_id = options.get("acme_account_id", None)
                acme_server_id = options.get("acme_server_id", None)
                if acme_account_id is not None:
                    acme_account_id = int(acme_account_id)
                    lib_db.delete.delete__RateLimited__by_AcmeAccountId(request.api_context, acme_account_id)
                    print("delete__RateLimited__by_AcmeAccountId")
                elif acme_server_id is not None:
                    acme_server_id = int(acme_server_id)
                    lib_db.delete.delete__RateLimited__by_AcmeServerId(request.api_context, acme_server_id)
                    print("delete__RateLimited__by_AcmeServerId")
                else:
                    raise ValueError("must supply acme_account_id or acme_server_id")

        # !!!: distpatch[renewal-configuration]
        elif command == "renewal-configuration":
            _dbRenewalConfiguration: Optional["RenewalConfiguration"]
            # !!!: focus
            if subcommand == "focus":
                _dbRenewalConfiguration = _get_RenewalConfiguration()
                print(_dbRenewalConfiguration.as_json)
            # !!!: - list
            elif subcommand == "list":
                print("Renewal Configurations:")
                _list_items(
                    lib_db.get.get__RenewalConfiguration__count,
                    lib_db.get.get__RenewalConfiguration__paginated,
                )
            # !!!: - mark
            elif subcommand == "mark":
                # !!!: - mark - help
                if "help" in options:
                    pprint.pprint(Form_RenewalConfiguration_mark.fields)
                    exit(0)
                try:
                    _dbRenewalConfiguration = _get_RenewalConfiguration()
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
            # !!!: - new
            elif subcommand == "new":
                # !!!: - new - help
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
            # !!!: - new-configuration
            elif subcommand == "new-configuration":
                # !!!: - new-configuration - help
                if "help" in options:
                    print("MUST submit `id`")
                    pprint.pprint(Form_RenewalConfig_new_configuration.fields)
                    exit(0)
                _dbRenewalConfiguration = _get_RenewalConfiguration()
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
            # !!!: - new-enrollment
            elif subcommand == "new-enrollment":
                # !!!: - new-enrollment - help
                if "help" in options:
                    print("MUST submit `enrollment_factory_id`")
                    pprint.pprint(Form_RenewalConfig_new_enrollment.fields)
                    exit(0)
                _dbEnrollmentFactory = _get_EnrollmentFactory(
                    arg="enrollment_factory_id"
                )
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
            # !!!: - new-order
            elif subcommand == "new-order":
                # !!!: - new-order - help
                if "help" in options:
                    print("MUST submit `id`")
                    pprint.pprint(Form_RenewalConfig_new_order.fields)
                    exit(0)
                _dbRenewalConfiguration = _get_RenewalConfiguration()
                try:
                    _dbAcmeOrder, _excAcmeOrder = (
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
        # !!!: distpatch[system-configuration]
        elif command == "system-configuration":
            # _dbRenewalConfiguration: Optional["RenewalConfiguration"]  # type: ignore[no-redef]

            # !!!: - list
            if subcommand == "list":
                print("Renewal Configurations:")
                _list_items(
                    lib_db.get.get__SystemConfiguration__count,
                    lib_db.get.get__SystemConfiguration__paginated,
                )
            # !!!: - edit
            elif subcommand == "edit":
                # !!!: - edit - help
                if "help" in options:
                    print("MUST submit `id`")
                    print("Global:")
                    pprint.pprint(Form_SystemConfiguration_Global_edit.fields)
                    print("Others:")
                    pprint.pprint(Form_SystemConfiguration_edit.fields)
                    exit(0)
                _dbSystemConfiguration = _get_SystemConfiguration()
                try:
                    if _dbSystemConfiguration.name == "global":
                        _dbSystemConfiguration = (
                            v_system_configuration.submit__edit_global(
                                request,
                                dbSystemConfiguration=_dbSystemConfiguration,
                                acknowledge_transaction_commits=True,
                            )
                        )
                    else:
                        _dbSystemConfiguration = v_system_configuration.submit__edit(
                            request,
                            dbSystemConfiguration=_dbSystemConfiguration,
                            acknowledge_transaction_commits=True,
                        )
                    print("success")
                    print(_dbSystemConfiguration.as_json)
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    pprint.pprint(exc.formStash.errors)
