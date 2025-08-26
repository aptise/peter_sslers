# stdlib
import json
import os
import pprint
import sys
from typing import Any
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
from ..lib.forms import Form_EnrollmentFactory_query
from ..lib.forms import Form_RenewalConfig_new
from ..lib.forms import Form_RenewalConfig_new_configuration
from ..lib.forms import Form_RenewalConfig_new_enrollment
from ..lib.forms import Form_RenewalConfig_new_order
from ..lib.forms import Form_RenewalConfiguration_mark
from ..lib.forms import Form_SystemConfiguration_edit
from ..lib.forms import Form_SystemConfiguration_Global_edit
from ..lib.forms import Form_X509Certificate_mark
from ..views_admin import acme_account as v_acme_account
from ..views_admin import acme_dns_server as v_acme_dns_server
from ..views_admin import enrollment_factory as v_enrollment_factory
from ..views_admin import renewal_configuration as v_renewal_configuration
from ..views_admin import system_configuration as v_system_configuration
from ..views_admin import x509_certificate as v_x509_certificate
from ...lib import db as lib_db  # noqa: F401
from ...lib.utils import validate_config_uri
from ...model import objects as model_objects

if TYPE_CHECKING:
    from ...model.objects import AcmeAccount
    from ...model.objects import AcmeDnsServer
    from ...model.objects import AcmeOrder
    from ...model.objects import EnrollmentFactory
    from ...model.objects import RenewalConfiguration
    from ...model.objects import SystemConfiguration
    from ...model.objects import X509Certificate

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
    "domain": [
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
    "x509-certificate": [
        "list",
        "focus",
        "mark",
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
    config_uri = validate_config_uri(config_uri)
    command = argv[2]
    subcommand = argv[3]

    options: dict = {}
    try:
        if len(argv) == 5:
            if argv[4].lower() in ("help", "help=1"):
                options["help"] = "1"
                raise GeneratorExit()
        options = parse_vars(argv[4:])
    except GeneratorExit:
        pass

    # GLOBAL varlue
    RENDER_JSON = True if options.get("as_json", "").upper() in ("TRUE", "1") else False

    if command not in COMMANDS:
        print("`%s` is not a valid command" % command)
        exit(1)
    if subcommand not in COMMANDS[command]:
        print("`%s` is not a valid subcommand for `%s`" % (subcommand, command))
        exit(1)

    def render_data(data: Any) -> None:
        # determine as_json on the fly;
        # the pyramid integration code expects the options to all be strings
        if RENDER_JSON:
            print(json.dumps(data))
        else:
            pprint.pprint(data)

    # don't use this, as we need a real pyramid request
    # ctx = new_scripts_setup(config_uri, options=options)

    app = get_app(config_uri, options=options)
    request = Request.blank("/", POST=MultiDict(**options))
    with pyramid.scripting.prepare(registry=app.app.registry, request=request) as env:
        _request = env["request"]
        assert request == _request

        # generic functions
        def _list_items(
            f_count: Optional[Callable],
            f_paginated: Callable,
            is_extended=True,
            condensed=False,
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
            if RENDER_JSON:
                # TODO: print these asjson, but needs to be wrapped into caller
                return
            for _dbItem in dbItems:
                print("-----")
                if condensed:
                    if isinstance(_dbItem, model_objects.X509Certificate):
                        print("Certificate:", _dbItem.id)
                        print("\tnotAfter:", _dbItem.timestamp_not_after)
                        print("\tnotBefore:", _dbItem.timestamp_not_before)
                        print("\tDomains:", _dbItem.domains_as_string)
                        print(
                            "\tACME Server:",
                            (
                                _dbItem.acme_order.acme_account.acme_server.name
                                if _dbItem.acme_order
                                else "{}"
                            ),
                        )
                        continue

                if is_extended:
                    if isinstance(_dbItem, model_objects.EnrollmentFactory):
                        render_data(_dbItem.as_json_docs)
                        continue
                    elif isinstance(_dbItem, model_objects.RenewalConfiguration):
                        render_data(_dbItem.as_json_docs)
                        continue
                render_data(_dbItem.as_json)
            print("Total Items: %s" % dbItemsCount if dbItemsCount is not None else "x")
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

        def _get_X509Certificate(
            arg: str = "id", required: bool = True
        ) -> "X509Certificate":
            x509_certificate_id = options[arg]
            _dbX509Certificate = lib_db.get.get__X509Certificate__by_id(
                request.api_context, x509_certificate_id
            )
            if not _dbX509Certificate:
                print("invalid `X509Certificate`")
                exit(1)
            return _dbX509Certificate

        # !!!: distpatch[acme-account]
        if command == "acme-account":
            _dbAcmeAccount: Optional["AcmeAccount"]
            # !!!: focus
            if subcommand == "focus":
                _dbAcmeAccount = _get_AcmeAccount()
                render_data(_dbAcmeAccount.as_json)
            # !!!: - list
            elif subcommand == "list":
                if not RENDER_JSON:
                    print("ACME Accounts:")
                _list_items(
                    lib_db.get.get__AcmeAccount__count,
                    lib_db.get.get__AcmeAccount__paginated,
                )
            # !!!: - new
            elif subcommand == "new":
                # !!!: - new - help
                if "help" in options:
                    render_data(Form_AcmeAccount_new__auth.fields)
                    exit(0)
                try:
                    _dbAcmeAccount, _is_created = v_acme_account.submit__new_auth(
                        request,
                        acknowledge_transaction_commits=True,
                    )
                    if not RENDER_JSON:
                        print("success", "[CREATED]" if _is_created else "")
                    render_data(_dbAcmeAccount.as_json)
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    render_data(exc.formStash.errors)
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
                if not RENDER_JSON:
                    print("acme-dns Servers:")
                _list_items(
                    lib_db.get.get__AcmeDnsServer__count,
                    lib_db.get.get__AcmeDnsServer__paginated,
                )
            # !!!: - new
            elif subcommand == "new":
                # !!!: - new - help
                if "help" in options:
                    render_data(Form_AcmeDnsServer_new.fields)
                    exit(0)
                try:
                    _dbAcmeDnsServer, _is_created = v_acme_dns_server.submit__new(
                        request,
                        acknowledge_transaction_commits=True,
                    )
                    if not RENDER_JSON:
                        print("success", "[CREATED]" if _is_created else "")
                    render_data(_dbAcmeDnsServer.as_json)
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    render_data(exc.formStash.errors)
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
                if not RENDER_JSON:
                    print("successful check")
        # !!!: distpatch[acme-order]
        elif command == "acme-order":
            # !!!: - focus
            if command == "focus":
                _dbAcmeOrder = _get_AcmeOrder()
                render_data(_dbAcmeOrder.as_json)
            # !!!: - list
            elif subcommand == "list":
                if not RENDER_JSON:
                    print("ACME Orders:")
                _list_items(
                    lib_db.get.get__AcmeOrder__count,
                    lib_db.get.get__AcmeOrder__paginated,
                )
        # !!!: distpatch[acme-server]
        elif command == "acme-server":
            # !!!: - list
            if subcommand == "list":
                if not RENDER_JSON:
                    print("ACME Servers:")
                _list_items(
                    None,
                    lib_db.get.get__AcmeServer__paginated,
                )
        # !!!: distpatch[domain]
        elif command == "domain":
            # !!!: - list
            if subcommand == "list":
                if not RENDER_JSON:
                    print("Domains:")
                _list_items(
                    None,
                    lib_db.get.get__Domain__paginated,
                )
        # !!!: distpatch[enrollment-factory]
        elif command == "enrollment-factory":
            _dbEnrollmentFactory: Optional["EnrollmentFactory"]
            # !!!: focus
            if subcommand == "focus":
                _dbEnrollmentFactory = _get_EnrollmentFactory()
                # ssl_manage data_development enrollment-factory focus id=1 query=1 domain_name=example.com
                if "query" in options:
                    if "help" in options:
                        render_data(Form_EnrollmentFactory_query.fields)
                        exit(0)
                    (formStash, dbRenewalConfiguration, dbX509Certificates) = (
                        v_enrollment_factory.submit__query(
                            request,
                            dbEnrollmentFactory=_dbEnrollmentFactory,
                        )
                    )
                    _formatted = {
                        "result": "success",
                        "domain_name": formStash.results["domain_name"],
                        "RenewalConfiguration": (
                            dbRenewalConfiguration.as_json
                            if dbRenewalConfiguration
                            else None
                        ),
                        "X509Certificates": [i.as_json for i in dbX509Certificates],
                    }
                    render_data(_formatted)
                else:
                    render_data(_dbEnrollmentFactory.as_json)
            # !!!: - list
            elif subcommand == "list":
                if not RENDER_JSON:
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
                    render_data(_dbEnrollmentFactory.as_json_docs)
                except formhandling.FormInvalid as exc:
                    if not RENDER_JSON:
                        print("Errors:")
                    render_data(exc.formStash.errors)
                    exit(1)

        # !!!: distpatch[rate-limited]
        elif command == "rate-limited":
            # !!!: - list
            if subcommand == "list":
                if not RENDER_JSON:
                    print("RateLimiteds:")
                _list_items(
                    None,
                    lib_db.get.get__RateLimited__paginated,
                )
            # !!!: - clear
            elif subcommand == "clear":
                # !!!: - clear - help
                if "help" in options:
                    print(
                        "submit either `acme_account_id=INT` or `acme_server_id=INT`."
                    )
                    print(
                        "you may submit `unique_fqdn_set_id=INT` with `acme_server_id`."
                    )
                    exit(0)
                acme_account_id = options.get("acme_account_id", None)
                acme_server_id = options.get("acme_server_id", None)
                unique_fqdn_set_id = options.get("unique_fqdn_set_id", None)
                if acme_account_id is not None:
                    acme_account_id = int(acme_account_id)
                    lib_db.delete.delete__RateLimited__by_AcmeAccountId(
                        request.api_context, acme_account_id
                    )
                    print("delete__RateLimited__by_AcmeAccountId")
                    request.api_context.pyramid_transaction_commit()
                elif acme_server_id is not None:
                    acme_server_id = int(acme_server_id)
                    if unique_fqdn_set_id is not None:
                        unique_fqdn_set_id = int(unique_fqdn_set_id)
                        lib_db.delete.delete__RateLimited__by_AcmeServerId_UniqueFQDNSetId(
                            request.api_context, acme_server_id, unique_fqdn_set_id
                        )
                        print("delete__RateLimited__by_AcmeServerId_UniqueFQDNSetId")
                        request.api_context.pyramid_transaction_commit()
                    else:
                        lib_db.delete.delete__RateLimited__by_AcmeServerId(
                            request.api_context, acme_server_id
                        )
                        print("delete__RateLimited__by_AcmeServerId")
                        request.api_context.pyramid_transaction_commit()
                else:
                    raise ValueError(
                        "must supply `acme_account_id` or `acme_server_id`; `unique_fqdn_set_id` can be submitted with `acme_server_id`"
                    )

        # !!!: distpatch[renewal-configuration]
        elif command == "renewal-configuration":
            _dbRenewalConfiguration: Optional["RenewalConfiguration"]
            # !!!: focus
            if subcommand == "focus":
                _dbRenewalConfiguration = _get_RenewalConfiguration()
                render_data(_dbRenewalConfiguration.as_json)
            # !!!: - list
            elif subcommand == "list":
                if not RENDER_JSON:
                    print("Renewal Configurations:")
                _list_items(
                    lib_db.get.get__RenewalConfiguration__count,
                    lib_db.get.get__RenewalConfiguration__paginated,
                )
            # !!!: - mark
            elif subcommand == "mark":
                # !!!: - mark - help
                if "help" in options:
                    render_data(Form_RenewalConfiguration_mark.fields)
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
                    if not RENDER_JSON:
                        print("success", _action)
                    render_data(_dbRenewalConfiguration.as_json)
                except formhandling.FormInvalid as exc:
                    if not RENDER_JSON:
                        print("Errors:")
                    render_data(exc.formStash.errors)
                    exit(1)
            # !!!: - new
            elif subcommand == "new":
                # !!!: - new - help
                if "help" in options:
                    render_data(Form_RenewalConfig_new.fields)
                    exit(0)
                try:
                    _dbRenewalConfiguration, _is_duplicate = (
                        v_renewal_configuration.submit__new(
                            request,
                            acknowledge_transaction_commits=True,
                        )
                    )
                    if not RENDER_JSON:
                        print("success", "[DUPLICATE]" if _is_duplicate else "")
                    render_data(_dbRenewalConfiguration.as_json)
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    render_data(exc.formStash.errors)
                    exit(1)
            # !!!: - new-configuration
            elif subcommand == "new-configuration":
                # !!!: - new-configuration - help
                if "help" in options:
                    print("MUST submit `id`")
                    render_data(Form_RenewalConfig_new_configuration.fields)
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
                    if not RENDER_JSON:
                        print("success", "[DUPLICATE]" if _is_duplicate else "")
                    render_data(_dbRenewalConfigurationNew.as_json)
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    render_data(exc.formStash.errors)
            # !!!: - new-enrollment
            elif subcommand == "new-enrollment":
                # !!!: - new-enrollment - help
                if "help" in options:
                    print("MUST submit `enrollment_factory_id`")
                    render_data(Form_RenewalConfig_new_enrollment.fields)
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
                    render_data(_dbRenewalConfiguration.as_json)
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    render_data(exc.formStash.errors)
            # !!!: - new-order
            elif subcommand == "new-order":
                # !!!: - new-order - help
                if "help" in options:
                    print("MUST submit `id`")
                    render_data(Form_RenewalConfig_new_order.fields)
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
                    if not RENDER_JSON:
                        print(
                            "success",
                            (
                                "[NonFatalError: %s]" % _excAcmeOrder
                                if _excAcmeOrder
                                else ""
                            ),
                        )
                    render_data(_dbAcmeOrder.as_json)
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    render_data(exc.formStash.errors)
        # !!!: distpatch[system-configuration]
        elif command == "system-configuration":
            # _dbRenewalConfiguration: Optional["RenewalConfiguration"]  # type: ignore[no-redef]

            # !!!: - list
            if subcommand == "list":
                if not RENDER_JSON:
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
                    render_data(Form_SystemConfiguration_Global_edit.fields)
                    print("Others:")
                    render_data(Form_SystemConfiguration_edit.fields)
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
                    if not RENDER_JSON:
                        print("success")
                    render_data(_dbSystemConfiguration.as_json)
                except formhandling.FormInvalid as exc:
                    print("Errors:")
                    render_data(exc.formStash.errors)
        # !!!: distpatch[x509-certificate]
        elif command == "x509-certificate":
            _dbX509Certificate: Optional["X509Certificate"]
            # !!!: focus
            if subcommand == "focus":
                _dbX509Certificate = _get_X509Certificate()
                render_data(_dbX509Certificate.as_json)
            elif subcommand == "list":
                if not RENDER_JSON:
                    print("X509Certificates:")
                _list_items(
                    lib_db.get.get__X509Certificate__count,
                    lib_db.get.get__X509Certificate__paginated,
                    condensed=True,
                )
            # !!!: - mark
            elif subcommand == "mark":
                # !!!: - mark - help
                if "help" in options:
                    render_data(Form_X509Certificate_mark.fields)
                    exit(0)
                try:
                    _dbX509Certificate = _get_X509Certificate()
                    _dbX509Certificate, _action = v_x509_certificate.submit__mark(
                        request,
                        dbX509Certificate=_dbX509Certificate,
                        acknowledge_transaction_commits=True,
                    )
                    if not RENDER_JSON:
                        print("success", _action)
                    render_data(_dbX509Certificate.as_json)
                except formhandling.FormInvalid as exc:
                    if not RENDER_JSON:
                        print("Errors:")
                    render_data(exc.formStash.errors)
                    exit(1)
