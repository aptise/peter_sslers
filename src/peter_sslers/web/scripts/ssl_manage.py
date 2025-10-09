"""

Example usage:

    ssl_manage data_development/config.ini acme-account list
    ssl_manage data_development/config.ini acme-account list as_json=1
    ssl_manage data_development/config.ini acme-account focus id=4
    ssl_manage data_development/config.ini acme-account focus id=4 as_json=1
    ssl_manage data_development/config.ini acme-account check id=4
    ssl_manage data_development/config.ini acme-account check id=4 as_json=1
    ssl_manage data_development/config.ini acme-account authenticate id=4
    ssl_manage data_development/config.ini acme-account authenticate id=4 as_json=1

    ssl_manage data_development/config.ini acme-dns-server list
    ssl_manage data_development/config.ini acme-dns-server list as_json=1
    ssl_manage data_development/config.ini acme-dns-server new help
    ssl_manage data_development/config.ini acme-dns-server new as_json=1
    ssl_manage data_development/config.ini acme-dns-server check id=1

    ssl_manage data_development/config.ini acme-order list
    ssl_manage data_development/config.ini acme-order list as_json=1
    ssl_manage data_development/config.ini acme-order focus id=40
    ssl_manage data_development/config.ini acme-order focus id=40 as_json=1
    ssl_manage data_development/config.ini acme-order retry id=39
    ssl_manage data_development/config.ini acme-order process id=40
    ssl_manage data_development/config.ini acme-order retry id=40 as_json=1
    ssl_manage data_development/config.ini acme-order mark id=41 as_json=1
    ssl_manage data_development/config.ini acme-order mark id=41 as_json=1 action=invalid

    ssl_manage data_development/config.ini acme-order mark id=41 as_json=1 action=invalid
    ssl_manage data_development/config.ini acme-order retry id=41 as_json=1

    ssl_manage data_development/config.ini acme-order server_sync id=41 as_json=1
    ssl_manage data_development/config.ini acme-order server_sync_authz id=41 as_json=1
    ssl_manage data_development/config.ini acme-order deactivate_authz id=41 as_json=1
    ssl_manage data_development/config.ini acme-order download_certificate id=41 as_json=1

    ssl_manage data_development/config.ini action deactivate_expired as_json=1
"""

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
from pyramid_formencode_classic.tools import document_form
from webob.multidict import MultiDict

# local
from ..lib import formhandling
from ..lib.forms import Form_AcmeAccount_new__auth
from ..lib.forms import Form_AcmeDnsServer_new
from ..lib.forms import Form_AcmeOrder_mark
from ..lib.forms import Form_AcmeOrder_retry
from ..lib.forms import Form_EnrollmentFactory_new
from ..lib.forms import Form_EnrollmentFactory_onboard
from ..lib.forms import Form_EnrollmentFactory_query
from ..lib.forms import Form_RenewalConfig_new
from ..lib.forms import Form_RenewalConfig_new_configuration
from ..lib.forms import Form_RenewalConfig_new_order
from ..lib.forms import Form_RenewalConfiguration_mark
from ..lib.forms import Form_SystemConfiguration_edit
from ..lib.forms import Form_SystemConfiguration_Global_edit
from ..lib.forms import Form_X509Certificate_mark
from ..views_admin import acme_account as v_acme_account
from ..views_admin import acme_dns_server as v_acme_dns_server
from ..views_admin import acme_order as v_acme_order
from ..views_admin import api as v_api
from ..views_admin import enrollment_factory as v_enrollment_factory
from ..views_admin import renewal_configuration as v_renewal_configuration
from ..views_admin import system_configuration as v_system_configuration
from ..views_admin import x509_certificate as v_x509_certificate
from ...lib import db as lib_db  # noqa: F401
from ...lib import errors
from ...lib import utils_nginx
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
        "process",
        "mark",
        "retry",
        # these use the same api
        "deactivate_authz",
        "download_certificate",
        "finalize",
        "server_sync",
        "server_sync_authz",
    ],
    "acme-server": [
        "list",
    ],
    "action": [
        "deactivate_expired",
        "reconcile_cas",
        "prime_redis",
        "flush_nginx",
        "status_nginx",
        "update_recents",
    ],
    "domain": [
        "list",
    ],
    "enrollment-factory": [
        "focus",
        "onboard",
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

    def render_data(
        data: Any,
        error: Optional[Any] = None,
        success: Optional[Any] = None,
    ) -> None:
        """
        If data is just formfields, do not set "success".
        If error is supplied, set succes to False
        """
        # determine as_json on the fly;
        # the pyramid integration code expects the options to all be strings
        if error:
            if success is None:
                success = False
            if success is not False:
                raise ValueError("`success` must be `False` if `error` is submitted")
        if RENDER_JSON:
            payload = {
                "result": "success" if success else ("error" if error else None),
                "payload": data,
            }
            if error:
                payload["error"] = str(error) if isinstance(error, Exception) else error
            if success:
                if not isinstance(success, bool):
                    payload["success"] = success
            print(json.dumps(payload))
        else:
            print("=" * 80)
            if success:
                print("success")
                if not isinstance(success, bool):
                    print(success)
            if error:
                print("error", error)
            print("- " * 40)
            pprint.pprint(data)
            print("=" * 80)

    if command not in COMMANDS:
        render_data(None, error="`%s` is not a valid command" % command)
        exit(1)
    if subcommand not in COMMANDS[command]:
        render_data(
            None,
            error="`%s` is not a valid subcommand for `%s`" % (subcommand, command),
        )
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
            obj_name: str,
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
                payload = {
                    obj_name: [i.as_json for i in dbItems],
                    "pagination": {
                        "total": dbItemsCount,
                        "offset": offset,
                        "limit": limit,
                    },
                }
                render_data(payload, success=True)
                return
            for _dbItem in dbItems:
                print(obj_name)
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
                render_data(None, error="invalid `AcmeAccount`")
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
                render_data(None, error="invalid `AcmeDnsServer`")
                exit(1)
            return _dbAcmeDnsServer

        def _get_AcmeOrder(arg: str = "id", required: bool = True) -> "AcmeOrder":
            acme_ord_id = options[arg]
            _dbAcmeOrder = lib_db.get.get__AcmeOrder__by_id(
                request.api_context, acme_ord_id
            )
            if not _dbAcmeOrder:
                render_data(None, error="invalid `AcmeOrder`")
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
                render_data(None, error="invalid `EnrollmentFactory`")
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
                render_data(None, error="invalid `RenewalConfiguration`")
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
                render_data(None, error="invalid `SystemConfiguration`")
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
                render_data(None, error="invalid `X509Certificate`")
                exit(1)
            return _dbX509Certificate

        # scoping
        _dbAcmeAccount: Optional["AcmeAccount"]
        _dbAcmeDnsServer: Optional["AcmeDnsServer"]
        _dbEnrollmentFactory: Optional["EnrollmentFactory"]
        _dbRenewalConfiguration: Optional["RenewalConfiguration"]
        _dbX509Certificate: Optional["X509Certificate"]

        # !!!: distpatch[acme-account]
        if command == "acme-account":
            # !!!: focus
            if subcommand == "focus":
                _dbAcmeAccount = _get_AcmeAccount()
                render_data(_dbAcmeAccount.as_json, success=True)
                exit(0)
            # !!!: - list
            elif subcommand == "list":
                _list_items(
                    "AcmeAccount",
                    lib_db.get.get__AcmeAccount__count,
                    lib_db.get.get__AcmeAccount__paginated,
                )
                exit(0)
            # !!!: - new
            elif subcommand == "new":
                # !!!: - new - help
                if "help" in options:
                    payload = {"form": document_form(Form_AcmeAccount_new__auth)}
                    render_data(payload)
                    exit(0)
                try:
                    _dbAcmeAccount, _is_created = v_acme_account.submit__new_auth(
                        request,
                        acknowledge_transaction_commits=True,
                    )
                    render_data(
                        _dbAcmeAccount.as_json,
                        success="[CREATED]" if _is_created else True,
                    )
                except formhandling.FormInvalid as exc:
                    render_data(None, error=exc.formStash.errors)
                    exit(1)
                exit(0)
            # !!!: - authenticate/check
            elif subcommand in (
                "authenticate",
                "check",
            ):
                # !!!: - authenticate/check - help
                if "help" in options:
                    render_data({"note": '%s id="{INT}' % subcommand})
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
                render_data(_result, success=(not bool(_err)), error=_err)
                exit(0)

        # !!!: distpatch[acme-dns-server]
        elif command == "acme-dns-server":
            # !!!: - list
            if subcommand == "list":
                _list_items(
                    "AcmeDnsServer",
                    lib_db.get.get__AcmeDnsServer__count,
                    lib_db.get.get__AcmeDnsServer__paginated,
                )
                exit(0)
            # !!!: - new
            elif subcommand == "new":
                # !!!: - new - help
                if "help" in options:
                    payload = {"form": document_form(Form_AcmeDnsServer_new)}
                    render_data(payload)
                    exit(0)
                try:
                    _dbAcmeDnsServer, _is_created = v_acme_dns_server.submit__new(
                        request,
                        acknowledge_transaction_commits=True,
                    )
                    render_data(
                        _dbAcmeDnsServer.as_json,
                        success="[CREATED]" if _is_created else True,
                    )
                    exit(0)
                except formhandling.FormInvalid as exc:
                    render_data(None, error=exc.formStash.errors)
                    exit(1)
                except Exception as exc:
                    render_data(None, error=str(exc))
                    exit(1)
            # !!!: - check
            elif subcommand == "check":
                # !!!: - check - help
                if "help" in options:
                    render_data({"note": 'check id="{INT}'})
                    exit(0)
                _dbAcmeDnsServer = _get_AcmeDnsServer()
                _result = v_acme_dns_server.submit__check(  # noqa: F841
                    request,
                    dbAcmeDnsServer=_dbAcmeDnsServer,
                )
                render_data(_result, success=(not bool(_result)))
                exit(0)

        # !!!: distpatch[acme-order]
        elif command == "acme-order":
            # !!!: - focus
            if subcommand == "focus":
                _dbAcmeOrder = _get_AcmeOrder()
                render_data(_dbAcmeOrder.as_json, success=True)
                exit(0)

            # !!!: - list
            elif subcommand == "list":
                _list_items(
                    "AcmeOrder",
                    lib_db.get.get__AcmeOrder__count,
                    lib_db.get.get__AcmeOrder__paginated,
                )
                exit(0)

            # !!!: - process
            elif subcommand == "process":
                _dbAcmeOrder = _get_AcmeOrder()
                _dbAcmeOrder, _error = v_acme_order.submit__process(
                    request,
                    dbAcmeOrder=_dbAcmeOrder,
                    acknowledge_transaction_commits=True,
                )
                render_data(
                    _dbAcmeOrder.as_json, success=(not bool(_error)), error=_error
                )
                exit(0)
            # !!!: - mark
            elif subcommand == "mark":
                # !!!: - mark - help
                if "help" in options:
                    payload = {"form": document_form(Form_AcmeOrder_mark)}
                    render_data(payload)
                    exit(0)
                try:
                    _dbAcmeOrder = _get_AcmeOrder()
                    _dbAcmeOrder, _action = v_acme_order.submit__mark(
                        request,
                        dbAcmeOrder=_dbAcmeOrder,
                        acknowledge_transaction_commits=True,
                    )
                    render_data(_dbAcmeOrder.as_json, success=True)
                    exit(0)
                except (errors.InvalidRequest, errors.InvalidTransition) as exc:
                    render_data(None, error=str(exc))
                    exit(1)
            # !!!: - retry
            elif subcommand == "retry":
                # !!!: - retry - help
                if "help" in options:
                    payload = {"form": document_form(Form_AcmeOrder_retry)}
                    render_data(payload)
                    exit(0)
                try:
                    _dbAcmeOrder = _get_AcmeOrder()
                    _dbAcmeOrderNew, _exc = v_acme_order.submit__retry(
                        request,
                        dbAcmeOrder=_dbAcmeOrder,
                        acknowledge_transaction_commits=True,
                    )
                    render_data(
                        _dbAcmeOrderNew.as_json if _dbAcmeOrderNew else None,
                        success=(not bool(_exc)),
                        error=_exc,
                    )
                    exit(1 if _exc else 0)
                except formhandling.FormInvalid as exc:
                    render_data(None, error=exc.formStash.errors)
                    exit(1)
            # !!!: - deactivate_authz
            # !!!: - download_certificate
            # !!!: - finalize
            # !!!: - server_sync
            # !!!: - server_sync_authz
            elif subcommand in (
                "deactivate_authz",
                "download_certificate",
                "finalize",
                "server_sync",
                "server_sync_authz",
            ):
                _defs: Dict[str, Callable] = {
                    "deactivate_authz": v_acme_order.submit__acme_server_deactivate_authorizations,
                    "download_certificate": v_acme_order.submit__acme_server_download_certificate,
                    "finalize": v_acme_order.submit__acme_server_finalize,
                    "server_sync": v_acme_order.submit__acme_server_sync,
                    "server_sync_authz": v_acme_order.submit__acme_server_sync_authorizations,
                }
                _dbAcmeOrder = _get_AcmeOrder()
                _dbAcmeOrder, _error = _defs[subcommand](
                    request,
                    dbAcmeOrder=_dbAcmeOrder,
                    acknowledge_transaction_commits=True,
                )
                render_data(
                    _dbAcmeOrder.as_json,
                    success=(not bool(_error)),
                    error=_error,
                )
                exit(0 if not _error else 1)

        # !!!: distpatch[acme-server]
        elif command == "acme-server":
            # !!!: - list
            if subcommand == "list":
                _list_items(
                    "AcmeServer",
                    None,
                    lib_db.get.get__AcmeServer__paginated,
                )
                exit(0)

        # !!!: distpatch[action]
        elif command == "action":
            if subcommand == "deactivate_expired":
                rval = v_api.actual__deactivate_expired(
                    request,
                    acknowledge_transaction_commits=True,
                )
                render_data(rval, success=True)

            elif subcommand == "reconcile_cas":
                operations_event = lib_db.actions.operations_reconcile_cas(
                    request.api_context,
                )
                request.api_context.pyramid_transaction_commit()
                render_data(operations_event.as_json, success=True)

            elif subcommand == "prime_redis":
                dbEvent, total_primed = v_api.actual__prime_redis(
                    request,
                    acknowledge_transaction_commits=True,
                )
                rval = {
                    "OperationsEvent": dbEvent.as_json,
                    "total_primed": total_primed,
                }
                render_data(rval, success=True)

            elif subcommand == "flush_nginx":
                request.api_context._ensure_nginx()
                success, dbEvent, servers_status = utils_nginx.nginx_flush_cache(
                    request,
                    request.api_context,
                )
                request.api_context.pyramid_transaction_commit()
                render_data(servers_status, success=True)

            elif subcommand == "status_nginx":
                request.api_context._ensure_nginx()
                servers_status = utils_nginx.nginx_status(
                    request,
                    request.api_context,
                )
                request.api_context.pyramid_transaction_commit()
                render_data(servers_status, success=True)

            elif subcommand == "update_recents":
                operations_event = lib_db.actions.operations_update_recents__global(
                    request.api_context,
                )
                request.api_context.pyramid_transaction_commit()
                render_data(operations_event.as_json, success=True)
            exit(0)

        # !!!: distpatch[domain]
        elif command == "domain":
            # !!!: - list
            if subcommand == "list":
                _list_items(
                    "Domain",
                    None,
                    lib_db.get.get__Domain__paginated,
                )
                exit(0)
        # !!!: distpatch[enrollment-factory]
        elif command == "enrollment-factory":
            # !!!: focus
            if subcommand == "focus":
                _dbEnrollmentFactory = _get_EnrollmentFactory()
                # ssl_manage data_development enrollment-factory focus id=1 query=1 domain_name=example.com
                if "query" in options:
                    if "help" in options:
                        payload = {"form": document_form(Form_EnrollmentFactory_query)}
                        render_data(payload)
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
                    render_data(_formatted, success=True)
                else:
                    render_data(_dbEnrollmentFactory.as_json, success=True)
                exit(0)

            # !!!: - onboard
            elif subcommand == "onboard":
                # !!!: - onboard - help
                if "help" in options:
                    payload = {
                        "note": "MUST submit `id`",
                        "form": document_form(Form_EnrollmentFactory_onboard),
                    }
                    render_data(payload)
                    exit(0)
                _dbEnrollmentFactory = _get_EnrollmentFactory()
                try:
                    _dbRenewalConfiguration, _is_duplicate = (
                        v_enrollment_factory.submit__onboard(
                            request,
                            dbEnrollmentFactory=_dbEnrollmentFactory,
                            acknowledge_transaction_commits=True,
                        )
                    )
                    render_data(
                        _dbRenewalConfiguration.as_json,
                        success="[DUPLICATE]" if _is_duplicate else True,
                    )
                    exit(0)
                except formhandling.FormInvalid as exc:
                    render_data(None, error=exc.formStash.errors)
                    exit(1)
            # !!!: - list
            elif subcommand == "list":
                _list_items(
                    "EnrollmentFactory",
                    lib_db.get.get__EnrollmentFactory__count,
                    lib_db.get.get__EnrollmentFactory__paginated,
                )
                exit(0)
            # !!!: - new
            elif subcommand == "new":
                # !!!: - new - help
                if "help" in options:
                    payload = {"form": document_form(Form_EnrollmentFactory_new)}
                    render_data(payload)
                    exit(0)
                try:
                    _dbEnrollmentFactory = v_enrollment_factory.submit__new(
                        request,
                        acknowledge_transaction_commits=True,
                    )
                    render_data(_dbEnrollmentFactory.as_json_docs, success=True)

                except formhandling.FormInvalid as exc:
                    render_data(None, error=exc.formStash.errors)
                    exit(1)

        # !!!: distpatch[rate-limited]
        elif command == "rate-limited":
            # !!!: - list
            if subcommand == "list":
                _list_items(
                    "RateLimited",
                    None,
                    lib_db.get.get__RateLimited__paginated,
                )
                exit(0)
            # !!!: - clear
            elif subcommand == "clear":
                # !!!: - clear - help
                if "help" in options:
                    payload = {
                        "note": [
                            "submit either `acme_account_id=INT` or `acme_server_id=INT`.",
                            "you may submit `unique_fqdn_set_id=INT` with `acme_server_id`.",
                        ],
                    }
                    render_data(payload)
                    exit(0)
                acme_account_id = options.get("acme_account_id", None)
                acme_server_id = options.get("acme_server_id", None)
                unique_fqdn_set_id = options.get("unique_fqdn_set_id", None)
                if acme_account_id is not None:
                    acme_account_id = int(acme_account_id)
                    lib_db.delete.delete__RateLimited__by_AcmeAccountId(
                        request.api_context, acme_account_id
                    )
                    render_data("delete__RateLimited__by_AcmeAccountId", success=True)
                    request.api_context.pyramid_transaction_commit()
                    exit(0)
                elif acme_server_id is not None:
                    acme_server_id = int(acme_server_id)
                    if unique_fqdn_set_id is not None:
                        unique_fqdn_set_id = int(unique_fqdn_set_id)
                        lib_db.delete.delete__RateLimited__by_AcmeServerId_UniqueFQDNSetId(
                            request.api_context, acme_server_id, unique_fqdn_set_id
                        )
                        render_data(
                            "delete__RateLimited__by_AcmeServerId_UniqueFQDNSetId",
                            success=True,
                        )
                        request.api_context.pyramid_transaction_commit()
                    else:
                        lib_db.delete.delete__RateLimited__by_AcmeServerId(
                            request.api_context, acme_server_id
                        )
                        render_data(
                            "delete__RateLimited__by_AcmeServerId", success=True
                        )
                        request.api_context.pyramid_transaction_commit()
                    exit(0)
                else:
                    render_data(
                        None,
                        error="must supply `acme_account_id` or `acme_server_id`; `unique_fqdn_set_id` can be submitted with `acme_server_id`",
                    )
                    exit(1)

        # !!!: distpatch[renewal-configuration]
        elif command == "renewal-configuration":
            # !!!: focus
            if subcommand == "focus":
                _dbRenewalConfiguration = _get_RenewalConfiguration()
                render_data(_dbRenewalConfiguration.as_json, success=True)
                exit(0)
            # !!!: - list
            elif subcommand == "list":
                _list_items(
                    "RenewalConfiguration",
                    lib_db.get.get__RenewalConfiguration__count,
                    lib_db.get.get__RenewalConfiguration__paginated,
                )
                exit(0)
            # !!!: - mark
            elif subcommand == "mark":
                # !!!: - mark - help
                if "help" in options:
                    payload = {"form": document_form(Form_RenewalConfiguration_mark)}
                    render_data(payload)
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
                    render_data(_dbRenewalConfiguration.as_json, success=True)
                    exit(0)
                except formhandling.FormInvalid as exc:
                    render_data(None, error=exc.formStash.errors)
                    exit(1)
            # !!!: - new
            elif subcommand == "new":
                # !!!: - new - help
                if "help" in options:
                    payload = {"form": document_form(Form_RenewalConfig_new)}
                    render_data(payload)
                    exit(0)
                try:
                    _dbRenewalConfiguration, _is_duplicate = (
                        v_renewal_configuration.submit__new(
                            request,
                            acknowledge_transaction_commits=True,
                        )
                    )
                    render_data(
                        _dbRenewalConfiguration.as_json,
                        success="[DUPLICATE]" if _is_duplicate else True,
                    )
                except formhandling.FormInvalid as exc:
                    render_data(None, error=exc.formStash.errors)
                    exit(1)

            # !!!: - new-configuration
            elif subcommand == "new-configuration":

                # !!!: - new-configuration - help
                if "help" in options:
                    payload = {
                        "form": document_form(Form_RenewalConfig_new_configuration)
                    }
                    render_data(payload)
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
                    render_data(
                        _dbRenewalConfigurationNew.as_json,
                        success="[DUPLICATE]" if _is_duplicate else True,
                    )
                    exit(0)
                except formhandling.FormInvalid as exc:
                    render_data(None, error=exc.formStash.errors)
                    exit(1)

            # !!!: - new-order
            elif subcommand == "new-order":
                # !!!: - new-order - help
                if "help" in options:
                    payload = {"form": document_form(Form_RenewalConfig_new_order)}
                    render_data(payload)
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
                    if _excAcmeOrder:
                        render_data(
                            _dbAcmeOrder.as_json,
                            success=True,
                            error=_excAcmeOrder,
                        )
                        exit(1)
                    render_data(_dbAcmeOrder.as_json, success=True)
                    exit(0)
                except formhandling.FormInvalid as exc:
                    render_data(None, error=exc.formStash.errors)
                    exit(1)

        # !!!: distpatch[system-configuration]
        elif command == "system-configuration":
            # _dbRenewalConfiguration: Optional["RenewalConfiguration"]  # type: ignore[no-redef]

            # !!!: - list
            if subcommand == "list":
                _list_items(
                    "SystemConfiguration",
                    lib_db.get.get__SystemConfiguration__count,
                    lib_db.get.get__SystemConfiguration__paginated,
                )
                exit(0)

            # !!!: - edit
            elif subcommand == "edit":
                # !!!: - edit - help
                if "help" in options:
                    _payload = {
                        "note": "`id=` is required",
                        "form.global": document_form(
                            Form_SystemConfiguration_Global_edit
                        ),
                        "form.others": document_form(Form_SystemConfiguration_edit),
                    }
                    render_data(_payload)
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
                    render_data(_dbSystemConfiguration.as_json, success=True)
                    exit(0)
                except formhandling.FormInvalid as exc:
                    render_data(None, error=exc.formStash.errors)
                    exit(1)

        # !!!: distpatch[x509-certificate]
        elif command == "x509-certificate":
            # !!!: focus
            if subcommand == "focus":
                _dbX509Certificate = _get_X509Certificate()
                render_data(_dbX509Certificate.as_json, success=True)
                exit(0)
            elif subcommand == "list":
                _list_items(
                    "X509Certificate",
                    lib_db.get.get__X509Certificate__count,
                    lib_db.get.get__X509Certificate__paginated,
                    condensed=True,
                )
                exit(0)
            # !!!: - mark
            elif subcommand == "mark":
                # !!!: - mark - help
                if "help" in options:
                    payload = {"form": document_form(Form_X509Certificate_mark)}
                    render_data(payload)
                    exit(0)
                try:
                    _dbX509Certificate = _get_X509Certificate()
                    _dbX509Certificate, _action = v_x509_certificate.submit__mark(
                        request,
                        dbX509Certificate=_dbX509Certificate,
                        acknowledge_transaction_commits=True,
                    )
                    render_data(
                        _dbX509Certificate.as_json,
                        success={"action": _action},
                    )
                    exit(0)
                except formhandling.FormInvalid as exc:
                    render_data(None, error=exc.formStash.errors)
                    exit(1)
