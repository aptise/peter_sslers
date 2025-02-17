# stdlib
from functools import wraps
from io import BytesIO  # noqa: F401
from io import StringIO  # noqa: F401
import json
import logging
import pdb  # noqa: F401
import pprint
import time
from typing import Dict
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING
import unittest
import zipfile

# pypi
import cert_utils
import packaging.version
import requests
import sqlalchemy
from typing_extensions import Literal
from webtest import Upload

# local
from peter_sslers.lib import errors as lib_errors
from peter_sslers.lib.db import actions as lib_db_actions
from peter_sslers.lib.db import actions_acme as lib_db_actions_acme
from peter_sslers.lib.db import get as lib_db_get
from peter_sslers.lib.db import update as lib_db_update
from peter_sslers.model import objects as model_objects
from peter_sslers.model import utils as model_utils
from . import _utils
from ._utils import AppTest
from ._utils import AppTestWSGI
from ._utils import generate_random_domain
from ._utils import generate_random_emailaddress
from ._utils import OPENRESTY_PLUGIN_MINIMUM
from ._utils import ResponseFailureOkay
from ._utils import RUN_API_TESTS__ACME_DNS_API
from ._utils import RUN_API_TESTS__EXTENDED
from ._utils import RUN_API_TESTS__PEBBLE
from ._utils import RUN_NGINX_TESTS
from ._utils import RUN_REDIS_TESTS
from ._utils import TEST_FILES
from ._utils import db_freeze
from ._utils import db_unfreeze
from ._utils import under_pebble
from ._utils import under_pebble_alt
from ._utils import under_pebble_strict
from ._utils import under_redis
from .regex_library import RE_AcmeAccount_deactivate_pending_post_required
from .regex_library import RE_AcmeAccount_deactivate_pending_success
from .regex_library import RE_AcmeAccount_new
from .regex_library import RE_AcmeAuthorization_deactivate_btn
from .regex_library import RE_AcmeAuthorization_deactivate_fail
from .regex_library import RE_AcmeAuthorization_deactivated
from .regex_library import RE_AcmeAuthorization_sync_btn
from .regex_library import RE_AcmeAuthorization_synced
from .regex_library import RE_AcmeChallenge_sync_btn
from .regex_library import RE_AcmeChallenge_synced
from .regex_library import RE_AcmeChallenge_trigger_btn
from .regex_library import RE_AcmeChallenge_trigger_fail
from .regex_library import RE_AcmeChallenge_triggered
from .regex_library import RE_AcmeDnsServer_checked
from .regex_library import RE_AcmeDnsServer_created
from .regex_library import RE_AcmeDnsServer_edited
from .regex_library import RE_AcmeDnsServer_ensure_domains_results
from .regex_library import RE_AcmeDnsServer_import_domain_existing
from .regex_library import RE_AcmeDnsServer_import_domain_success
from .regex_library import RE_AcmeDnsServer_marked_active
from .regex_library import RE_AcmeDnsServer_marked_global_default
from .regex_library import RE_AcmeDnsServer_marked_inactive
from .regex_library import RE_AcmeOrder
from .regex_library import RE_AcmeOrder_btn_acme_process__can
from .regex_library import RE_AcmeOrder_btn_deactive_authorizations
from .regex_library import RE_AcmeOrder_btn_deactive_authorizations__off
from .regex_library import RE_AcmeOrder_deactivated
from .regex_library import RE_AcmeOrder_downloaded_certificate
from .regex_library import RE_AcmeOrder_invalidated
from .regex_library import RE_AcmeOrder_invalidated_error
from .regex_library import RE_AcmeOrder_processed
from .regex_library import RE_AcmeOrder_renewal_configuration
from .regex_library import RE_AcmeOrder_retry
from .regex_library import RE_AcmeOrder_status
from .regex_library import RE_CertificateCA_uploaded
from .regex_library import RE_CertificateCAChain_uploaded
from .regex_library import RE_CertificateSigned_button
from .regex_library import RE_CertificateSigned_main
from .regex_library import RE_CertificateSigned_operation_nginx_expire
from .regex_library import RE_CertificateSigned_operation_nginx_expire__GET
from .regex_library import RE_CoverageAssuranceEvent_mark
from .regex_library import RE_CoverageAssuranceEvent_mark_nochange
from .regex_library import RE_Domain_new
from .regex_library import RE_Domain_new_AcmeDnsServerAccount
from .regex_library import RE_Domain_operation_nginx_expire
from .regex_library import RE_Domain_operation_nginx_expire__GET
from .regex_library import RE_RenewalConfiguration
from .regex_library import RE_RenewalConfiguration_link
from .regex_library import RE_UniqueFQDNSet_modify
from .regex_library import RE_UniqueFQDNSet_new


# ==============================================================================
#
# essentially disable logging for tests
#

log = logging.getLogger()
log.addHandler(logging.StreamHandler())
log.setLevel(logging.CRITICAL)


# ==============================================================================

_ROUTES_TESTED = {}


def routes_tested(*args):
    """
    `@routes_tested` is a decorator
    when writing/editing a test, declare what routes the test covers, like such:

        @routes_tested(("foo", "bar"))
        def test_foo_bar(self):
            ...

    this will populate a global variable `_ROUTES_TESTED` with the name of the
    tested routes.

    invoking the Audit test:

        python -m unittest tests.test_pyramid_app.FunctionalTests_AuditRoutes

    will ensure all routes in Pyramid have test coverage
    """
    _routes = args[0]
    if isinstance(_routes, (list, tuple)):
        for _r in _routes:
            _ROUTES_TESTED[_r] = True
    else:
        _ROUTES_TESTED[_routes] = True

    def _decorator(_function):
        @wraps(_function)
        def _wrapper(*args, **kwargs):
            return _function(*args, **kwargs)

        return _wrapper

    return _decorator


# =====


def do__AcmeServers_sync(
    testCase: unittest.TestCase,
) -> bool:
    # both exist after setup
    dbAcmeAccount_backup = lib_db_get.get__AcmeAccount__GlobalBackup(testCase.ctx)
    if not dbAcmeAccount_backup:
        raise ValueError("AcmeAccount__GlobalBackup not configured")
    dbAcmeAccount_default = lib_db_get.get__AcmeAccount__GlobalDefault(testCase.ctx)
    if not dbAcmeAccount_default:
        raise ValueError("AcmeAccount__GlobalDefault not configured")

    for _dbAcmeAccount in (dbAcmeAccount_backup, dbAcmeAccount_default):
        res = testCase.testapp.get(
            "/.well-known/peter_sslers/acme-server/%s" % _dbAcmeAccount.acme_server_id,
            status=200,
        )
        form = res.forms["form-check_support"]
        res2 = form.submit()
        assert res2.status_code == 303
        assert res2.location.endswith(
            "/.well-known/peter_sslers/acme-server/%s?result=success&operation=check-support&check-support=True"
            % _dbAcmeAccount.acme_server_id
        )

    return True


@routes_tested("admin:acme_account:new|json")
def make_one__AcmeAccount__random(
    testCase: unittest.TestCase,
) -> Tuple[model_objects.AcmeAccount, int]:
    """use the json api!"""
    form = {
        "acme_server_id": 1,
        "account__contact": generate_random_emailaddress(),
        "account__private_key_technology": "EC_P256",
        "account__order_default_private_key_cycle": "single_use",
        "account__order_default_private_key_technology": "EC_P256",
    }
    res4 = testCase.testapp.post(
        "/.well-known/peter_sslers/acme-account/new.json", form
    )
    assert res4.json["result"] == "success"
    assert "AcmeAccount" in res4.json
    focus_item = (
        testCase.ctx.dbSession.query(model_objects.AcmeAccount)
        .filter(model_objects.AcmeAccount.id == res4.json["AcmeAccount"]["id"])
        .filter(model_objects.AcmeAccount.is_active.is_(True))
        .filter(model_objects.AcmeAccount.acme_server_id == 1)
        .first()
    )
    assert focus_item is not None
    return (focus_item, focus_item.id)


@routes_tested("admin:acme_account:upload|json")
def make_one__AcmeAccount__pem(
    testCase: unittest.TestCase,
    account__contact: str,
    pem_file_name: str,
    expect_failure: bool = False,
) -> Tuple[model_objects.AcmeAccount, int]:
    """use the json api!"""
    form = {
        "account_key_option": "account_key_file",
        "account_key_file_pem": Upload(testCase._filepath_testfile(pem_file_name)),
        "acme_server_id": 1,
        "account__contact": account__contact,
        "account__order_default_private_key_cycle": "account_daily",
        "account__order_default_private_key_technology": "EC_P256",
    }
    res = testCase.testapp.post(
        "/.well-known/peter_sslers/acme-account/upload.json", form
    )
    if expect_failure:
        raise ResponseFailureOkay(res)

    assert res.json["result"] == "success"
    assert "AcmeAccount" in res.json
    focus_item = (
        testCase.ctx.dbSession.query(model_objects.AcmeAccount)
        .filter(model_objects.AcmeAccount.id == res.json["AcmeAccount"]["id"])
        .filter(model_objects.AcmeAccount.is_active.is_(True))
        .filter(model_objects.AcmeAccount.acme_server_id == 1)
        .first()
    )
    assert focus_item is not None
    return (focus_item, focus_item.id)


@routes_tested("admin:acme_order:new:freeform|json")
def make_one__AcmeOrder(
    testCase: unittest.TestCase,
    domain_names_http01: Optional[str] = None,
    domain_names_dns01: Optional[str] = None,
    account_key_option_backup: Optional[str] = None,
    acme_profile: Optional[str] = None,
    acme_profile__backup: Optional[str] = None,
    processing_strategy: Literal["create_order", "process_single"] = "create_order",
) -> model_objects.AcmeOrder:
    """use the json api!"""
    res = testCase.testapp.get(
        "/.well-known/peter_sslers/acme-order/new/freeform", status=200
    )
    form = res.form
    _form_fields = form.fields.keys()
    assert "account_key_option" in _form_fields
    form["account_key_option"].force_value("account_key_global_default")
    form["private_key_option"].force_value("account_default")
    form["private_key_cycle"].force_value("account_default")
    if domain_names_http01:
        form["domain_names_http01"] = domain_names_http01
    if domain_names_dns01:
        form["domain_names_dns01"] = domain_names_dns01
    if acme_profile:
        form["acme_profile"] = acme_profile
    if acme_profile__backup:
        form["acme_profile__backup"] = acme_profile__backup
    if account_key_option_backup:
        form["account_key_option_backup"].force_value(account_key_option_backup)
    form["processing_strategy"].force_value(processing_strategy)
    res2 = form.submit()
    assert res2.status_code == 303

    matched = RE_AcmeOrder.match(res2.location)
    assert matched
    obj_id = matched.groups()[0]

    dbAcmeOrder = testCase.ctx.dbSession.query(model_objects.AcmeOrder).get(obj_id)
    assert dbAcmeOrder
    return dbAcmeOrder


@routes_tested("admin:acme_order:new:freeform|json")
def make_one__AcmeOrder__random(
    testCase: unittest.TestCase,
) -> model_objects.AcmeOrder:
    """use the json api!"""
    domain_names_http01 = generate_random_domain(testCase=testCase)
    dbAcmeOrder = make_one__AcmeOrder(
        testCase=testCase, domain_names_http01=domain_names_http01
    )
    assert dbAcmeOrder
    return dbAcmeOrder


def make_one__DomainBlocklisted(
    testCase: unittest.TestCase,
    domain_name: str,
):
    dbDomainBlocklisted = model_objects.DomainBlocklisted()
    dbDomainBlocklisted.domain_name = domain_name
    testCase.ctx.dbSession.add(dbDomainBlocklisted)
    testCase.ctx.dbSession.flush(
        objects=[
            dbDomainBlocklisted,
        ]
    )
    testCase.ctx.pyramid_transaction_commit()
    return dbDomainBlocklisted


def make_one__RenewalConfiguration(
    testCase: unittest.TestCase,
    dbAcmeAccount: model_objects.AcmeAccount,
    domain_names_http01: str,
    private_key_cycle: Optional[str] = "account_default",
    key_technology: Optional[str] = "account_default",
) -> model_objects.AcmeOrder:
    """use the json api!"""
    res = testCase.testapp.get(
        "/.well-known/peter_sslers/renewal-configuration/new.json", status=200
    )
    assert "form_fields" in res.json

    form: Dict[str, Optional[str]] = {}
    form["account_key_option"] = "account_key_existing"
    form["account_key_existing"] = dbAcmeAccount.acme_account_key.key_pem_md5
    form["private_key_cycle"] = private_key_cycle
    form["key_technology"] = key_technology
    form["domain_names_http01"] = domain_names_http01

    res2 = testCase.testapp.post(
        "/.well-known/peter_sslers/renewal-configuration/new.json",
        form,
    )
    assert res2.json["result"] == "success"
    assert "RenewalConfiguration" in res2.json

    dbRenewalConfiguration = (
        testCase.ctx.dbSession.query(model_objects.RenewalConfiguration)
        .filter(
            model_objects.RenewalConfiguration.id
            == res2.json["RenewalConfiguration"]["id"]
        )
        .first()
    )
    assert dbRenewalConfiguration
    return dbRenewalConfiguration


def check_error_AcmeDnsServerError(response_type: Literal["html", "json"], response):
    message = "Error communicating with the acme-dns server."
    if response_type == "html":
        if response.status_code == 200:
            if message in response.text:
                raise lib_errors.AcmeDnsServerError()
    elif response_type == "json":
        if response.json["result"] == "error":
            if "form_errors" in response.json:
                if message in response.json["form_errors"]["Error_Main"]:
                    raise lib_errors.AcmeDnsServerError()
            elif "error" in response.json:
                if response.json["error"] == message:
                    raise lib_errors.AcmeDnsServerError()


# =====


def unset_testing_data(testCase: unittest.TestCase) -> Literal[True]:
    testCase.ctx.dbSession.commit()
    dbAcmeOrders = (
        testCase.ctx.dbSession.query(model_objects.AcmeOrder)
        .order_by(model_objects.AcmeOrder.id.asc())
        .filter(model_objects.AcmeOrder.is_processing.is_(True))
        .all()
    )
    for _dbAcmeOrder in dbAcmeOrders:
        result = lib_db_update.update_AcmeOrder_deactivate(testCase.ctx, _dbAcmeOrder)
    testCase.ctx.dbSession.commit()
    return True


def setup_testing_data(testCase: unittest.TestCase) -> Literal[True]:
    """
    This function is used to setup some of the testing data under pebble.

    Several routines require valid AcmeOrders, blocking authorizations, or
    live ari-check endpoints.  This is designed to build that data.
    """
    print("setup_testing_data")

    def _actual():
        if db_unfreeze(
            testCase.ctx.dbSession,
            "test_pyramid_app-setup_testing_data",
            testCase=testCase,
        ):
            print("setup_testing_data | using frozen database")
        else:
            print("setup_testing_data | creating new database records")
            _orders = []
            for i in range(0, 3):
                dbAcmeOrder = make_one__AcmeOrder__random(testCase)
                _orders.append(dbAcmeOrder)

            # This is all to generate a valid ARI Check
            # only 1 is needed
            for dbAcmeOrder in _orders:
                res = testCase.testapp.get(
                    "/.well-known/peter_sslers/acme-order/%s" % dbAcmeOrder.id,
                    status=200,
                )
                print(
                    "setup_testing_data: process res:", "form-acme_process" in res.forms
                )
                if "form-acme_process" in res.forms:
                    # the first acme_process should validate challenges
                    form = res.forms["form-acme_process"]
                    res2 = form.submit()
                    assert res2.status_code == 303
                    assert res2.location.endswith(
                        "?result=success&operation=acme+process"
                    )
                    res3 = testCase.testapp.get(res2.location, status=200)
                    print(
                        "setup_testing_data: process res3:",
                        "form-acme_process" in res3.forms,
                    )
                    if "form-acme_process" in res3.forms:
                        # the second form should finalize and download the cert
                        form = res3.forms["form-acme_process"]
                        res4 = form.submit()
                        assert res4.status_code == 303
                        assert res4.location.endswith(
                            "?result=success&operation=acme+process"
                        )
                        res5 = testCase.testapp.get(res4.location, status=200)
                        assert "certificate_downloaded" in res5.text
                        matched = RE_CertificateSigned_main.search(res5.text)
                        print(
                            "setup_testing_data: process res5:",
                            "form-acme_process" in res5.forms,
                        )
                        print("setup_testing_data: matched?", matched)
                        if matched:
                            certificate_id = matched.groups()[0]
                            res = testCase.testapp.get(
                                "/.well-known/peter_sslers/certificate-signed/%s"
                                % certificate_id,
                                status=200,
                            )
                            if "form-certificate_signed-ari_check" in res.forms:
                                form = res.forms["form-certificate_signed-ari_check"]
                                res2 = form.submit()
                                assert res2.status_code == 303
                                assert (
                                    "?result=success&operation=ari-check"
                                    in res2.location
                                )
                                # we just need one!
                                break

            db_freeze(testCase.ctx.dbSession, "test_pyramid_app-setup_testing_data")

    if _utils.PEBBLE_RUNNING:
        print("setup_testing_data | pebble already running, using that!")
        _actual()
    else:

        if not RUN_API_TESTS__PEBBLE:
            raise unittest.SkipTest("Not Running Against: Pebble API")

        @under_pebble
        def _wrapped():
            print("setup_testing_data | spun up a new pebble")
            _actual()

        _wrapped()

    print("setup_testing_data | finished")
    return True


# The following classes are only used when developing tests
# They are used to ensure the harnesses work correctly and to preload data
if False:

    class AAA_TestingSetup(AppTest):
        """
        python -m unittest tests.test_pyramid_app.AAA_TestingSetup
        this is only used to generate a testing database

        this should be used in conjunction with other tests that require it

        the "AAA_" prefix is to ensure this class runs first.
        """

        def test_setup_database(self):
            """
            this will freeze a database with some objects in it
            """
            setup_testing_data(self)

    class IntegratedTests_Explore(AppTest):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_Explore
        this is only used to test setup
        """

        @under_pebble_alt
        @under_pebble
        def test_passes(self):
            return True

    class FunctionalTests_Passes(AppTest):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_Passes
        this is only used to test setup
        """

        @under_pebble
        def test_passes(self):
            return True

        @under_pebble
        def test_passes_alt(self):
            return True

        @under_pebble
        def test_passes_alt_2(self):
            return True

        @under_pebble
        def test_passes_alt_3(self):
            return True


class FunctionalTests_Main(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_Main
    """

    @routes_tested("admin")
    def test_custom_headers(self):
        res = self.testapp.get("/.well-known/peter_sslers", status=200)
        assert res.headers["X-Peter-SSLers"] == "production"

    @routes_tested("admin")
    def test_root(self):
        res = self.testapp.get("/.well-known/peter_sslers", status=200)

    @routes_tested("admin:whoami")
    def test_admin_whoami(self):
        res = self.testapp.get("/.well-known/peter_sslers/whoami", status=200)

    @routes_tested("admin:help")
    def test_help(self):
        res = self.testapp.get("/.well-known/peter_sslers/help", status=200)

    @routes_tested("admin:settings")
    def test_settings(self):
        res = self.testapp.get("/.well-known/peter_sslers/settings", status=200)

    @routes_tested("admin:api")
    def test_api_docs(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_Main.test_api_docs
        """
        res = self.testapp.get("/.well-known/peter_sslers/api", status=200)

    @routes_tested(("admin:api:version", "admin:api:version|json"))
    def test_api_version(self):
        res = self.testapp.get("/.well-known/peter_sslers/api/version", status=200)
        res = self.testapp.get("/.well-known/peter_sslers/api/version.json", status=200)

    @routes_tested("admin:search")
    def test_search(self):
        res = self.testapp.get("/.well-known/peter_sslers/search", status=200)

    @routes_tested("public_whoami")
    def test_public_whoami(self):
        res = self.testapp.get("/.well-known/public/whoami", status=200)


class FunctionalTests_AcmeAccount(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeAccount
    """

    def _get_one(
        self, not_acme_server_id: Optional[int] = None
    ) -> Tuple[model_objects.AcmeAccount, int]:
        # grab a Key
        q_focus_item = (
            self.ctx.dbSession.query(model_objects.AcmeAccount)
            .filter(model_objects.AcmeAccount.is_active.is_(True))
            .filter(model_objects.AcmeAccount.is_global_default.is_not(True))
            .filter(model_objects.AcmeAccount.is_global_backup.is_not(True))
        )
        if not_acme_server_id:
            q_focus_item = q_focus_item.filter(
                model_objects.AcmeAccount.acme_server_id.is_not(not_acme_server_id)
            )
        q_focus_item = q_focus_item.order_by(model_objects.AcmeAccount.id.asc())
        focus_item = q_focus_item.first()
        assert focus_item is not None
        return focus_item, focus_item.id

    @routes_tested(("admin:acme_accounts", "admin:acme_accounts_paginated"))
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/peter_sslers/acme-accounts", status=200)
        # paginated
        res = self.testapp.get("/.well-known/peter_sslers/acme-accounts/1", status=200)

    @routes_tested(("admin:acme_accounts|json", "admin:acme_accounts_paginated|json"))
    def test_list_json(self):
        # json root
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-accounts.json", status=200
        )
        assert "AcmeAccounts" in res.json

        # json paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-accounts/1.json", status=200
        )
        assert "AcmeAccounts" in res.json

    @routes_tested(
        (
            "admin:acme_account:focus",
            "admin:acme_account:focus:acme_account_keys",
            "admin:acme_account:focus:acme_account_keys_paginated",
            "admin:acme_account:focus:acme_authorizations",
            "admin:acme_account:focus:acme_authorizations_paginated",
            "admin:acme_account:focus:acme_orders",
            "admin:acme_account:focus:acme_orders_paginated",
            "admin:acme_account:focus:private_keys",
            "admin:acme_account:focus:private_keys_paginated",
            "admin:acme_account:focus:certificate_signeds",
            "admin:acme_account:focus:certificate_signeds_paginated",
            "admin:acme_account:focus:renewal_configurations",
            "admin:acme_account:focus:renewal_configurations_paginated",
            "admin:acme_account:focus:renewal_configurations_backup",
            "admin:acme_account:focus:renewal_configurations_backup_paginated",
            "admin:acme_account:focus:terms_of_service",
            "admin:acme_account:focus:terms_of_service_paginated",
        )
    )
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-account-keys" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-account-keys/1" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-authorizations" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-authorizations/1"
            % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-orders" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-orders/1" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/private-keys" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/private-keys/1" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/certificate-signeds" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/certificate-signeds/1"
            % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/renewal-configurations"
            % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/renewal-configurations/1"
            % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/renewal-configurations-backup"
            % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/renewal-configurations-backup/1"
            % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/terms-of-service" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/terms-of-service/1" % focus_id,
            status=200,
        )

    @routes_tested(
        (
            "admin:acme_account:focus|json",
            "admin:acme_account:focus:parse|json",
            "admin:acme_account:focus:acme_account_keys|json",
            "admin:acme_account:focus:acme_account_keys_paginated|json",
            "admin:acme_account:focus:acme_authorizations|json",
            "admin:acme_account:focus:acme_authorizations_paginated|json",
        )
    )
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s.json" % focus_id, status=200
        )
        assert "AcmeAccount" in res.json
        assert res.json["AcmeAccount"]["id"] == focus_id

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/parse.json" % focus_id,
            status=200,
        )
        assert "AcmeAccount" in res.json
        assert res.json["AcmeAccount"]["id"] == focus_id
        assert "AcmeAccountKey" in res.json["AcmeAccount"]
        assert "id" in res.json["AcmeAccount"]["AcmeAccountKey"]

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-account-keys.json"
            % focus_id,
            status=200,
        )
        assert "AcmeAccountKeys" in res.json
        assert "pagination" in res.json

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-account-keys/1.json"
            % focus_id,
            status=200,
        )
        assert "AcmeAccountKeys" in res.json
        assert "pagination" in res.json

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-authorizations.json"
            % focus_id,
            status=200,
        )
        assert "AcmeAuthorizations" in res.json
        assert "pagination" in res.json

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-authorizations/1.json"
            % focus_id,
            status=200,
        )
        assert "AcmeAuthorizations" in res.json
        assert "pagination" in res.json

    @routes_tested("admin:acme_account:focus:raw")
    def test_focus_raw(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/key.key" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/key.pem" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/key.pem.txt" % focus_id,
            status=200,
        )

    @routes_tested(("admin:acme_account:focus:edit", "admin:acme_account:focus:mark"))
    def test_manipulate_html(self):
        (focus_item, focus_id) = self._get_one()
        (alt_focus_item, alt_focus_id) = self._get_one(
            not_acme_server_id=focus_item.acme_server_id
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/mark" % focus_id,
            status=303,
        )
        assert res.location.endswith("?result=error&error=post+required&operation=mark")

        if focus_item.is_global_backup:
            raise ValueError("this should not be the global backup")

        if focus_item.is_global_default:
            raise ValueError("this should not be the global default")

        if not focus_item.is_active:
            raise ValueError("this should be active")

        # fail making this active
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/mark" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 303
        assert res.location.endswith(
            "?result=error&error=Error_Main--There+was+an+error+with+your+form.+Already+activated.&operation=mark&action=active"
        )

        # inactive ROUNDTRIP
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/mark" % focus_id,
            {"action": "inactive"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=inactive")

        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/mark" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=active")

        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/mark" % focus_id,
            {"action": "global_default"},
        )
        assert res.status_code == 303
        assert res.location.endswith(
            "?result=success&operation=mark&action=global_default"
        )

        # edit nothing
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/edit" % focus_id, status=200
        )
        form = res.form
        res2 = form.submit()
        assert res2.status_code == 200
        assert "There was an error with your form. No edits submitted." in res2.text

        # edit it
        unique_name = generate_random_domain()
        # only the private_key_cycle and name
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/edit" % focus_id, status=200
        )
        form = res.form
        _existing = form["account__order_default_private_key_cycle"].value
        _new = None
        if _existing == "single_use":
            _new = "account_daily"
        else:
            _new = "single_use"
        form["account__order_default_private_key_cycle"] = _new
        form["name"] = unique_name
        res2 = form.submit()
        assert res2.status_code == 303
        assert (
            res2.location
            == """http://peter-sslers.example.com/.well-known/peter_sslers/acme-account/%s?result=success&operation=edit"""
            % focus_id
        )
        res3 = self.testapp.get(res2.location, status=200)
        assert unique_name in res3.text

        # edit the name

    @routes_tested(
        (
            "admin:acme_account:focus:edit|json",
            "admin:acme_account:focus:mark|json",
        )
    )
    def test_manipulate_json(self):
        (focus_item, focus_id) = self._get_one()
        (alt_focus_item, alt_focus_id) = self._get_one(
            not_acme_server_id=focus_item.acme_server_id
        )

        if focus_item.is_global_default:
            raise ValueError("this should not be the global default")

        if focus_item.is_global_backup:
            raise ValueError("this should not be the global backup")

        if not focus_item.is_active:
            raise ValueError("this should be active")

        # fail making this active
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/mark.json" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 200
        assert res.json["result"] == "error"
        assert (
            res.json["form_errors"]["Error_Main"]
            == "There was an error with your form. Already activated."
        )

        # inactive ROUNDTRIP
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/mark.json" % focus_id,
            {"action": "inactive"},
        )
        assert res.status_code == 200
        assert "AcmeAccount" in res.json
        assert res.json["AcmeAccount"]["id"] == focus_id
        assert res.json["AcmeAccount"]["is_active"] is False

        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/mark.json" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 200
        assert "AcmeAccount" in res.json
        assert res.json["AcmeAccount"]["id"] == focus_id
        assert res.json["AcmeAccount"]["is_active"] is True

        # then global_default
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/mark.json" % focus_id,
            {"action": "global_default"},
        )
        assert res.status_code == 200
        assert "AcmeAccount" in res.json
        assert res.json["AcmeAccount"]["id"] == focus_id
        assert res.json["AcmeAccount"]["is_global_default"] is True

        # trying to be global backup should fail
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/mark.json" % focus_id,
            {"action": "global_backup"},
        )
        assert res.status_code == 200
        assert res.json["result"] == "error"
        assert (
            res.json["form_errors"]["Error_Main"]
            == "There was an error with your form. Account is global default."
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/edit.json" % focus_id, status=200
        )
        assert "form_fields" in res.json

        # submit nothing
        form: Dict = {}
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/edit.json" % focus_id, form
        )
        assert res2.json["result"] == "error"
        assert "form_errors" in res2.json
        assert isinstance(res2.json["form_errors"], dict)
        assert len(res2.json["form_errors"]) == 1
        assert res2.json["form_errors"]["Error_Main"] == "Nothing submitted."

        # edit nothing
        form["name"] = focus_item.name or ""
        form["account__private_key_technology"] = focus_item.private_key_technology
        form["account__order_default_private_key_technology"] = (
            focus_item.order_default_private_key_technology
        )
        form["account__order_default_private_key_cycle"] = (
            focus_item.order_default_private_key_cycle
        )
        res3 = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/edit.json" % focus_id,
            form,
            status=200,
        )
        assert res3.status_code == 200
        assert "There was an error with your form. No edits submitted." in res3.text

        # Account:Edit has 4 items:
        # * name
        # * account__private_key_technology
        # * order_default_private_key_cycle
        # * account__order_default_private_key_technology

        unique_name = generate_random_domain()
        _existing_cycle = focus_item.order_default_private_key_cycle
        _new_cycle: str
        if _existing_cycle == "single_use":
            _new_cycle = "account_daily"
        else:
            _new_cycle = "single_use"
        form = {
            "account__private_key_technology": focus_item.private_key_technology,
            "account__order_default_private_key_cycle": _new_cycle,
            "name": unique_name,
        }
        res3 = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/edit.json" % focus_id, form
        )
        assert res3.json["result"] == "error"
        assert "form_errors" in res3.json
        assert isinstance(res3.json["form_errors"], dict)

        assert len(res3.json["form_errors"]) == 2
        assert (
            res3.json["form_errors"]["Error_Main"]
            == "There was an error with your form."
        )
        assert (
            res3.json["form_errors"]["account__order_default_private_key_technology"]
            == "Missing value"
        )

        form["account__order_default_private_key_technology"] = "RSA_2048"
        res4 = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/edit.json" % focus_id, form
        )
        assert res4.json["result"] == "success"
        assert "AcmeAccount" in res4.json
        assert res4.json["AcmeAccount"]["name"] == unique_name

    def test_post_required_json(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `acme-account/new.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/new.json", status=200
        )
        assert "form_fields" in res.json
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-account/upload.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/upload.json", status=200
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-account/%s/mark.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/mark.json" % focus_id,
            status=200,
        )
        assert "form_fields" in res.json
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-account/%s/acme-server/authenticate.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/authenticate.json"
            % focus_id,
            status=200,
        )
        assert res.location is None  # no redirect
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-account/%s/acme-server/check.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/check.json"
            % focus_id,
            status=200,
        )
        assert res.location is None  # no redirect
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]


class FunctionalTests_AcmeAuthorization(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeAuthorization
    """

    def _get_one(self):
        # grab an order
        focus_item = (
            self.ctx.dbSession.query(model_objects.AcmeAuthorization)
            .order_by(model_objects.AcmeAuthorization.id.asc())
            .first()
        )
        assert focus_item is not None
        return focus_item, focus_item.id

    @routes_tested(("admin:acme_authorizations", "admin:acme_authorizations_paginated"))
    def test_list_html(self):
        # root
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authorizations", status=200
        )
        # paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authorizations/1", status=200
        )

    @routes_tested(
        ("admin:acme_authorizations|json", "admin:acme_authorizations_paginated|json")
    )
    def test_list_json(self):
        # json root
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authorizations.json", status=200
        )
        assert "AcmeAuthorizations" in res.json
        # json paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authorizations/1.json", status=200
        )
        assert "AcmeAuthorizations" in res.json

    @routes_tested(
        (
            "admin:acme_authorization:focus",
            "admin:acme_authorization:focus:acme_orders",
            "admin:acme_authorization:focus:acme_orders_paginated",
            "admin:acme_authorization:focus:acme_challenges",
            "admin:acme_authorization:focus:acme_challenges_paginated",
        )
    )
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authorization/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authorization/%s/acme-orders" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authorization/%s/acme-orders/1" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authorization/%s/acme-challenges"
            % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authorization/%s/acme-challenges/1"
            % focus_id,
            status=200,
        )

    @routes_tested("admin:acme_authorization:focus|json")
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authorization/%s.json" % focus_id,
            status=200,
        )
        assert "AcmeAuthorization" in res.json
        assert res.json["AcmeAuthorization"]["id"] == focus_id

    def test_post_required_html(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `acme-authorization/%s/acme-server/sync`
        # "admin:acme_authorization:focus:sync"
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authorization/%s/acme-server/sync"
            % focus_id,
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/peter_sslers/acme-authorization/%s?result=error&operation=acme+server+sync&message=HTTP+POST+required"
            % focus_id
        )

        # note: removed `acme-authorization/%s/acme-server/trigger`

        # !!!: test `POST required` `acme-authorization/%s/acme-server/deactivate`
        # "admin:acme_authorization:focus:deactivate"
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authorization/%s/acme-server/deactivate"
            % focus_id,
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/acme-authorization/%s?result=error&operation=acme+server+deactivate&message=HTTP+POST+required"
            % focus_id
        )

    def test_post_required_json(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `acme-authorization/%s/acme-server/sync.json`
        # "admin:acme_authorization:focus:sync|json"
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authorization/%s/acme-server/sync.json"
            % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # note: removed `acme-authorization/%s/acme-server/trigger.json`

        # !!!: test `POST required` `acme-authorization/%s/acme-server/deactivate.json`
        # "admin:acme_authorization:focus:deactivate|json"
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authorization/%s/acme-server/deactivate.json"
            % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]


class FunctionalTests_AcmeAuthorizationPotential(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeAuthorizationPotential
    """

    def _ensure_one(self) -> model_objects.AcmeOrder:
        focus_item = (
            self.ctx.dbSession.query(model_objects.AcmeAuthorizationPotential)
            .order_by(model_objects.AcmeAuthorizationPotential.id.asc())
            .first()
        )
        if not focus_item:
            setup_testing_data(self)

        focus_item = (
            self.ctx.dbSession.query(model_objects.AcmeAuthorizationPotential)
            .order_by(model_objects.AcmeAuthorizationPotential.id.asc())
            .first()
        )
        assert focus_item is not None
        return focus_item

    def tearDown(self):
        unset_testing_data(self)
        AppTest.tearDown(self)

    @routes_tested(
        (
            "admin:acme_authorization_potentials",
            "admin:acme_authorization_potentials_paginated",
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authz-potentials", status=200
        )
        # paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authz-potentials/1", status=200
        )

    @routes_tested(
        (
            "admin:acme_authorization_potentials|json",
            "admin:acme_authorization_potentials_paginated|json",
        )
    )
    def test_list_json(self):
        # json root
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authz-potentials.json", status=200
        )
        assert "AcmeAuthorizationPotentials" in res.json
        # json paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authz-potentials/1.json", status=200
        )
        assert "AcmeAuthorizationPotentials" in res.json

    @routes_tested(("admin:acme_authorization_potential:focus",))
    def test_focus_html(self):
        focus_item = self._ensure_one()
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authz-potential/%s" % focus_item.id,
            status=200,
        )

    @routes_tested(("admin:acme_authorization_potential:focus|json",))
    def test_focus_json(self):
        focus_item = self._ensure_one()
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authz-potential/%s.json" % focus_item.id,
            status=200,
        )
        assert "AcmeAuthorizationPotential" in res.json
        assert res.json["AcmeAuthorizationPotential"]["id"] == focus_item.id

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_authorization_potential:focus",
            "admin:acme_authorization_potential:focus:delete",
        )
    )
    def test_manipulate_html(self):
        # ensure we have some here
        focus_item = self._ensure_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authz-potential/%s" % focus_item.id,
            status=200,
        )

        form = res.forms["form-acme_authz_potential-delete"]
        res2 = form.submit()
        res2.location

        assert res2.status_code == 303
        assert (
            res2.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/acme-authz-potentials?id=%s&result=success&operation=delete"
            % focus_item.id
        )

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_authorization_potential:focus|json",
            "admin:acme_authorization_potential:focus:delete|json",
        )
    )
    def test_manipulate_json(self):
        # ensure we have some here
        focus_item = self._ensure_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authz-potential/%s.json" % focus_item.id,
            status=200,
        )
        assert "AcmeAuthorizationPotential" in res.json
        assert res.json["AcmeAuthorizationPotential"]["id"] == focus_item.id

        res2 = self.testapp.get(
            "/.well-known/peter_sslers/acme-authz-potential/%s/delete.json"
            % focus_item.id,
            status=200,
        )
        assert "instructions" in res2.json
        assert "HTTP POST required" in res2.json["instructions"]

        res3 = self.testapp.post(
            "/.well-known/peter_sslers/acme-authz-potential/%s/delete.json"
            % focus_item.id,
            status=200,
        )
        assert "result" in res3.json
        assert res3.json["result"] == "success"
        assert res3.json["operation"] == "delete"
        assert "AcmeAuthorizationPotential" in res3.json
        assert res3.json["AcmeAuthorizationPotential"]["id"] == focus_item.id

    def test_post_required_html(self):
        focus_item = self._ensure_one()

        # !!!: test `POST required` `acme-authz-potential/%s/delete`
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authz-potential/%s/delete" % focus_item.id,
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/acme-authz-potential/%s?result=error&operation=delete&message=HTTP+POST+required"
            % focus_item.id
        )

    def test_post_required_json(self):
        focus_item = self._ensure_one()

        # !!!: test `POST required` `acme-authz-potential/%s/delete.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authz-potential/%s/delete.json"
            % focus_item.id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]


class FunctionalTests_AcmeChallenge(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeChallenge
    """

    def _get_one(self):
        # grab an order
        focus_item = (
            self.ctx.dbSession.query(model_objects.AcmeChallenge)
            .filter(
                model_objects.AcmeChallenge.challenge_url
                == "https://example.com/acme/chall/acmeOrder-1--authz-1--chall-1"
            )
            .one()
        )
        assert focus_item is not None
        return focus_item, focus_item.id

    @routes_tested(("admin:acme_challenges", "admin:acme_challenges_paginated"))
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/peter_sslers/acme-challenges", status=200)
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenges?status=active", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenges?status=resolved", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenges?status=processing", status=200
        )
        # paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenges/1", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenges/1?status=active", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenges/1?status=resolved", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenges/1?status=processing", status=200
        )

    @routes_tested(
        ("admin:acme_challenges|json", "admin:acme_challenges_paginated|json")
    )
    def test_list_json(self):
        # json root
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenges.json", status=200
        )
        assert "AcmeChallenges" in res.json
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenges.json?status=active", status=200
        )
        assert "AcmeChallenges" in res.json
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenges.json?status=resolved", status=200
        )
        assert "AcmeChallenges" in res.json
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenges.json?status=processing",
            status=200,
        )
        assert "AcmeChallenges" in res.json

        # json paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenges/1.json", status=200
        )
        assert "AcmeChallenges" in res.json
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenges/1.json?status=active", status=200
        )
        assert "AcmeChallenges" in res.json
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenges/1.json?status=resolved",
            status=200,
        )
        assert "AcmeChallenges" in res.json
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenges/1.json?status=processing",
            status=200,
        )
        assert "AcmeChallenges" in res.json

    @routes_tested(("admin:acme_challenge:focus"))
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenge/%s" % focus_id, status=200
        )

    @routes_tested(("admin:acme_challenge:focus|json"))
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenge/%s.json" % focus_id, status=200
        )
        assert "AcmeChallenge" in res.json
        assert res.json["AcmeChallenge"]["id"] == focus_id

    def test_post_required_html(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `acme-challenge/%s/acme-server/sync`
        # "admin:acme_challenge:focus:acme_server:sync",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenge/%s/acme-server/sync" % focus_id,
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/acme-challenge/%s?result=error&operation=acme+server+sync&message=HTTP+POST+required"
            % focus_id
        )

        # !!!: test `POST required` `acme-challenge/%s/acme-server/trigger`
        # "admin:acme_challenge:focus:acme_server:trigger",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenge/%s/acme-server/trigger"
            % focus_id,
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/acme-challenge/%s?result=error&operation=acme+server+trigger&message=HTTP+POST+required"
            % focus_id
        )

    def test_post_required_json(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `acme-challenge/%s/acme-server/sync.json`
        # "admin:acme_challenge:focus:acme_server:sync|json",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenge/%s/acme-server/sync.json"
            % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-challenge/%s/acme-server/trigger.json`
        # "admin:acme_challenge:focus:acme_server:trigger|json",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenge/%s/acme-server/trigger.json"
            % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

    @routes_tested(("public_challenge"))
    def test_public_challenge(self):
        (focus_item, focus_id) = self._get_one()
        token = focus_item.token
        keyauthorization = focus_item.keyauthorization

        _extra_environ = {
            "REMOTE_ADDR": "192.168.1.1",
        }
        resp_1 = self.testapp.get(
            "/.well-known/acme-challenge/%s" % token,
            extra_environ=_extra_environ,
            status=200,
        )
        # this is not on an active domain
        assert resp_1.text == "ERROR"

        _extra_environ_2 = {
            "REMOTE_ADDR": "192.168.1.1",
            "HTTP_HOST": "selfsigned-1.example.com",
        }
        resp_2 = self.testapp.get(
            "/.well-known/acme-challenge/%s" % token,
            extra_environ=_extra_environ_2,
            status=200,
        )
        assert resp_2.text == keyauthorization


class FunctionalTests_AcmeChallengePolls(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeChallengePolls
    """

    @routes_tested(
        ("admin:acme_challenge_polls", "admin:acme_challenge_polls_paginated")
    )
    def test_list_html(self):
        # root
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenge-polls", status=200
        )
        # paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenge-polls/1", status=200
        )

    @routes_tested(
        ("admin:acme_challenge_polls|json", "admin:acme_challenge_polls_paginated|json")
    )
    def test_list_json(self):
        # json paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenge-polls/1.json", status=200
        )
        assert "AcmeChallengePolls" in res.json

        # json paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenge-polls/1.json", status=200
        )
        assert "AcmeChallengePolls" in res.json
        assert "pagination" in res.json
        assert res.json["pagination"]["total_items"] >= 1


class FunctionalTests_AcmeChallengeUnknownPolls(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeChallengeUnknownPolls
    """

    @routes_tested(
        (
            "admin:acme_challenge_unknown_polls",
            "admin:acme_challenge_unknown_polls_paginated",
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenge-unknown-polls", status=200
        )
        # paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenge-unknown-polls/1", status=200
        )

    @routes_tested(
        (
            "admin:acme_challenge_unknown_polls|json",
            "admin:acme_challenge_unknown_polls_paginated|json",
        )
    )
    def test_list_json(self):
        # json paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenge-unknown-polls/1.json", status=200
        )
        assert "AcmeChallengeUnknownPolls" in res.json

        # json paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenge-unknown-polls/1.json", status=200
        )
        assert "AcmeChallengeUnknownPolls" in res.json
        assert "pagination" in res.json
        assert res.json["pagination"]["total_items"] >= 1


class FunctionalTests_AcmeDnsServer(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeDnsServer
    """

    def _acme_dns_support(self) -> Optional[str]:
        return self.testapp.app.registry.settings["application_settings"][
            "acme_dns_support"
        ]

    def _get_one(self, id_not=None):
        # grab an order
        q = self.ctx.dbSession.query(model_objects.AcmeDnsServer)
        if id_not:
            q = q.filter(model_objects.AcmeDnsServer.id != id_not)
        focus_item = q.order_by(model_objects.AcmeDnsServer.id.asc()).first()
        assert focus_item is not None
        return focus_item, focus_item.id

    @routes_tested(("admin:acme_dns_servers", "admin:acme_dns_servers_paginated"))
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/peter_sslers/acme-dns-servers", status=200)
        # paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-dns-servers/1", status=200
        )

    @routes_tested(
        ("admin:acme_dns_servers|json", "admin:acme_dns_servers_paginated|json")
    )
    def test_list_json(self):
        # json root
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-dns-servers.json", status=200
        )
        assert "AcmeDnsServers" in res.json
        # json paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-dns-servers/1.json", status=200
        )
        assert "AcmeDnsServers" in res.json

    @routes_tested(
        (
            "admin:acme_dns_server:focus",
            "admin:acme_dns_server:focus:acme_dns_server_accounts",
            "admin:acme_dns_server:focus:acme_dns_server_accounts_paginated",
        )
    )
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-dns-server/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-dns-server/%s/acme-dns-server-accounts"
            % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-dns-server/%s/acme-dns-server-accounts/1"
            % focus_id,
            status=200,
        )

    @routes_tested(
        (
            "admin:acme_dns_server:focus|json",
            "admin:acme_dns_server:focus:acme_dns_server_accounts|json",
            "admin:acme_dns_server:focus:acme_dns_server_accounts_paginated|json",
        )
    )
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-dns-server/%s.json" % focus_id, status=200
        )
        assert "AcmeDnsServer" in res.json
        assert res.json["AcmeDnsServer"]["id"] == focus_id

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-dns-server/%s/acme-dns-server-accounts.json"
            % focus_id,
            status=200,
        )
        assert "AcmeDnsServer" in res.json
        assert res.json["AcmeDnsServer"]["id"] == focus_id
        assert "AcmeDnsServerAccounts" in res.json

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-dns-server/%s/acme-dns-server-accounts/1.json"
            % focus_id,
            status=200,
        )
        assert "AcmeDnsServer" in res.json
        assert res.json["AcmeDnsServer"]["id"] == focus_id
        assert "AcmeDnsServerAccounts" in res.json

    @routes_tested(
        (
            "admin:acme_dns_server:focus",
            "admin:acme_dns_server:focus:mark",
            "admin:acme_dns_server:focus:edit",
        )
    )
    def test_manipulate_html(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeDnsServer.test_manipulate_html
        """

        def _make_global_default(_item_id):
            res = self.testapp.get(
                "/.well-known/peter_sslers/acme-dns-server/%s" % _item_id, status=200
            )
            assert "set Global Default" in res.text
            assert "form-mark-global_default" in res.forms
            form = res.forms["form-mark-global_default"]
            res2 = form.submit()
            assert res2.status_code == 303
            assert RE_AcmeDnsServer_marked_global_default.match(res2.location)

        def _make_inactive(_item_id):
            res = self.testapp.get(
                "/.well-known/peter_sslers/acme-dns-server/%s" % _item_id, status=200
            )
            assert "Deactivate" in res.text
            assert "form-mark-inactive" in res.forms
            form = res.forms["form-mark-inactive"]
            res2 = form.submit()
            assert res2.status_code == 303
            assert RE_AcmeDnsServer_marked_inactive.match(res2.location)

        def _make_active(_item_id):
            res = self.testapp.get(
                "/.well-known/peter_sslers/acme-dns-server/%s" % _item_id, status=200
            )
            assert "set Global Default" not in res.text
            assert "Activate" in res.text
            assert "form-mark-active" in res.forms
            form = res.forms["form-mark-active"]
            res2 = form.submit()
            assert res2.status_code == 303
            assert RE_AcmeDnsServer_marked_active.match(res2.location)

        def _edit_url(_item_id, _root_url, expect_failure_nochange=None):
            res = self.testapp.get(
                "/.well-known/peter_sslers/acme-dns-server/%s" % _item_id, status=200
            )
            assert ("/acme-dns-server/%s/edit" % _item_id) in res.text
            res = self.testapp.get(
                "/.well-known/peter_sslers/acme-dns-server/%s/edit" % _item_id,
                status=200,
            )
            assert "form-edit" in res.forms
            form = res.forms["form-edit"]
            form["root_url"] = _root_url
            res2 = form.submit()

            if expect_failure_nochange:
                assert res2.status_code == 200
                assert "There was an error with your form. No change" in res2.text
            else:
                assert res2.status_code == 303
                assert RE_AcmeDnsServer_edited.match(res2.location)

        def _ensure_domains(_item_id: int):
            # ensure-domains
            # use ._get_one() so the real server is used
            res = self.testapp.get(
                "/.well-known/peter_sslers/acme-dns-server/%s/ensure-domains"
                % _item_id,
                status=200,
            )
            assert "form-acme_dns_server-ensure_domains" in res.forms
            form = res.forms["form-acme_dns_server-ensure_domains"]
            res2 = form.submit()
            assert res2.status_code == 200
            assert (
                """<!-- for: domain_names -->\n<div class="alert alert-danger"><div class="control-group error"><span class="help-inline">Please enter a value</span></div></div>"""
                in res2.text
            )
            form["domain_names"] = TEST_FILES["Domains"]["AcmeDnsServer"]["1"][
                "ensure-domains.html"
            ]
            res2 = form.submit()
            check_error_AcmeDnsServerError("html", res2)
            assert RE_AcmeDnsServer_ensure_domains_results.match(res2.location)

            # import_domain
            # use ._get_one() so the real server is used
            res = self.testapp.get(
                "/.well-known/peter_sslers/acme-dns-server/%s/import-domain" % _item_id,
                status=200,
            )
            assert "form-acme_dns_server-import_domain" in res.forms
            form = res.forms["form-acme_dns_server-import_domain"]
            res2 = form.submit()
            assert res2.status_code == 200
            assert (
                """<!-- for: domain_name -->\n<div class="alert alert-danger"><div class="control-group error"><span class="help-inline">Please enter a value</span></div></div>"""
                in res2.text
            )
            _intended_payload = TEST_FILES["Domains"]["AcmeDnsServer"]["1"][
                "import-domain.html"
            ]["payload"]
            _fields = [i[0] for i in form.submit_fields()]
            for k in _intended_payload.keys():
                assert k in _fields
                form[k] = _intended_payload[k]
            res2 = form.submit()
            assert res2.status_code == 303
            assert RE_AcmeDnsServer_import_domain_success.match(res2.location)

            # submit this again, and we should go to existing!
            res3 = form.submit()
            assert res3.status_code == 303
            assert RE_AcmeDnsServer_import_domain_existing.match(res3.location)

        # ok our tests!
        _acme_dns_support = self.testapp.app.registry.settings["application_settings"][
            "acme_dns_support"
        ]
        _SUPPORT_ALT = True if _acme_dns_support == "extended" else False
        focus_item: model_objects.AcmeDnsServer
        focus_id: int
        alt_item: model_objects.AcmeDnsServer
        alt_id: int

        # obj 1
        (focus_item, focus_id) = self._get_one()

        if _SUPPORT_ALT:
            # obj 2
            (alt_item, alt_id) = self._get_one(id_not=focus_id)

        # test mark: global_default
        if _SUPPORT_ALT:
            if not focus_item.is_global_default:
                _make_global_default(focus_id)
                _make_global_default(alt_id)
            else:
                _make_global_default(alt_id)

            # expire these items!
            self.ctx.dbSession.expire(focus_item)
            self.ctx.dbSession.expire(alt_item)

            # test mark: inactive
            # the focus item is NOT the global default, so can be turned off
            _make_inactive(focus_id)

            # test mark: active
            # the focus item is NOT the global default, so can be turned and back on
            _make_active(focus_id)

        # test: edit
        url_og = focus_item.root_url

        # fail editing the url
        _edit_url(focus_id, url_og, expect_failure_nochange=True)

        # make the url silly, then make it real
        _edit_url(focus_id, url_og + "123")
        _edit_url(focus_id, url_og)

        # ensure domains
        _ensure_domains(focus_id)

    @routes_tested(
        (
            "admin:acme_dns_server:focus|json",
            "admin:acme_dns_server:focus:mark|json",
            "admin:acme_dns_server:focus:edit|json",
        )
    )
    def test_manipulate_json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeDnsServer.test_manipulate_json
        """

        def _make_global_default(_item_id):
            res = self.testapp.get(
                "/.well-known/peter_sslers/acme-dns-server/%s.json" % _item_id,
                status=200,
            )
            assert "AcmeDnsServer" in res.json
            assert res.json["AcmeDnsServer"]["id"] == _item_id
            assert res.json["AcmeDnsServer"]["is_global_default"] is False

            res2 = self.testapp.get(
                "/.well-known/peter_sslers/acme-dns-server/%s/mark.json" % _item_id,
                status=200,
            )
            assert "instructions" in res2.json

            res3 = self.testapp.post(
                "/.well-known/peter_sslers/acme-dns-server/%s/mark.json" % _item_id,
                {},
                status=200,
            )
            assert res3.json["result"] == "error"
            assert "form_errors" in res3.json
            assert res3.json["form_errors"]["Error_Main"] == "Nothing submitted."

            res4 = self.testapp.post(
                "/.well-known/peter_sslers/acme-dns-server/%s/mark.json" % _item_id,
                {"action": "global_default"},
                status=200,
            )
            assert res4.json["result"] == "success"
            assert "AcmeDnsServer" in res4.json
            assert res4.json["AcmeDnsServer"]["is_global_default"] is True

        def _make_inactive(_item_id):
            res = self.testapp.get(
                "/.well-known/peter_sslers/acme-dns-server/%s.json" % _item_id,
                status=200,
            )
            assert "AcmeDnsServer" in res.json
            assert res.json["AcmeDnsServer"]["id"] == _item_id
            assert res.json["AcmeDnsServer"]["is_active"] is True

            res2 = self.testapp.get(
                "/.well-known/peter_sslers/acme-dns-server/%s/mark.json" % _item_id,
                status=200,
            )
            assert "instructions" in res2.json

            res3 = self.testapp.post(
                "/.well-known/peter_sslers/acme-dns-server/%s/mark.json" % _item_id,
                {},
                status=200,
            )
            assert res3.json["result"] == "error"
            assert "form_errors" in res3.json
            assert res3.json["form_errors"]["Error_Main"] == "Nothing submitted."

            res4 = self.testapp.post(
                "/.well-known/peter_sslers/acme-dns-server/%s/mark.json" % _item_id,
                {"action": "inactive"},
                status=200,
            )
            assert res4.json["result"] == "success"
            assert "AcmeDnsServer" in res4.json
            assert res4.json["AcmeDnsServer"]["is_active"] is False

        def _make_active(_item_id):
            res = self.testapp.get(
                "/.well-known/peter_sslers/acme-dns-server/%s.json" % _item_id,
                status=200,
            )
            assert "AcmeDnsServer" in res.json
            assert res.json["AcmeDnsServer"]["id"] == _item_id
            assert res.json["AcmeDnsServer"]["is_active"] is False

            res2 = self.testapp.get(
                "/.well-known/peter_sslers/acme-dns-server/%s/mark.json" % _item_id,
                status=200,
            )
            assert "instructions" in res2.json

            res3 = self.testapp.post(
                "/.well-known/peter_sslers/acme-dns-server/%s/mark.json" % _item_id,
                {},
                status=200,
            )
            assert res3.json["result"] == "error"
            assert "form_errors" in res3.json
            assert res3.json["form_errors"]["Error_Main"] == "Nothing submitted."

            res4 = self.testapp.post(
                "/.well-known/peter_sslers/acme-dns-server/%s/mark.json" % _item_id,
                {"action": "active"},
                status=200,
            )
            assert res4.json["result"] == "success"
            assert "AcmeDnsServer" in res4.json
            assert res4.json["AcmeDnsServer"]["is_active"] is True

        def _edit_url(_item_id, _root_url, expect_failure_nochange=False):
            res = self.testapp.get(
                "/.well-known/peter_sslers/acme-dns-server/%s.json" % _item_id,
                status=200,
            )
            assert res.json["AcmeDnsServer"]["id"] == _item_id
            assert "AcmeDnsServer" in res.json

            res2 = self.testapp.get(
                "/.well-known/peter_sslers/acme-dns-server/%s/edit.json" % _item_id,
                status=200,
            )
            assert "instructions" in res2.json

            res3 = self.testapp.post(
                "/.well-known/peter_sslers/acme-dns-server/%s/edit.json" % _item_id,
                {},
                status=200,
            )
            assert res3.json["result"] == "error"
            assert "form_errors" in res3.json
            assert res3.json["form_errors"]["Error_Main"] == "Nothing submitted."

            if not expect_failure_nochange:
                res4 = self.testapp.post(
                    "/.well-known/peter_sslers/acme-dns-server/%s/edit.json" % _item_id,
                    {"root_url": _root_url},
                    status=200,
                )
                assert res4.json["result"] == "success"
                assert "AcmeDnsServer" in res4.json
                assert res4.json["AcmeDnsServer"]["root_url"] == _root_url
            else:
                res4 = self.testapp.post(
                    "/.well-known/peter_sslers/acme-dns-server/%s/edit.json" % _item_id,
                    {"root_url": _root_url},
                    status=200,
                )
                assert res4.json["result"] == "error"
                assert "form_errors" in res4.json
                assert (
                    res4.json["form_errors"]["Error_Main"]
                    == "There was an error with your form. No change"
                )

        def _ensure_domains(_item_id: int):

            # ensure-domains
            # use ._get_one() so the real server is used
            # (focus_item, focus_id) = self._get_one()
            res = self.testapp.get(
                "/.well-known/peter_sslers/acme-dns-server/%s/ensure-domains.json"
                % _item_id,
                status=200,
            )
            assert "domain_names" in res.json["form_fields"]

            res = self.testapp.post(
                "/.well-known/peter_sslers/acme-dns-server/%s/ensure-domains.json"
                % _item_id,
                status=200,
            )
            assert res.json["result"] == "error"
            assert "form_errors" in res.json
            assert res.json["form_errors"]["Error_Main"] == "Nothing submitted."

            _payload = {
                "domain_names": TEST_FILES["Domains"]["AcmeDnsServer"]["1"][
                    "ensure-domains.json"
                ]
            }
            res = self.testapp.post(
                "/.well-known/peter_sslers/acme-dns-server/%s/ensure-domains.json"
                % _item_id,
                _payload,
                status=200,
            )
            check_error_AcmeDnsServerError("json", res)
            assert res.json["result"] == "success"
            assert "result_matrix" in res.json

            _account_ids = [
                "%s" % res.json["result_matrix"][_domain]["AcmeDnsServerAccount"]["id"]
                for _domain in res.json["result_matrix"].keys()
            ]
            res = self.testapp.get(
                "/.well-known/peter_sslers/acme-dns-server/%s/ensure-domains-results.json?acme-dns-server-accounts=%s"
                % (_item_id, ",".join(_account_ids))
            )
            assert res.json["result"] == "success"
            assert "result_matrix" in res.json

            # import-domain
            # use ._get_one() so the real server is used
            res = self.testapp.get(
                "/.well-known/peter_sslers/acme-dns-server/%s/import-domain.json"
                % _item_id,
                status=200,
            )
            _intended_payload = TEST_FILES["Domains"]["AcmeDnsServer"]["1"][
                "import-domain.json"
            ]["payload"]
            for k in _intended_payload.keys():
                assert k in res.json["form_fields"]

            res = self.testapp.post(
                "/.well-known/peter_sslers/acme-dns-server/%s/import-domain.json"
                % _item_id,
                status=200,
            )
            assert res.json["result"] == "error"
            assert "form_errors" in res.json
            assert res.json["form_errors"]["Error_Main"] == "Nothing submitted."

            res = self.testapp.post(
                "/.well-known/peter_sslers/acme-dns-server/%s/import-domain.json"
                % _item_id,
                _intended_payload,
                status=200,
            )
            assert res.json["result"] == "success"
            assert "result_matrix" in res.json
            assert _intended_payload["domain_name"] in res.json["result_matrix"]
            assert (
                res.json["result_matrix"][_intended_payload["domain_name"]]["result"]
                == "success"
            )

            # submit this again, and we should go to existing!
            res = self.testapp.post(
                "/.well-known/peter_sslers/acme-dns-server/%s/import-domain.json"
                % _item_id,
                _intended_payload,
                status=200,
            )
            assert res.json["result"] == "success"
            assert "result_matrix" in res.json
            assert _intended_payload["domain_name"] in res.json["result_matrix"]
            assert (
                res.json["result_matrix"][_intended_payload["domain_name"]]["result"]
                == "existing"
            )

        # ok our tests!
        _acme_dns_support = self.testapp.app.registry.settings["application_settings"][
            "acme_dns_support"
        ]
        _SUPPORT_ALT = True if _acme_dns_support == "extended" else False
        focus_item: model_objects.AcmeDnsServer
        focus_id: int
        alt_item: model_objects.AcmeDnsServer
        alt_id: int

        # obj 1
        (focus_item, focus_id) = self._get_one()

        if _SUPPORT_ALT:
            # obj 2
            (alt_item, alt_id) = self._get_one(id_not=focus_id)

        # test mark: global_default
        if _SUPPORT_ALT:
            if not focus_item.is_global_default:
                _make_global_default(focus_id)
                _make_global_default(alt_id)
            else:
                _make_global_default(alt_id)

            # expire these items!
            self.ctx.dbSession.expire(focus_item)
            self.ctx.dbSession.expire(alt_item)

            # test mark: inactive
            # the focus item is NOT the global default, so can be turned off
            _make_inactive(focus_id)

            # test mark: active
            # the focus item is NOT the global default, so can be turned and back on
            _make_active(focus_id)

        # test: edit
        url_og = focus_item.root_url

        # fail editing the url
        _edit_url(focus_id, url_og, expect_failure_nochange=True)

        # make the url silly, then make it real
        _edit_url(focus_id, url_og + "123")
        _edit_url(focus_id, url_og)

        # ensure_domains
        _ensure_domains(focus_id)

    @unittest.skipUnless(RUN_API_TESTS__ACME_DNS_API, "Not Running Against: acme-dns")
    @routes_tested(("admin:acme_dns_server:focus:check",))
    def test_against_acme_dns__html(self):
        (focus_item, focus_id) = self._get_one()
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-dns-server/%s" % focus_id, status=200
        )
        assert "form-check" in res.forms
        form = res.forms["form-check"]
        res = form.submit()
        assert res.status_code == 303
        if res.location.endswith("?result=error&operation=check"):
            raise lib_errors.AcmeDnsServerError()
        assert RE_AcmeDnsServer_checked.match(res.location)

    @unittest.skipUnless(RUN_API_TESTS__ACME_DNS_API, "Not Running Against: acme-dns")
    @routes_tested(("admin:acme_dns_server:focus:check|json",))
    def test_against_acme_dns__json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-dns-server/%s/check.json" % focus_id,
            {},
            status=200,
        )
        check_error_AcmeDnsServerError("json", res)
        assert res.json["result"] == "success"
        assert res.json["health"] is True

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @unittest.skipUnless(RUN_API_TESTS__ACME_DNS_API, "Not Running Against: acme-dns")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_dns_server:new",
            "admin:acme_dns_server:focus:ensure_domains",
            "admin:acme_dns_server:focus:ensure_domains_results",
            "admin:acme_dns_server:focus:import_domain",
        )
    )
    def test_new_html(self):
        """
        python -munittest tests.test_pyramid_app.FunctionalTests_AcmeDnsServer.test_new_html
        """
        if self._acme_dns_support != "experimental":
            res = self.testapp.get(
                "/.well-known/peter_sslers/acme-dns-server/new", status=303
            )
            assert res.location.endswith(
                "/.well-known/peter_sslers/acme-dns-servers?error=only-one-server-supported"
            )

            return

        # experimental

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-dns-server/new", status=200
        )
        form = res.form
        form["root_url"] = TEST_FILES["AcmeDnsServer"]["3"]["root_url"]
        res2 = form.submit()

        matched = RE_AcmeDnsServer_created.match(res2.location)
        assert matched
        obj_id = matched.groups()[0]

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-dns-server/%s" % obj_id, status=200
        )

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @unittest.skipUnless(RUN_API_TESTS__ACME_DNS_API, "Not Running Against: acme-dns")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_dns_server:new|json",
            "admin:acme_dns_server:focus:ensure_domains|json",
            "admin:acme_dns_server:focus:ensure_domains_results|json",
            "admin:acme_dns_server:focus:import_domain|json",
        )
    )
    def test_new_json(self):

        if self._acme_dns_support != "experimental":

            res = self.testapp.post(
                "/.well-known/peter_sslers/acme-dns-server/new.json", {}, status=303
            )
            assert res.location.endswith(
                "/.well-known/peter_sslers/acme-dns-servers?error=only-one-server-supported"
            )
            return

        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-dns-server/new.json", {}, status=200
        )
        assert res.json["result"] == "error"
        assert "form_errors" in res.json
        assert res.json["form_errors"]["Error_Main"] == "Nothing submitted."

        _payload = {"root_url": TEST_FILES["AcmeDnsServer"]["4"]["root_url"]}
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-dns-server/new.json", _payload, status=200
        )
        assert res.json["result"] == "success"
        assert res.json["is_created"] is True
        assert "AcmeDnsServer" in res.json

        obj_id = res.json["AcmeDnsServer"]["id"]

    def test_post_required_json(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `acme-dns-server/%s/check.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-dns-server/%s/check.json" % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        if self._acme_dns_support == "experimental":
            # !!!: test `POST required` `acme-dns-server/new.json`
            res = self.testapp.get(
                "/.well-known/peter_sslers/acme-dns-server/new.json", status=200
            )
            assert "instructions" in res.json
            assert "HTTP POST required" in res.json["instructions"]


class FunctionalTests_AcmeDnsServerAccount(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeDnsServerAccount
    """

    def _get_one(self):
        # grab an order
        focus_item = (
            self.ctx.dbSession.query(model_objects.AcmeDnsServerAccount)
            .order_by(model_objects.AcmeDnsServerAccount.id.asc())
            .first()
        )
        assert focus_item is not None
        return focus_item, focus_item.id

    @routes_tested(
        ("admin:acme_dns_server_accounts", "admin:acme_dns_server_accounts_paginated")
    )
    def test_list_html(self):
        # root
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-dns-server-accounts", status=200
        )
        # paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-dns-server-accounts/1", status=200
        )

    @routes_tested(
        (
            "admin:acme_dns_server_accounts|json",
            "admin:acme_dns_server_accounts_paginated|json",
        )
    )
    def test_list_json(self):
        # json root
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-dns-server-accounts.json", status=200
        )
        assert "AcmeDnsServerAccounts" in res.json
        # json paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-dns-server-accounts/1.json", status=200
        )
        assert "AcmeDnsServerAccounts" in res.json

    @routes_tested(("admin:acme_dns_server_account:focus",))
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-dns-server-account/%s" % focus_id,
            status=200,
        )

    @routes_tested(("admin:acme_dns_server_account:focus|json",))
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-dns-server-account/%s.json" % focus_id,
            status=200,
        )
        assert "AcmeDnsServerAccount" in res.json
        assert res.json["AcmeDnsServerAccount"]["id"] == focus_item.id


class FunctionalTests_AcmeEventLog(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeEventLog
    """

    def _get_one(self):
        # grab an event
        focus_item = self.ctx.dbSession.query(model_objects.AcmeEventLog).first()
        assert focus_item is not None
        return focus_item, focus_item.id

    @routes_tested(("admin:acme_event_log", "admin:acme_event_log_paginated"))
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/peter_sslers/acme-event-logs", status=200)
        # paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-event-logs/1", status=200
        )

    @routes_tested(("admin:acme_event_log|json", "admin:acme_event_log_paginated|json"))
    def test_list_json(self):
        # json root
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-event-logs.json", status=200
        )
        assert "AcmeEventLogs" in res.json
        # json paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-event-logs/1.json", status=200
        )
        assert "AcmeEventLogs" in res.json

    @routes_tested(("admin:acme_event_log:focus"))
    def test_focus_html(self):
        """
        AcmeEventLog entries are normally only created when hitting the ACME Server
        BUT
        We faked one when creating a new AcmeOrder in the setup routine
        """
        # focus
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-event-log/%s" % focus_id, status=200
        )

    @routes_tested(("admin:acme_event_log:focus|json"))
    def test_focus_json(self):
        """
        AcmeEventLog entries are normally only created when hitting the ACME Server
        BUT
        We faked one when creating a new AcmeOrder in the setup routine
        """
        # focus
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-event-log/%s.json" % focus_id, status=200
        )
        assert "AcmeEventLog" in res.json
        assert res.json["AcmeEventLog"]["id"] == focus_id


class FunctionalTests_AcmeOrder(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeOrder
    """

    def _get_one(self):
        # grab an order
        focus_item = (
            self.ctx.dbSession.query(model_objects.AcmeOrder)
            .order_by(model_objects.AcmeOrder.id.asc())
            .first()
        )
        assert focus_item is not None
        return focus_item, focus_item.id

    @routes_tested(
        (
            "admin:acme_orders",
            "admin:acme_orders:all",
            "admin:acme_orders:all_paginated",
            "admin:acme_orders:active",
            "admin:acme_orders:active_paginated",
            "admin:acme_orders:finished",
            "admin:acme_orders:finished_paginated",
        )
    )
    def test_list_html(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeOrder.test_list_html
        """
        # root
        res = self.testapp.get("/.well-known/peter_sslers/acme-orders", status=303)
        assert (
            res.location
            == """http://peter-sslers.example.com/.well-known/peter_sslers/acme-orders/active"""
        )

        for _type in (
            "all",
            "active",
            "finished",
        ):
            res = self.testapp.get(
                "/.well-known/peter_sslers/acme-orders/%s" % _type, status=200
            )
            res = self.testapp.get(
                "/.well-known/peter_sslers/acme-orders/%s/1" % _type, status=200
            )

    @routes_tested(
        (
            "admin:acme_orders|json",
            "admin:acme_orders:all|json",
            "admin:acme_orders:all_paginated|json",
            "admin:acme_orders:active|json",
            "admin:acme_orders:active_paginated|json",
            "admin:acme_orders:finished|json",
            "admin:acme_orders:finished_paginated|json",
        )
    )
    def test_list_json(self):
        # json root
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeOrder.test_list_json
        """
        res = self.testapp.get("/.well-known/peter_sslers/acme-orders.json", status=303)
        assert (
            res.location
            == """http://peter-sslers.example.com/.well-known/peter_sslers/acme-orders/active.json"""
        )

        for _type in (
            "all",
            "active",
            "finished",
        ):
            res = self.testapp.get(
                "/.well-known/peter_sslers/acme-orders/%s.json" % _type, status=200
            )
            assert "AcmeOrders" in res.json
            res = self.testapp.get(
                "/.well-known/peter_sslers/acme-orders/%s/1.json" % _type, status=200
            )
            assert "AcmeOrders" in res.json

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(("admin:acme_orders:active:acme_server:sync",))
    def test_active_acme_server_sync_html(self):
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-orders/active/acme-server/sync", status=303
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/peter_sslers/acme-orders/active?result=error&operation=acme+server+sync&message=HTTP+POST+required"
        )
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-orders/active/acme-server/sync",
            {},
            status=303,
        )
        assert res.location.startswith(
            "http://peter-sslers.example.com/.well-known/peter_sslers/acme-orders/active?result=success&operation=acme+server+sync&acme_order_ids.success="
        )

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(("admin:acme_orders:active:acme_server:sync|json",))
    def test_active_acme_server_sync_json(self):
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-orders/active/acme-server/sync.json",
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-orders/active/acme-server/sync.json",
            {},
            status=200,
        )
        assert "result" in res.json
        assert "AcmeOrderIds.success" in res.json
        assert "AcmeOrderIds.error" in res.json

    @routes_tested(
        (
            "admin:acme_order:focus",
            "admin:acme_order:focus:acme_event_logs",
            "admin:acme_order:focus:acme_event_logs_paginated",
            "admin:acme_order:focus:audit",
        )
    )
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s/acme-event-logs" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s/acme-event-logs/1" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s/audit" % focus_id, status=200
        )

    @routes_tested(("admin:acme_order:focus|json", "admin:acme_order:focus:audit|json"))
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % focus_id, status=200
        )
        assert "AcmeOrder" in res.json
        assert res.json["AcmeOrder"]["id"] == focus_id

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s/audit.json" % focus_id, status=200
        )
        assert "AuditReport" in res.json
        assert "AcmeOrder" in res.json["AuditReport"]
        assert "AcmeAccount" in res.json["AuditReport"]
        assert "AcmeServer" in res.json["AuditReport"]
        assert "PrivateKey" in res.json["AuditReport"]
        assert "UniqueFQDNSet" in res.json["AuditReport"]
        assert "AcmeAuthorizations" in res.json["AuditReport"]

    def test_post_required_html(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `acme-order/%s/acme-server/sync`
        # "admin:acme_order:focus:acme_server:sync",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s/acme-server/sync" % focus_id,
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/peter_sslers/acme-order/%s?result=error&operation=acme+server+sync&message=HTTP+POST+required"
            % focus_id
        )

        # !!!: test `POST required` `acme-order/%s/acme-server/sync-authorizations`
        # "admin:acme_order:focus:acme_server:sync_authorizations",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s/acme-server/sync-authorizations"
            % focus_id,
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/peter_sslers/acme-order/%s?result=error&operation=acme+server+sync+authorizations&message=HTTP+POST+required"
            % focus_id
        )

        # !!!: test `POST required` `acme-order/%s/acme-finalize`
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s/acme-finalize" % focus_id,
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/acme-order/%s?result=error&operation=acme+finalize&message=HTTP+POST+required"
            % focus_id
        )

        # !!!: test `POST required` `acme-order/%s/acme-server/deactivate-authorizations`
        # "admin:acme_order:focus:acme_server:deactivate_authorizations",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s/acme-server/deactivate-authorizations"
            % focus_id,
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/acme-order/%s?result=error&operation=acme+server+deactivate+authorizations&message=HTTP+POST+required"
            % focus_id
        )

        # !!!: test `POST required` `acme-order/%s/mark`
        # "admin:acme_order:focus:mark",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s/mark?action=deactivate" % focus_id,
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/acme-order/%s?result=error&operation=mark&message=HTTP+POST+required"
            % focus_id
        )

        # !!!: test `POST required` `acme-order/%s/acme-process`
        # "admin:acme_order:focus:acme-process",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s/acme-process" % focus_id,
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/acme-order/%s?result=error&operation=acme+process&message=HTTP+POST+required"
            % focus_id
        )

    def test_post_required_json(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `acme-order/%s/acme-server/sync.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s/acme-server/sync.json" % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-order/%s/acme-server/sync-authorizations.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s/acme-server/sync-authorizations.json"
            % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-order/%s/acme-finalize.json`
        # "admin:acme_order:focus:acme_finalize|json",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s/acme-finalize.json" % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-order/%s/acme-server/deactivate-authorizations.json`
        # "admin:acme_order:focus:acme_server:deactivate_authorizations",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s/acme-server/deactivate-authorizations.json"
            % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-order/%s/mark.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s/mark.json?action=deactivate"
            % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-order/%s/acme-process.json`
        # "admin:acme_order:focus:acme-process",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s/acme-process.json" % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-order/new/freeform.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/new/freeform.json", status=200
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]


class FunctionalTests_AcmeServer(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer
    """

    @routes_tested("admin:acme_servers")
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/peter_sslers/acme-servers", status=200)

    @routes_tested("admin:acme_servers|json")
    def test_list_json(self):
        # json root
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-servers.json", status=200
        )
        assert "AcmeServers" in res.json

    @routes_tested(
        (
            "admin:acme_server:focus",
            "admin:acme_server:focus:acme_accounts",
            "admin:acme_server:focus:acme_accounts__paginated",
        )
    )
    def test_focus_html(self):
        res = self.testapp.get("/.well-known/peter_sslers/acme-server/1", status=200)
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-server/1/acme-accounts", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-server/1/acme-accounts/1", status=200
        )

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_server:focus",
            "admin:acme_server:focus:check_support",
            "admin:acme_server:focus:mark",
        )
    )
    def test_manipulate_html(self):

        res = self.testapp.get("/.well-known/peter_sslers/acme-server/1")
        form_check = res.forms["form-check"]
        form_mark = res.forms["form-mark"]

        res2 = form_check.submit()
        assert res2.status_code == 303
        assert (
            res2.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/acme-server/1?result=success&operation=check-support&check-support=True"
        )

        _action = form_mark.fields["action"][0].value
        res3 = form_mark.submit()
        assert res3.status_code == 303
        assert (
            res3.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/acme-server/1?result=success&operation=mark&action=%s"
            % _action
        )

    @routes_tested(
        (
            "admin:acme_server:focus|json",
            "admin:acme_server:focus:acme_accounts|json",
            "admin:acme_server:focus:acme_accounts__paginated|json",
        )
    )
    def test_focus_json(self):
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-server/1.json", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-server/1/acme-accounts.json", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-server/1/acme-accounts/1.json", status=200
        )

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_server:focus|json",
            "admin:acme_account:focus:edit|json",
            "admin:acme_server:focus:check_support|json",
            "admin:acme_server:focus:mark|json",
        )
    )
    def test_manipulate_json(self):

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-server/1/check-support.json", status=200
        )
        assert "instructions" in res.json

        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-server/1/check-support.json"
        )

        assert "result" in res.json
        assert res.json["result"] == "success"

        assert "operation" in res.json
        assert res.json["operation"] == "check-support"

        assert "check-support" in res.json
        assert res.json["check-support"] is True

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-server/1/mark.json", status=200
        )
        assert "instructions" in res.json

        res_focus = self.testapp.get(
            "/.well-known/peter_sslers/acme-server/1.json", status=200
        )

        if res_focus.json["AcmeServer"]["is_unlimited_pending_authz"]:
            res = self.testapp.post(
                "/.well-known/peter_sslers/acme-server/1/mark.json",
                {"action": "is_unlimited_pending_authz-false"},
            )
            assert res.status_code == 200
            expected = False
        else:
            res = self.testapp.post(
                "/.well-known/peter_sslers/acme-server/1/mark.json",
                {"action": "is_unlimited_pending_authz-true"},
            )
            expected = True
        assert res.status_code == 200
        assert res.json["result"] == "success"
        assert "AcmeServer" in res.json
        assert res.json["AcmeServer"]["is_unlimited_pending_authz"] == expected

    def test_post_required_html(self):
        # !!!: test `POST required` `acme-server/{ID}/check-support`
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-server/1/check-support", status=303
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/acme-server/1?result=error&error=post+required&operation=check-support"
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-server/1/mark", status=303
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/acme-server/1?result=error&error=post+required&operation=mark"
        )

    def test_post_required_json(self):
        # !!!: test `POST required` `acme-server/{ID}/check-support.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-server/1/check-support.json", status=200
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-server/{ID}/mark.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-server/1/mark.json", status=200
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]


class FunctionalTests_AriCheck(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_AriCheck
    """

    def _ensure_one(self) -> model_objects.AriCheck:
        focus_item = (
            self.ctx.dbSession.query(model_objects.AriCheck)
            .order_by(model_objects.AriCheck.id.asc())
            .first()
        )
        if not focus_item:
            setup_testing_data(self)

        focus_item = (
            self.ctx.dbSession.query(model_objects.AriCheck)
            .order_by(model_objects.AriCheck.id.asc())
            .first()
        )
        assert focus_item is not None
        return focus_item

    @routes_tested(
        (
            "admin:ari_checks",
            "admin:ari_checks:all",
            "admin:ari_checks:all_paginated",
            "admin:ari_checks:cert_latest",
            "admin:ari_checks:cert_latest_paginated",
            "admin:ari_checks:cert_latest_overdue",
            "admin:ari_checks:cert_latest_overdue_paginated",
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/peter_sslers/ari-checks", status=303)
        assert res.location.endswith(
            "/.well-known/peter_sslers/ari-checks/cert-latest-overdue"
        )

        res = self.testapp.get("/.well-known/peter_sslers/ari-checks/all", status=200)
        res = self.testapp.get("/.well-known/peter_sslers/ari-checks/all/1", status=200)
        res = self.testapp.get(
            "/.well-known/peter_sslers/ari-checks/cert-latest", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/ari-checks/cert-latest/1", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/ari-checks/cert-latest-overdue", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/ari-checks/cert-latest-overdue/1", status=200
        )

    @routes_tested(
        (
            "admin:ari_checks|json",
            "admin:ari_checks:all|json",
            "admin:ari_checks:all_paginated|json",
            "admin:ari_checks:cert_latest|json",
            "admin:ari_checks:cert_latest_paginated|json",
            "admin:ari_checks:cert_latest_overdue|json",
            "admin:ari_checks:cert_latest_overdue_paginated|json",
        )
    )
    def test_list_json(self):
        # root
        res = self.testapp.get("/.well-known/peter_sslers/ari-checks.json", status=303)
        assert res.location.endswith(
            "/.well-known/peter_sslers/ari-checks/cert-latest-overdue.json"
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/ari-checks/all.json", status=200
        )
        assert "AriChecks" in res.json
        res = self.testapp.get(
            "/.well-known/peter_sslers/ari-checks/all/1.json", status=200
        )
        assert "AriChecks" in res.json
        res = self.testapp.get(
            "/.well-known/peter_sslers/ari-checks/cert-latest.json", status=200
        )
        assert "AriChecks" in res.json
        res = self.testapp.get(
            "/.well-known/peter_sslers/ari-checks/cert-latest/1.json", status=200
        )
        assert "AriChecks" in res.json
        res = self.testapp.get(
            "/.well-known/peter_sslers/ari-checks/cert-latest-overdue.json", status=200
        )
        assert "AriChecks" in res.json
        res = self.testapp.get(
            "/.well-known/peter_sslers/ari-checks/cert-latest-overdue/1.json",
            status=200,
        )
        assert "AriChecks" in res.json

    @routes_tested(("admin:ari_check:focus",))
    def test_focus_html(self):
        dbAriCheck = self._ensure_one()
        res = self.testapp.get(
            "/.well-known/peter_sslers/ari-check/%s" % dbAriCheck.id,
            status=200,
        )

    @routes_tested(("admin:ari_check:focus|json",))
    def test_focus_json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_AriCheck.test_focus_json
        """
        dbAriCheck = self._ensure_one()
        res = self.testapp.get(
            "/.well-known/peter_sslers/ari-check/%s.json" % dbAriCheck.id,
            status=200,
        )
        assert "AriCheck" in res.json
        assert res.json["AriCheck"]["id"] == dbAriCheck.id


class FunctionalTests_CertificateCA(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_CertificateCA
    """

    @routes_tested(
        (
            "admin:certificate_cas",
            "admin:certificate_cas_paginated",
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/peter_sslers/certificate-cas", status=200)
        # paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-cas/1", status=200
        )

    @routes_tested(
        (
            "admin:certificate_cas|json",
            "admin:certificate_cas_paginated|json",
        )
    )
    def test_list_json(self):
        # JSON root
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-cas.json", status=200
        )
        assert "CertificateCAs" in res.json

        # JSON paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-cas/1.json", status=200
        )
        assert "CertificateCAs" in res.json

    @routes_tested(
        (
            "admin:certificate_ca:focus",
            "admin:certificate_ca:focus:raw",
            "admin:certificate_ca:focus:certificate_signeds",
            "admin:certificate_ca:focus:certificate_signeds_paginated",
            "admin:certificate_ca:focus:certificate_ca_chains_0",
            "admin:certificate_ca:focus:certificate_ca_chains_0_paginated",
            "admin:certificate_ca:focus:certificate_ca_chains_n",
            "admin:certificate_ca:focus:certificate_ca_chains_n_paginated",
        )
    )
    def test_focus_html(self):
        res = self.testapp.get("/.well-known/peter_sslers/certificate-ca/1", status=200)

        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca/1/cert.pem", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca/1/cert.pem.txt", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca/1/cert.cer", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca/1/cert.crt", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca/1/cert.der", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca/1/certificate-signeds", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca/1/certificate-signeds/1",
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca/1/certificate-ca-chains-0",
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca/1/certificate-ca-chains-0/1",
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca/1/certificate-ca-chains-n",
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca/1/certificate-ca-chains-n/1",
            status=200,
        )

    @routes_tested(
        (
            "admin:certificate_ca:focus|json",
            "admin:certificate_ca:focus:parse|json",
        )
    )
    def test_focus_json(self):
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca/1.json", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca/1/parse.json", status=200
        )
        assert "CertificateCA" in res.json
        assert "id" in res.json["CertificateCA"]
        assert "parsed" in res.json["CertificateCA"]

    @routes_tested(("admin:certificate_ca:upload_cert",))
    def test_upload_html(self):
        """
        This should enter in item #8, but the CertificateCAs.order is 0.
        xxx At this point, the only CA Cert that is not self-signed should be `ISRG Root X1`
        update: ISRG Root X2 has a cross-signed variant

        python -m unittest tests.test_pyramid_app.FunctionalTests_CertificateCA.test_upload_html
        """
        _cert_ca_id = TEST_FILES["CertificateCAs"]["order"][0]
        self.assertEqual(_cert_ca_id, "trustid_root_x3")
        _cert_ca_filename = TEST_FILES["CertificateCAs"]["cert"][_cert_ca_id]
        _cert_ca_filepath = self._filepath_testfile(_cert_ca_filename)

        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca/upload-cert", status=200
        )
        form = res.form
        form["cert_file"] = Upload(_cert_ca_filepath)
        res2 = form.submit()
        assert res2.status_code == 303

        matched = RE_CertificateCA_uploaded.match(res2.location)

        # this querystring ends: ?result=success&is_created=0'
        _is_created = bool(int(res2.location[-1]))

        assert matched
        obj_id = matched.groups()[0]
        res3 = self.testapp.get(res2.location, status=200)

    @routes_tested(("admin:certificate_ca:upload_cert|json",))
    def test_upload_json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_CertificateCA.test_upload_json

        This originally tested an upload, but now we preload this certificate
        We
        """
        _cert_ca_id = TEST_FILES["CertificateCAs"]["order"][2]
        self.assertEqual(_cert_ca_id, "isrg_root_x1_cross")
        _cert_ca_filename = TEST_FILES["CertificateCAs"]["cert"][_cert_ca_id]
        _cert_ca_filepath = self._filepath_testfile(_cert_ca_filename)

        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca/upload-cert.json", status=200
        )
        _data = {"cert_file": Upload(_cert_ca_filepath)}
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/certificate-ca/upload-cert.json", _data
        )
        assert res2.status_code == 200
        assert res2.json["result"] == "success"
        # we may not have created this
        assert res2.json["CertificateCA"]["created"] in (True, False)
        assert (
            res2.json["CertificateCA"]["id"] == 3
        )  # this is the 3rd item in letsencrypt_info._CERT_CAS_ORDER
        obj_id = res2.json["CertificateCA"]["id"]
        res3 = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca/%s" % obj_id, status=200
        )

    def _expected_preferences(self):
        """this is shared by html and json"""
        # when we initialize the application, the setup routine inserts some
        # default CertificateCA preferences
        expected_preferences_initial = (
            ("1", "DAC9024F"),  # trustid_root_x3
            ("2", "BDB1B93C"),  # isrg_root_x2
            ("3", "CABD2A79"),  # isrg_root_x1
        )
        # calculate the expected matrix after an alteration
        # in this alteration, we swap the first and second items
        _expected_preferences_altered = [i[1] for i in expected_preferences_initial]
        _expected_preferences_altered.insert(0, _expected_preferences_altered.pop(1))
        expected_preferences_altered = [
            (str(idx + 1), i) for (idx, i) in enumerate(_expected_preferences_altered)
        ]

        return (expected_preferences_initial, expected_preferences_altered)

    def _load__CertificateCAPreferences(self):
        _dbCertificateCAPreferences = (
            self.ctx.dbSession.query(model_objects.CertificateCAPreference)
            .options(
                sqlalchemy.orm.joinedload(
                    model_objects.CertificateCAPreference.certificate_ca
                )
            )
            .all()
        )
        return _dbCertificateCAPreferences

    def _load__CertificateCA_unused(self):
        dbCertificateCA_unused = (
            self.ctx.dbSession.query(model_objects.CertificateCA)
            .outerjoin(
                model_objects.CertificateCAPreference,
                model_objects.CertificateCA.id
                == model_objects.CertificateCAPreference.certificate_ca_id,
            )
            .filter(model_objects.CertificateCAPreference.id.is_(None))
            .all()
        )
        return dbCertificateCA_unused

    @routes_tested(
        (
            "admin:certificate_cas:preferred",
            "admin:certificate_cas:preferred:add",
            "admin:certificate_cas:preferred:delete",
            "admin:certificate_cas:preferred:prioritize",
        )
    )
    def test_manipulate_html(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_CertificateCA.test_manipulate_html
        """

        (
            expected_preferences_initial,
            expected_preferences_altered,
        ) = self._expected_preferences()

        def _ensure_compliance_form(_res, _expected_preferences):
            """
            ensures the forms are present, expected and compliant
            """
            # load our database backed info
            _dbCertificateCAPreferences = self._load__CertificateCAPreferences()
            assert len(_dbCertificateCAPreferences) == len(_expected_preferences)

            _res_forms = _res.forms

            for _idx, (_slot_id, _fingerpint_sha1_substr) in enumerate(
                _expected_preferences
            ):
                # delete
                assert "form-preferred-delete-%s" % _slot_id in _res_forms
                _form = _res_forms["form-preferred-delete-%s" % _slot_id]
                _fields = dict(_form.submit_fields())
                assert _fields["slot"] == _slot_id
                assert _fields["fingerprint_sha1"].startswith(_fingerpint_sha1_substr)

                # prioritize_increase
                assert "form-preferred-prioritize_increase-%s" % _slot_id in _res_forms
                _form = _res_forms["form-preferred-prioritize_increase-%s" % _slot_id]
                _fields = dict(_form.submit_fields())
                assert _fields["slot"] == _slot_id
                assert _fields["fingerprint_sha1"].startswith(_fingerpint_sha1_substr)

                # prioritize_decrease
                assert "form-preferred-prioritize_decrease-%s" % _slot_id in _res_forms
                _form = _res_forms["form-preferred-prioritize_decrease-%s" % _slot_id]
                _fields = dict(_form.submit_fields())
                assert _fields["slot"] == _slot_id
                assert _fields["fingerprint_sha1"].startswith(_fingerpint_sha1_substr)

                assert _dbCertificateCAPreferences[_idx].id == int(_slot_id)
                assert _dbCertificateCAPreferences[
                    _idx
                ].certificate_ca.fingerprint_sha1.startswith(_fingerpint_sha1_substr)

        # !!!: start the test

        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-cas/preferred", status=200
        )
        _ensure_compliance_form(res, expected_preferences_initial)

        # some failures are expected
        res_forms = res.forms
        # first item can not increase in priority
        _form = res_forms["form-preferred-prioritize_increase-1"]
        res2 = _form.submit()
        assert res2.status_code == 200
        assert (
            """<div class="alert alert-danger"><div class="control-group error"><span class="help-inline">There was an error with your form. This item can not be increased in priority.</span></div></div>"""
            in res2.text
        )
        # last item can not decrease in priority
        _form = res_forms["form-preferred-prioritize_decrease-3"]
        res3 = _form.submit()
        assert res3.status_code == 200
        assert (
            """<div class="alert alert-danger"><div class="control-group error"><span class="help-inline">There was an error with your form. This item can not be decreased in priority.</span></div></div>"""
            in res3.text
        )

        # some things should work in an expected manner!
        # first, increase slot 2 to slot 1
        # submit the form
        _form = res_forms["form-preferred-prioritize_increase-2"]
        res4 = _form.submit()
        assert res4.status_code == 303
        assert (
            res4.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/certificate-cas/preferred?result=success&operation=prioritize"
        )
        res5 = self.testapp.get(res4.location, status=200)
        _ensure_compliance_form(res5, expected_preferences_altered)

        # now, do this again.
        # we should FAIL because it is stale
        res5b = _form.submit()
        assert res5b.status_code == 200
        assert (
            """<div class="alert alert-danger"><div class="control-group error"><span class="help-inline">There was an error with your form. Can not operate on bad or stale data.</span></div></div>"""
            in res5b.text
        )

        # now, undo the above by decreasing slot 1 to slot 2
        _form = res5.forms["form-preferred-prioritize_decrease-1"]
        res6 = _form.submit()
        assert res6.status_code == 303
        assert (
            res6.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/certificate-cas/preferred?result=success&operation=prioritize"
        )

        # now, do this again.
        # we should FAIL because it is stale
        res6b = _form.submit()
        assert res6b.status_code == 200
        assert (
            """<div class="alert alert-danger"><div class="control-group error"><span class="help-inline">There was an error with your form. Can not operate on bad or stale data.</span></div></div>"""
            in res6b.text
        )

        # woohoo, now grab a new certificateCA to insert
        dbCertificateCA_unused = self._load__CertificateCA_unused()
        assert len(dbCertificateCA_unused) >= 1
        dbCertificateCA_add = dbCertificateCA_unused[0]

        # start from scratch
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-cas/preferred", status=200
        )
        forms = res.forms
        assert "form-preferred-add" in res.forms

        # add
        form_add = res.forms["form-preferred-add"]
        assert "fingerprint_sha1" in dict(form_add.submit_fields())
        form_add["fingerprint_sha1"] = dbCertificateCA_add.fingerprint_sha1
        res2 = form_add.submit()
        assert res2.status_code == 303
        assert (
            res2.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/certificate-cas/preferred?result=success&operation=add"
        )

        # ensure compliance
        expected_preferences_added = list(expected_preferences_initial[:])
        expected_preferences_added.append(
            (
                str(len(expected_preferences_added) + 1),
                str(dbCertificateCA_add.fingerprint_sha1),
            )
        )
        res3 = self.testapp.get(res2.location)
        _ensure_compliance_form(res3, expected_preferences_added)

        # delete
        form_del = res3.forms["form-preferred-delete-4"]
        _submit_fields = dict(form_del.submit_fields())
        assert "fingerprint_sha1" in _submit_fields
        assert (
            _submit_fields["fingerprint_sha1"] == dbCertificateCA_add.fingerprint_sha1
        )
        res4 = form_del.submit()
        assert res4.status_code == 303
        assert (
            res4.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/certificate-cas/preferred?result=success&operation=delete"
        )

        # delete again, we should fail!
        res4b = form_del.submit()
        assert res4b.status_code == 200
        assert (
            """<div class="alert alert-danger"><div class="control-group error"><span class="help-inline">There was an error with your form. Can not operate on bad or stale data.</span></div></div>"""
            in res4b.text
        )

        # and lets make sure we're at the base option
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-cas/preferred", status=200
        )
        _ensure_compliance_form(res, expected_preferences_initial)

        # TODO: test adding more than 10 items

    @routes_tested(
        (
            "admin:certificate_cas:preferred|json",
            "admin:certificate_cas:preferred:add|json",
            "admin:certificate_cas:preferred:delete|json",
            "admin:certificate_cas:preferred:prioritize|json",
        )
    )
    def test_manipulate_json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_CertificateCA.test_manipulate_json
        """
        (
            expected_preferences_initial,
            expected_preferences_altered,
        ) = self._expected_preferences()

        # for json tests, we need to map the substring fingerprints in the test to
        # full size fingerprints for certain operations
        _dbCertificateCA_all = self.ctx.dbSession.query(
            model_objects.CertificateCA
        ).all()
        fingerprints_mapping = {
            i.fingerprint_sha1[:8]: i.fingerprint_sha1 for i in _dbCertificateCA_all
        }

        def _ensure_compliance_payload(_res, _expected_preferences):
            """
            ensures the forms are present, expected and compliant
            """
            # load our database backed info
            _dbCertificateCAPreferences = self._load__CertificateCAPreferences()
            assert len(_dbCertificateCAPreferences) == len(_expected_preferences)

            # check our payload
            assert "CertificateCAs" in res.json
            assert "PreferenceOrder" in res.json
            for _idx, _slot_id in enumerate(
                sorted(res.json["PreferenceOrder"].keys(), key=lambda x: int(x))
            ):
                _cert_ca_id = res.json["PreferenceOrder"][_slot_id]
                assert _cert_ca_id in res.json["CertificateCAs"]
                _fingerpint_sha1 = res.json["CertificateCAs"][_cert_ca_id][
                    "fingerprint_sha1"
                ]

                assert _dbCertificateCAPreferences[_idx].id == int(_slot_id)
                assert (
                    _dbCertificateCAPreferences[_idx].certificate_ca.fingerprint_sha1
                    == _fingerpint_sha1
                )

                # _expected_preferences = ((slot_id, fingerprint_sha1_substring), ...)
                assert _fingerpint_sha1.startswith(_expected_preferences[_idx][1])

        # !!!: start the test

        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-cas/preferred.json", status=200
        )
        _ensure_compliance_payload(res, expected_preferences_initial)

        # ensure GET/POST core functionality

        # GET/POST prioritize
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-cas/preferred/prioritize.json",
            status=200,
        )
        assert "form_fields" in res.json
        _expected_fields: Tuple[str, ...] = ("slot", "fingerprint_sha1", "priority")
        assert len(res.json["form_fields"]) == len(_expected_fields)
        for _field in _expected_fields:
            assert _field in res.json["form_fields"]
        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-cas/preferred/prioritize.json"
        )
        assert res.json["result"] == "error"
        assert "Error_Main" in res.json["form_errors"]
        assert res.json["form_errors"]["Error_Main"] == "Nothing submitted."

        # GET/POST add
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-cas/preferred/add.json", status=200
        )
        assert "form_fields" in res.json
        _expected_fields = ("fingerprint_sha1",)
        assert len(res.json["form_fields"]) == len(_expected_fields)
        for _field in _expected_fields:
            assert _field in res.json["form_fields"]
        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-cas/preferred/add.json"
        )
        assert res.json["result"] == "error"
        assert "Error_Main" in res.json["form_errors"]
        assert res.json["form_errors"]["Error_Main"] == "Nothing submitted."

        # GET/POST delete
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-cas/preferred/delete.json",
            status=200,
        )
        assert "form_fields" in res.json
        _expected_fields = ("fingerprint_sha1", "slot")
        assert len(res.json["form_fields"]) == len(_expected_fields)
        for _field in _expected_fields:
            assert _field in res.json["form_fields"]
        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-cas/preferred/delete.json"
        )
        assert res.json["result"] == "error"
        assert "Error_Main" in res.json["form_errors"]
        assert res.json["form_errors"]["Error_Main"] == "Nothing submitted."

        # some failures are expected

        # first item can not increase in priority
        # but we MUST use full fingerprints in this context
        _payload = {
            "slot": "1",
            "fingerprint_sha1": expected_preferences_initial[0][1],
            "priority": "increase",
        }
        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-cas/preferred/prioritize.json",
            _payload,
        )
        assert res.status_code == 200
        assert res.json["result"] == "error"
        assert "form_errors" in res.json
        assert (
            res.json["form_errors"]["Error_Main"]
            == "There was an error with your form. Can not operate on bad or stale data."
        )
        # trigger the expected error
        _payload["fingerprint_sha1"] = fingerprints_mapping[
            _payload["fingerprint_sha1"]
        ]
        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-cas/preferred/prioritize.json",
            _payload,
        )
        assert res.status_code == 200
        assert res.json["result"] == "error"
        assert "form_errors" in res.json
        assert (
            res.json["form_errors"]["Error_Main"]
            == "There was an error with your form. This item can not be increased in priority."
        )

        # last item can not decrease in priority
        # but we MUST use full fingerprints in this context
        _payload = {
            "slot": "3",
            "fingerprint_sha1": expected_preferences_initial[2][1],
            "priority": "decrease",
        }
        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-cas/preferred/prioritize.json",
            _payload,
        )
        assert res.status_code == 200
        assert res.json["result"] == "error"
        assert "form_errors" in res.json
        assert (
            res.json["form_errors"]["Error_Main"]
            == "There was an error with your form. Can not operate on bad or stale data."
        )
        # trigger the expected error
        _payload["fingerprint_sha1"] = fingerprints_mapping[
            _payload["fingerprint_sha1"]
        ]
        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-cas/preferred/prioritize.json",
            _payload,
        )
        assert res.status_code == 200
        assert res.json["result"] == "error"
        assert "form_errors" in res.json
        assert (
            res.json["form_errors"]["Error_Main"]
            == "There was an error with your form. This item can not be decreased in priority."
        )

        # some things should work in an expected manner!
        # first, increase slot 2 to slot 1
        # submit the form
        _payload = {
            "slot": "2",
            "fingerprint_sha1": expected_preferences_initial[1][1],
            "priority": "increase",
        }
        _payload["fingerprint_sha1"] = fingerprints_mapping[
            _payload["fingerprint_sha1"]
        ]
        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-cas/preferred/prioritize.json",
            _payload,
        )
        assert res.status_code == 200
        assert res.json["result"] == "success"
        assert res.json["operation"] == "prioritize"

        # now, do this again.
        # we should FAIL because it is stale
        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-cas/preferred/prioritize.json",
            _payload,
        )
        assert res.status_code == 200
        assert res.json["result"] == "error"
        assert "form_errors" in res.json
        assert (
            res.json["form_errors"]["Error_Main"]
            == "There was an error with your form. Can not operate on bad or stale data."
        )

        # now, undo the above by decreasing slot 1 to slot 2
        _payload = {
            "slot": "1",
            "fingerprint_sha1": expected_preferences_initial[1][1],
            "priority": "decrease",
        }
        _payload["fingerprint_sha1"] = fingerprints_mapping[
            _payload["fingerprint_sha1"]
        ]
        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-cas/preferred/prioritize.json",
            _payload,
        )
        assert res.status_code == 200
        assert res.json["result"] == "success"
        assert res.json["operation"] == "prioritize"

        # now, do this again.
        # we should FAIL because it is stale
        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-cas/preferred/prioritize.json",
            _payload,
        )
        assert res.status_code == 200
        assert res.json["result"] == "error"
        assert "form_errors" in res.json
        assert (
            res.json["form_errors"]["Error_Main"]
            == "There was an error with your form. Can not operate on bad or stale data."
        )

        # woohoo, now grab a new certificateCA to insert
        dbCertificateCA_unused = self._load__CertificateCA_unused()
        assert len(dbCertificateCA_unused) >= 1
        dbCertificateCA_add = dbCertificateCA_unused[0]

        # add
        _payload = {"fingerprint_sha1": dbCertificateCA_add.fingerprint_sha1}
        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-cas/preferred/add.json", _payload
        )
        assert res.status_code == 200
        assert res.json["result"] == "success"
        assert res.json["operation"] == "add"

        # ensure compliance
        expected_preferences_added = list(expected_preferences_initial[:])
        expected_preferences_added.append(
            (
                str(len(expected_preferences_added) + 1),
                str(dbCertificateCA_add.fingerprint_sha1),
            )
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-cas/preferred.json", status=200
        )
        _ensure_compliance_payload(res, expected_preferences_added)

        # delete
        _payload = {"slot": 4, "fingerprint_sha1": dbCertificateCA_add.fingerprint_sha1}
        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-cas/preferred/delete.json", _payload
        )
        assert res.status_code == 200
        assert res.json["result"] == "success"
        assert res.json["operation"] == "delete"

        # delete again, we should fail!
        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-cas/preferred/delete.json", _payload
        )
        assert res.status_code == 200
        assert res.json["result"] == "error"
        assert "form_errors" in res.json
        assert (
            res.json["form_errors"]["Error_Main"]
            == "There was an error with your form. Can not operate on bad or stale data."
        )

        # and lets make sure we're at the base option
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-cas/preferred.json", status=200
        )
        _ensure_compliance_payload(res, expected_preferences_initial)

        # TODO: test adding more than 10 items


class FunctionalTests_CertificateCAChain(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_CertificateCAChain
    """

    @routes_tested(
        (
            "admin:certificate_ca_chains",
            "admin:certificate_ca_chains_paginated",
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca-chains", status=200
        )
        # paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca-chains/1", status=200
        )

    @routes_tested(
        (
            "admin:certificate_ca_chains|json",
            "admin:certificate_ca_chains_paginated|json",
        )
    )
    def test_list_json(self):
        # JSON root
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca-chains.json", status=200
        )
        assert "CertificateCAChains" in res.json

        # JSON paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca-chains/1.json", status=200
        )
        assert "CertificateCAChains" in res.json

    @routes_tested(
        ("admin:certificate_ca_chain:focus", "admin:certificate_ca_chain:focus:raw")
    )
    def test_focus_html(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_CertificateCAChain.test_focus_html
        """
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca-chain/1", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca-chain/1/chain.pem", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca-chain/1/chain.pem.txt", status=200
        )

    @routes_tested(("admin:certificate_ca_chain:focus|json",))
    def test_focus_json(self):
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca-chain/1.json", status=200
        )

    @routes_tested(("admin:certificate_ca_chain:upload_chain",))
    def test_upload_html(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_CertificateCAChain.test_upload_html
        """
        # let's build a chain!
        chain_items = ["isrg_root_x2_cross", "isrg_root_x1"]
        _chain_data = []
        for _cert_ca_id in chain_items:
            _cert_ca_filename = TEST_FILES["CertificateCAs"]["cert"][_cert_ca_id]
            _cert_ca_filepath = self._filepath_testfile(_cert_ca_filename)
            _cert_ca_filedata = self._filedata_testfile(_cert_ca_filepath)
            if TYPE_CHECKING:
                assert isinstance(_cert_ca_filedata, str)
            _chain_data.append(_cert_ca_filedata)
        chain_data = "\n".join(_chain_data)
        tmpfile_pem = None
        try:
            tmpfile_pem = cert_utils.new_pem_tempfile(chain_data)
            res = self.testapp.get(
                "/.well-known/peter_sslers/certificate-ca-chain/upload-chain",
                status=200,
            )
            form = res.form
            form["chain_file"] = Upload(tmpfile_pem.name)
            res2 = form.submit()
            assert res2.status_code == 303
            matched = RE_CertificateCAChain_uploaded.match(res2.location)
            # this querystring ends: ?result=success&is_created=0'
            _is_created = bool(int(res2.location[-1]))
            assert matched
            obj_id = matched.groups()[0]
            res3 = self.testapp.get(res2.location, status=200)
        finally:
            if tmpfile_pem is not None:
                tmpfile_pem.close()

    @routes_tested(("admin:certificate_ca_chain:upload_chain|json",))
    def test_upload_json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_CertificateCAChain.test_upload_json
        """
        # test chain uploads
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-ca-chain/upload-chain.json",
            status=200,
        )
        # let's build a chain!
        chain_items = ["isrg_root_x2_cross", "isrg_root_x1"]
        _chain_data = []
        for _cert_ca_id in chain_items:
            _cert_ca_filename = TEST_FILES["CertificateCAs"]["cert"][_cert_ca_id]
            _cert_ca_filepath = self._filepath_testfile(_cert_ca_filename)
            _cert_ca_filedata = self._filedata_testfile(_cert_ca_filepath)
            if TYPE_CHECKING:
                assert isinstance(_cert_ca_filedata, str)
            _chain_data.append(_cert_ca_filedata)
        chain_data = "\n".join(_chain_data)
        tmpfile_pem = None
        try:
            tmpfile_pem = cert_utils.new_pem_tempfile(chain_data)
            _data = {"chain_file": Upload(tmpfile_pem.name)}
            res2 = self.testapp.post(
                "/.well-known/peter_sslers/certificate-ca-chain/upload-chain.json",
                _data,
            )
            assert res2.status_code == 200
            assert res2.json["result"] == "success"
            # we may not have created this
            assert res2.json["CertificateCAChain"]["created"] in (True, False)

        finally:
            if tmpfile_pem is not None:
                tmpfile_pem.close()


class FunctionalTests_CertificateRequest(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_CertificateRequest
    """

    def _get_one(self):
        # grab a certificate
        focus_item = (
            self.ctx.dbSession.query(model_objects.CertificateRequest)
            .order_by(model_objects.CertificateRequest.id.asc())
            .first()
        )
        assert focus_item is not None
        return focus_item, focus_item.id

    @routes_tested(
        (
            "admin:certificate_requests",
            "admin:certificate_requests_paginated",
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-requests", status=200
        )

        # paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-requests/1", status=200
        )

    @routes_tested(
        (
            "admin:certificate_requests|json",
            "admin:certificate_requests_paginated|json",
        )
    )
    def test_list_json(self):
        # root
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-requests.json", status=200
        )
        assert "CertificateRequests" in res.json

        # paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-requests/1.json", status=200
        )
        assert "CertificateRequests" in res.json

    @routes_tested(
        (
            "admin:certificate_request:focus",
            "admin:certificate_request:focus:acme_orders",
            "admin:certificate_request:focus:acme_orders_paginated",
        )
    )
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-request/%s" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-request/%s/acme-orders" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-request/%s/acme-orders/1" % focus_id,
            status=200,
        )

    @routes_tested(("admin:certificate_request:focus:raw",))
    def test_focus_raw(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-request/%s/csr.csr" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-request/%s/csr.pem" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-request/%s/csr.pem.txt" % focus_id,
            status=200,
        )

    @routes_tested(("admin:certificate_request:focus|json",))
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-request/%s.json" % focus_id,
            status=200,
        )
        assert "CertificateRequest" in res.json
        assert res.json["CertificateRequest"]["id"] == focus_id


class FunctionalTests_CertificateSigned(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_CertificateSigned
    """

    def _get_one(self):
        # grab a certificate
        # iterate backwards
        focus_item = (
            self.ctx.dbSession.query(model_objects.CertificateSigned)
            .filter(model_objects.CertificateSigned.is_active.is_(True))
            .order_by(model_objects.CertificateSigned.id.desc())
            .first()
        )
        assert focus_item is not None
        return focus_item, focus_item.id

    @routes_tested(("admin:certificate_signeds:search",))
    def test_search_html(self):
        """
        python -munittest tests.test_pyramid_app.FunctionalTests_CertificateSigned.test_search_html
        """
        (dbCert, cert_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signeds/search", status=200
        )
        assert "form-certificate_signeds-search" in res.forms
        form = res.forms["form-certificate_signeds-search"]
        form["ari_identifier"] = dbCert.ari_identifier
        res2 = form.submit()
        assert res2.status_code == 200
        assert "<h4>Results - Certificate</h4>" in res2.text
        assert "CertificateSigned-%s" % cert_id in res2.text

        form2 = res2.forms["form-certificate_signeds-search"]
        form2["serial"] = dbCert.cert_serial
        res3 = form.submit()
        assert res3.status_code == 200
        assert "<h4>Results - Certificate</h4>" in res3.text
        assert "CertificateSigned-%s" % cert_id in res3.text

    @routes_tested(("admin:certificate_signeds:search|json",))
    def test_search_json(self):
        """
        python -munittest tests.test_pyramid_app.FunctionalTests_CertificateSigned.test_search_json
        """
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signeds/search.json", status=200
        )
        assert "instructions" in res.json

        (dbCert, cert_id) = self._get_one()

        form = {"ari_identifier": dbCert.ari_identifier}
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/certificate-signeds/search.json",
            form,
            status=200,
        )
        assert res2.json["result"] == "success"
        assert res2.json["search_query"]["ari_identifier"] == dbCert.ari_identifier
        assert res2.json["search_query"]["serial"] is None
        assert "CertificateSigned" in res2.json["search_results"]
        assert res2.json["search_results"]["CertificateSigned"]["id"] == cert_id

        form = {"serial": dbCert.cert_serial}
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/certificate-signeds/search.json",
            form,
            status=200,
        )
        assert res2.json["result"] == "success"
        assert res2.json["search_query"]["ari_identifier"] is None
        assert res2.json["search_query"]["serial"] == dbCert.cert_serial
        assert "CertificateSigneds" in res2.json["search_results"]
        assert res2.json["search_results"]["CertificateSigneds"][0]["id"] == cert_id

    @routes_tested(
        (
            "admin:certificate_signeds",
            "admin:certificate_signeds:all",
            "admin:certificate_signeds:all_paginated",
            "admin:certificate_signeds:active",
            "admin:certificate_signeds:active_paginated",
            "admin:certificate_signeds:expiring",
            "admin:certificate_signeds:expiring_paginated",
            "admin:certificate_signeds:inactive",
            "admin:certificate_signeds:inactive_paginated",
            "admin:certificate_signeds:active_expired",
            "admin:certificate_signeds:active_expired_paginated",
            "admin:certificate_signeds:inactive_unexpired",
            "admin:certificate_signeds:inactive_unexpired_paginated",
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signeds", status=303
        )
        assert (
            res.location
            == """http://peter-sslers.example.com/.well-known/peter_sslers/certificate-signeds/active"""
        )

        for _type in (
            "all",
            "active",
            "expiring",
            "inactive",
            "active-expired",
            "inactive-unexpired",
        ):
            res = self.testapp.get(
                "/.well-known/peter_sslers/certificate-signeds/%s" % _type, status=200
            )
            res = self.testapp.get(
                "/.well-known/peter_sslers/certificate-signeds/%s/1" % _type, status=200
            )

    @routes_tested(
        (
            "admin:certificate_signeds|json",
            "admin:certificate_signeds:all|json",
            "admin:certificate_signeds:all_paginated|json",
            "admin:certificate_signeds:active|json",
            "admin:certificate_signeds:active_paginated|json",
            "admin:certificate_signeds:expiring|json",
            "admin:certificate_signeds:expiring_paginated|json",
            "admin:certificate_signeds:inactive|json",
            "admin:certificate_signeds:inactive_paginated|json",
            "admin:certificate_signeds:active_expired|json",
            "admin:certificate_signeds:active_expired_paginated|json",
            "admin:certificate_signeds:inactive_unexpired|json",
            "admin:certificate_signeds:inactive_unexpired_paginated|json",
        )
    )
    def test_list_json(self):
        # root
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signeds.json", status=303
        )
        assert (
            res.location
            == """http://peter-sslers.example.com/.well-known/peter_sslers/certificate-signeds/active.json"""
        )

        for _type in (
            "all",
            "active",
            "expiring",
            "inactive",
            "active-expired",
            "inactive-unexpired",
        ):
            res = self.testapp.get(
                "/.well-known/peter_sslers/certificate-signeds/%s.json" % _type,
                status=200,
            )
            assert "CertificateSigneds" in res.json

            res = self.testapp.get(
                "/.well-known/peter_sslers/certificate-signeds/%s/1.json" % _type,
                status=200,
            )
            assert "CertificateSigneds" in res.json

    @routes_tested(
        (
            "admin:certificate_signed:focus",
            "admin:certificate_signed:focus:ari_check_history",
            "admin:certificate_signed:focus:ari_check_history__paginated",
        )
    )
    def test_focus_html(self):
        try:
            (focus_item, focus_id) = self._get_one()
        except:
            raise ValueError(
                """This test currently fails when the ENTIRE SUITE is run """
                """because `FunctionalTests_API.tests_manipulate` will """
                """deactivate the certificate. Try running this test or """
                """this tests's class directly to ensure a pass."""
            )

        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/ari-check-history"
            % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/ari-check-history/1"
            % focus_id,
            status=200,
        )

    @routes_tested(
        (
            "admin:certificate_signed:focus:chain:raw",
            "admin:certificate_signed:focus:fullchain:raw",
            "admin:certificate_signed:focus:privatekey:raw",
            "admin:certificate_signed:focus:cert:raw",
            "admin:certificate_signed:focus:config|zip",
        )
    )
    def test_focus_raw(self):
        """
        python -munittest tests.test_pyramid_app.FunctionalTests_CertificateSigned.test_focus_raw
        """
        try:
            (focus_item, focus_id) = self._get_one()
        except:
            raise ValueError(
                """This test currently fails when the ENTIRE SUITE is run """
                """because `FunctionalTests_API.tests_manipulate` will """
                """deactivate the certificate. Try running this test or """
                """this tests's class directly to ensure a pass."""
            )

        # CERTIFICATE
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/cert.pem" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/cert.pem.txt" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/cert.cer" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/cert.crt" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/cert.der" % focus_id,
            status=200,
        )

        # CHAIN
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/chain.pem" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/chain.pem.txt" % focus_id,
            status=200,
        )

        # FULLCHAIN
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/fullchain.pem" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/fullchain.pem.txt"
            % focus_id,
            status=200,
        )

        # PRIVATE KEY
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/privkey.key" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/privkey.pem" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/privkey.pem.txt"
            % focus_id,
            status=200,
        )

        # CONFIG
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/config.zip" % focus_id,
            status=200,
        )
        assert res.headers["Content-Type"] == "application/zip"
        assert (
            res.headers["Content-Disposition"]
            == "attachment; filename= cert%s.zip" % focus_id
        )
        z = zipfile.ZipFile(BytesIO(res.body))
        assert len(z.infolist()) == 4
        expectations = [
            file_template % focus_id
            for file_template in (
                "cert%s.pem",
                "chain%s.pem",
                "fullchain%s.pem",
                "privkey%s.pem",
            )
        ]
        found = [zipped.filename for zipped in z.infolist()]
        expectations.sort()
        found.sort()
        assert found == expectations

    @routes_tested(
        (
            "admin:certificate_signed:focus|json",
            "admin:certificate_signed:focus:config|json",
            "admin:certificate_signed:focus:parse|json",
            "admin:certificate_signed:focus:ari_check_history|json",
            "admin:certificate_signed:focus:ari_check_history__paginated|json",
        )
    )
    def test_focus_json(self):
        try:
            (focus_item, focus_id) = self._get_one()
        except:
            raise ValueError(
                """This test currently fails when the ENTIRE SUITE is run """
                """because `FunctionalTests_API.tests_manipulate` will """
                """deactivate the certificate. Try running this test or """
                """this tests's class directly to ensure a pass."""
            )

        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s.json" % focus_id,
            status=200,
        )
        assert "CertificateSigned" in res.json
        assert res.json["CertificateSigned"]["id"] == focus_id

        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/config.json" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/parse.json" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/ari-check-history.json"
            % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/ari-check-history/1.json"
            % focus_id,
            status=200,
        )

    @routes_tested(("admin:certificate_signed:focus:mark",))
    def test_manipulate_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/mark" % focus_id
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=error&error=post+required&operation=mark")

        # the `focus_item` is active, so it can't be revoked or inactive
        if focus_item.is_revoked:
            raise ValueError("focus_item.is_revoked")

        if not focus_item.is_active:
            raise ValueError("NOT focus_item.is_active")

        # fail making this active
        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-signed/%s/mark" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 303
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/certificate-signed/%s?&result=error&error=There+was+an+error+with+your+form.+Already+active.&operation=mark&action=active"
            % focus_id
        )

        # inactive ROUNDTRIP
        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-signed/%s/mark" % focus_id,
            {"action": "inactive"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=inactive")

        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-signed/%s/mark" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=active")

        # then compromised
        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-signed/%s/mark" % focus_id,
            {"action": "revoked"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=revoked")

    @routes_tested(("admin:certificate_signed:focus:mark|json",))
    def test_manipulate_json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_CertificateSigned.test_manipulate_json
        """
        (focus_item, focus_id) = self._get_one()

        # the `focus_item` is active, so it can't be revoked or inactive
        if focus_item.is_revoked:
            raise ValueError("focus_item.is_revoked")

        if not focus_item.is_active:
            raise ValueError("NOT focus_item.is_active")

        # fail making this active
        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-signed/%s/mark.json" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 200
        assert res.json["result"] == "error"
        assert (
            res.json["form_errors"]["Error_Main"]
            == "There was an error with your form. Already active."
        )

        # inactive ROUNDTRIP
        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-signed/%s/mark.json" % focus_id,
            {"action": "inactive"},
        )
        assert res.status_code == 200
        assert "CertificateSigned" in res.json
        assert res.json["CertificateSigned"]["id"] == focus_id
        assert res.json["CertificateSigned"]["is_active"] is False

        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-signed/%s/mark.json" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 200
        assert "CertificateSigned" in res.json
        assert res.json["CertificateSigned"]["id"] == focus_id
        assert res.json["CertificateSigned"]["is_active"] is True

        # then compromised
        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-signed/%s/mark.json" % focus_id,
            {"action": "revoked"},
        )
        assert res.status_code == 200
        assert "CertificateSigned" in res.json
        assert res.json["CertificateSigned"]["id"] == focus_id
        assert res.json["CertificateSigned"]["is_active"] is False
        assert res.json["CertificateSigned"]["is_revoked"] is True
        assert res.json["CertificateSigned"]["is_deactivated"] is True

    @routes_tested(("admin:certificate_signed:upload",))
    def test_upload_html(self):
        #
        # upload a new cert
        #
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/upload", status=200
        )
        _SelfSigned_id = "1"
        form = res.form
        form["certificate_file"] = Upload(
            self._filepath_testfile(
                TEST_FILES["CertificateSigneds"]["SelfSigned"][_SelfSigned_id]["cert"]
            )
        )
        form["chain_file"] = Upload(
            self._filepath_testfile(
                TEST_FILES["CertificateSigneds"]["SelfSigned"][_SelfSigned_id]["cert"]
            )
        )
        form["private_key_file_pem"] = Upload(
            self._filepath_testfile(
                TEST_FILES["CertificateSigneds"]["SelfSigned"][_SelfSigned_id]["pkey"]
            )
        )
        res2 = form.submit()
        assert res2.status_code == 303
        assert res2.location.startswith(
            """http://peter-sslers.example.com/.well-known/peter_sslers/certificate-signed/"""
        )

    @routes_tested(("admin:certificate_signed:upload|json",))
    def test_upload_json(self):
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/upload.json", status=200
        )
        chain_filepath = self._filepath_testfile("lets-encrypt-x1-cross-signed.pem.txt")
        _SelfSigned_id = "2"
        form = {}
        form["certificate_file"] = Upload(
            self._filepath_testfile(
                TEST_FILES["CertificateSigneds"]["SelfSigned"][_SelfSigned_id]["cert"]
            )
        )
        form["chain_file"] = Upload(
            self._filepath_testfile(
                TEST_FILES["CertificateSigneds"]["SelfSigned"][_SelfSigned_id]["cert"]
            )
        )
        form["private_key_file_pem"] = Upload(
            self._filepath_testfile(
                TEST_FILES["CertificateSigneds"]["SelfSigned"][_SelfSigned_id]["pkey"]
            )
        )
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/certificate-signed/upload.json", form
        )
        assert res2.status_code == 200
        assert res2.json["result"] == "success"
        assert res2.json["CertificateSigned"]["created"] in (True, False)
        certificate_id = res2.json["CertificateSigned"]["id"]
        res3 = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s.json" % certificate_id,
            status=200,
        )
        assert "CertificateSigned" in res3.json

    @unittest.skipUnless(RUN_NGINX_TESTS, "Not Running Against: nginx")
    @routes_tested(("admin:certificate_signed:focus:nginx_cache_expire",))
    def test_nginx_html(self):
        (focus_item, focus_id) = self._get_one()

        # this shifted to POST only
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/nginx-cache-expire"
            % focus_id,
            status=303,
        )
        assert RE_CertificateSigned_operation_nginx_expire__GET.match(res.location)

        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-signed/%s/nginx-cache-expire"
            % focus_id,
        )
        assert res.status_code == 303
        assert RE_CertificateSigned_operation_nginx_expire.match(res.location)

    @unittest.skipUnless(RUN_NGINX_TESTS, "Not Running Against: nginx")
    @routes_tested(("admin:certificate_signed:focus:nginx_cache_expire|json",))
    def test_nginx_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/nginx-cache-expire.json"
            % focus_id,
            status=200,
        )
        assert "HTTP POST required" in res.json["instructions"]

        res = self.testapp.post(
            "/.well-known/peter_sslers/certificate-signed/%s/nginx-cache-expire.json"
            % focus_id,
        )
        assert res.status_code == 200
        assert res.json["result"] == "success"

    def test_post_required_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/ari-check" % focus_id,
            status=303,
        )
        assert res.location.endswith(
            "?result=error&operation=ari-check&message=POST+required"
        )

    def test_post_required_json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_CertificateSigned.test_post_required_json
        """

        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `certificate-signed/%s/mark.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/mark.json" % focus_id,
            status=200,
        )
        assert "form_fields" in res.json
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `certificate-signed/%s/ari-check.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/ari-check.json" % focus_id,
            status=200,
        )
        assert "form_fields" not in res.json
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]


class FunctionalTests_CoverageAssuranceEvent(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_CoverageAssuranceEvent
    """

    def _get_one(self):
        # grab a Domain
        focus_item = (
            self.ctx.dbSession.query(model_objects.CoverageAssuranceEvent)
            .order_by(model_objects.CoverageAssuranceEvent.id.asc())
            .first()
        )
        assert focus_item is not None
        return focus_item, focus_item.id

    @routes_tested(
        (
            "admin:coverage_assurance_events",
            "admin:coverage_assurance_events:all",
            "admin:coverage_assurance_events:all_paginated",
            "admin:coverage_assurance_events:unresolved",
            "admin:coverage_assurance_events:unresolved_paginated",
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get(
            "/.well-known/peter_sslers/coverage-assurance-events", status=303
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/peter_sslers/coverage-assurance-events/all"
        )

        # roots
        res = self.testapp.get(
            "/.well-known/peter_sslers/coverage-assurance-events/all", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/coverage-assurance-events/unresolved", status=200
        )

        # paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/coverage-assurance-events/all/1", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/coverage-assurance-events/unresolved/1",
            status=200,
        )

    @routes_tested(
        (
            "admin:coverage_assurance_events:all|json",
            "admin:coverage_assurance_events:all_paginated|json",
            "admin:coverage_assurance_events:unresolved|json",
            "admin:coverage_assurance_events:unresolved_paginated|json",
        )
    )
    def test_list_json(self):
        # roots
        res = self.testapp.get(
            "/.well-known/peter_sslers/coverage-assurance-events/all.json", status=200
        )
        assert "CoverageAssuranceEvents" in res.json
        res = self.testapp.get(
            "/.well-known/peter_sslers/coverage-assurance-events/unresolved.json",
            status=200,
        )
        assert "CoverageAssuranceEvents" in res.json

        # paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/coverage-assurance-events/all/1.json", status=200
        )
        assert "CoverageAssuranceEvents" in res.json
        res = self.testapp.get(
            "/.well-known/peter_sslers/coverage-assurance-events/unresolved/1.json",
            status=200,
        )
        assert "CoverageAssuranceEvents" in res.json

    @routes_tested(
        (
            "admin:coverage_assurance_event:focus",
            "admin:coverage_assurance_event:focus:children",
        )
    )
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/coverage-assurance-event/%s" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/coverage-assurance-event/%s/children" % focus_id,
            status=200,
        )

    @routes_tested(
        (
            "admin:coverage_assurance_event:focus|json",
            "admin:coverage_assurance_event:focus:children|json",
        )
    )
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/coverage-assurance-event/%s.json" % focus_id,
            status=200,
        )
        assert "CoverageAssuranceEvent" in res.json
        assert res.json["CoverageAssuranceEvent"]["id"] == focus_id

        res = self.testapp.get(
            "/.well-known/peter_sslers/coverage-assurance-event/%s/children.json"
            % focus_id,
            status=200,
        )
        assert "CoverageAssuranceEvent" in res.json
        assert res.json["CoverageAssuranceEvent"]["id"] == focus_id
        assert "pagination" in res.json
        assert "CoverageAssuranceEvents_Children" in res.json
        assert "CoverageAssuranceEvents_Children_count" in res.json

    @routes_tested(
        (
            "admin:coverage_assurance_event:focus",
            "admin:coverage_assurance_event:focus:mark",
        )
    )
    def test_manipulate_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/coverage-assurance-event/%s" % focus_id,
            status=200,
        )
        _form_names = [i for i in res.forms.keys() if str(i).startswith("form-mark-")]
        # 4 possible options, but 3 should appear
        assert len(_form_names) == 3
        _option_1 = None
        form = None
        if "form-mark-abandoned" in _form_names:
            form = res.forms["form-mark-abandoned"]
            _option_1 = "abandoned"
        else:
            form = res.forms["form-mark-unresolved"]
            _option_1 = "unresolved"
        res2 = form.submit("resolution")  # the value is on the button "resolution"
        assert res2.status_code == 303
        assert RE_CoverageAssuranceEvent_mark.match(res2.location)

        # we should no longer have abandoned, and
        res_alt = self.testapp.get(
            "/.well-known/peter_sslers/coverage-assurance-event/%s" % focus_id,
            status=200,
        )
        _form_names_alt = [
            i for i in res.forms.keys() if str(i).startswith("form-mark-")
        ]
        assert len(_form_names_alt) == 3

        # now submit the first form again
        res2 = form.submit("resolution")  # the value is on the button "resolution"
        assert res2.status_code == 303
        assert RE_CoverageAssuranceEvent_mark_nochange.match(res2.location)

    @routes_tested(
        (
            "admin:coverage_assurance_event:focus|json",
            "admin:coverage_assurance_event:focus:mark|json",
        )
    )
    def test_manipulate_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/coverage-assurance-event/%s.json" % focus_id,
            status=200,
        )
        assert "CoverageAssuranceEvent" in res.json
        assert res.json["CoverageAssuranceEvent"]["id"] == focus_id

        res2 = self.testapp.get(
            "/.well-known/peter_sslers/coverage-assurance-event/%s/mark.json"
            % focus_id,
            status=200,
        )
        assert "instructions" in res2.json
        assert "valid_options" in res2.json
        assert "action" in res2.json["valid_options"]
        assert "resolution" in res2.json["valid_options"]

        # toggle between these 2
        resolution = None
        if (
            res.json["CoverageAssuranceEvent"]["coverage_assurance_resolution"]
            == "abandoned"
        ):
            resolution = "unresolved"
        else:
            resolution = "abandoned"

        res3 = self.testapp.post(
            "/.well-known/peter_sslers/coverage-assurance-event/%s/mark.json"
            % focus_id,
            {},
            status=200,
        )
        assert res3.json["result"] == "error"
        assert "form_errors" in res3.json
        assert res3.json["form_errors"]["Error_Main"] == "Nothing submitted."

        _payload = {"action": "resolution", "resolution": resolution}
        res4 = self.testapp.post(
            "/.well-known/peter_sslers/coverage-assurance-event/%s/mark.json"
            % focus_id,
            _payload,
            status=200,
        )
        assert res4.json["result"] == "success"
        assert "CoverageAssuranceEvent" in res4.json
        assert res4.json["CoverageAssuranceEvent"]["id"] == focus_id
        assert (
            res4.json["CoverageAssuranceEvent"]["coverage_assurance_resolution"]
            == resolution
        )

        # try it again
        res5 = self.testapp.post(
            "/.well-known/peter_sslers/coverage-assurance-event/%s/mark.json"
            % focus_id,
            _payload,
            status=200,
        )
        assert res5.json["result"] == "error"
        assert "form_errors" in res5.json
        assert (
            res5.json["form_errors"]["Error_Main"]
            == "There was an error with your form. No Change"
        )


class FunctionalTests_Domain(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_Domain
    """

    def _get_one(self):
        # grab a Domain
        focus_item = (
            self.ctx.dbSession.query(model_objects.Domain)
            .order_by(model_objects.Domain.id.asc())
            .first()
        )
        assert focus_item is not None
        return focus_item, focus_item.id

    @routes_tested(
        (
            "admin:domains",
            "admin:domains_paginated",
            "admin:domains:challenged",
            "admin:domains:challenged_paginated",
            "admin:domains:expiring",
            "admin:domains:expiring_paginated",
            "admin:domains:authz_potential",
            "admin:domains:authz_potential_paginated",
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/peter_sslers/domains", status=200)
        res = self.testapp.get(
            "/.well-known/peter_sslers/domains/challenged", status=200
        )
        res = self.testapp.get("/.well-known/peter_sslers/domains/expiring", status=200)
        res = self.testapp.get(
            "/.well-known/peter_sslers/domains/authz-potential", status=200
        )

        # paginated
        res = self.testapp.get("/.well-known/peter_sslers/domains/1", status=200)
        res = self.testapp.get(
            "/.well-known/peter_sslers/domains/challenged/1", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/domains/expiring/1", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/domains/authz-potential/1", status=200
        )

    @routes_tested(
        (
            "admin:domains|json",
            "admin:domains_paginated|json",
            "admin:domains:challenged|json",
            "admin:domains:challenged_paginated|json",
            "admin:domains:expiring|json",
            "admin:domains:expiring_paginated|json",
            "admin:domains:authz_potential|json",
            "admin:domains:authz_potential_paginated|json",
        )
    )
    def test_list_json(self):
        # json root
        res = self.testapp.get("/.well-known/peter_sslers/domains.json", status=200)
        assert "Domains" in res.json

        res = self.testapp.get(
            "/.well-known/peter_sslers/domains/challenged.json", status=200
        )
        assert "Domains" in res.json

        res = self.testapp.get(
            "/.well-known/peter_sslers/domains/expiring.json", status=200
        )
        assert "Domains" in res.json

        res = self.testapp.get(
            "/.well-known/peter_sslers/domains/authz-potential.json", status=200
        )
        assert "Domains" in res.json

        # json paginated
        res = self.testapp.get("/.well-known/peter_sslers/domains/1.json", status=200)
        assert "Domains" in res.json

        res = self.testapp.get(
            "/.well-known/peter_sslers/domains/challenged/1.json", status=200
        )
        assert "Domains" in res.json

        res = self.testapp.get(
            "/.well-known/peter_sslers/domains/expiring/1.json", status=200
        )
        assert "Domains" in res.json

        res = self.testapp.get(
            "/.well-known/peter_sslers/domains/authz-potential/1.json", status=200
        )
        assert "Domains" in res.json

    @routes_tested(("admin:domains:search",))
    def test_search_html(self):
        res = self.testapp.get("/.well-known/peter_sslers/domains/search", status=200)
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/domains/search", {"domain": "example.com"}
        )

    @routes_tested(("admin:domains:search|json",))
    def test_search_json(self):
        res = self.testapp.get(
            "/.well-known/peter_sslers/domains/search.json", status=200
        )
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/domains/search.json", {"domain": "example.com"}
        )

    @routes_tested(
        (
            "admin:domain:focus",
            "admin:domain:focus:acme_authorizations",
            "admin:domain:focus:acme_authorizations_paginated",
            "admin:domain:focus:acme_authorization_potentials",
            "admin:domain:focus:acme_authorization_potentials_paginated",
            "admin:domain:focus:acme_challenges",
            "admin:domain:focus:acme_challenges_paginated",
            "admin:domain:focus:acme_orders",
            "admin:domain:focus:acme_orders_paginated",
            "admin:domain:focus:certificate_requests",
            "admin:domain:focus:certificate_requests_paginated",
            "admin:domain:focus:domain_autocerts",
            "admin:domain:focus:domain_autocerts_paginated",
            "admin:domain:focus:certificate_signeds",
            "admin:domain:focus:certificate_signeds_paginated",
            "admin:domain:focus:unique_fqdn_sets",
            "admin:domain:focus:unique_fqdn_sets_paginated",
            "admin:domain:focus:uniquely_challenged_fqdn_sets",
            "admin:domain:focus:uniquely_challenged_fqdn_sets_paginated",
        )
    )
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()
        focus_name = focus_item.domain_name

        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s" % focus_name, status=200
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/acme-authorizations" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/acme-authorizations/1" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/acme-authz-potentials" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/acme-authz-potentials/1" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/acme-challenges" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/acme-challenges/1" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/acme-orders" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/acme-orders/1" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/domain-autocerts" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/domain-autocerts/1" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/certificate-requests" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/certificate-requests/1" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/certificate-signeds" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/certificate-signeds/1" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/unique-fqdn-sets" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/unique-fqdn-sets/1" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/uniquely-challenged-fqdn-sets"
            % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/uniquely-challenged-fqdn-sets/1"
            % focus_id,
            status=200,
        )

    @routes_tested(
        (
            "admin:domain:focus|json",
            "admin:domain:focus:config|json",
            "admin:domain:focus:calendar|json",
        )
    )
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()
        focus_name = focus_item.domain_name

        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s.json" % focus_id, status=200
        )
        assert "Domain" in res.json
        assert res.json["Domain"]["id"] == focus_id
        assert res.json["Domain"]["domain_name"].lower() == focus_name.lower()

        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s.json" % focus_name, status=200
        )
        assert "Domain" in res.json
        assert res.json["Domain"]["id"] == focus_id
        assert res.json["Domain"]["domain_name"].lower() == focus_name.lower()

        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/config.json" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/calendar.json" % focus_id, status=200
        )

    @routes_tested(("admin:domain:focus:mark", "admin:domain:focus:update_recents"))
    def test_manipulate_html(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_Domain.test_manipulate_html
        """
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/update-recents" % focus_id, status=303
        )
        assert (
            res.location
            == """http://peter-sslers.example.com/.well-known/peter_sslers/domain/%s?result=error&operation=update-recents&message=POST+required"""
            % focus_id
        )

        res = self.testapp.post(
            "/.well-known/peter_sslers/domain/%s/update-recents" % focus_id, status=303
        )
        assert (
            res.location
            == """http://peter-sslers.example.com/.well-known/peter_sslers/domain/%s?result=success&operation=update-recents"""
            % focus_id
        )

    @routes_tested(
        ("admin:domain:focus:mark|json", "admin:domain:focus:update_recents|json")
    )
    def test_manipulate_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.post(
            "/.well-known/peter_sslers/domain/%s/update-recents.json" % focus_id,
            status=200,
        )
        assert res.status_code == 200
        assert res.json["result"] == "success"
        assert "Domain" in res.json

    @unittest.skipUnless(RUN_API_TESTS__ACME_DNS_API, "Not Running Against: acme-dns")
    @routes_tested(
        (
            "admin:domain:new",
            "admin:domain:focus:acme_dns_server:new",
            "admin:domain:focus:acme_dns_server_accounts",
        )
    )
    def test_acme_dns_server_new__html(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_Domain.test_acme_dns_server_new__html
        """
        res = self.testapp.get("/.well-known/peter_sslers/domain/new", status=200)
        assert "form-domain-new" in res.forms
        form = res.forms["form-domain-new"]
        form["domain_name"] = TEST_FILES["AcmeDnsServerAccount"]["test-new-via-Domain"][
            "html"
        ]["Domain"]
        res2 = form.submit()
        assert res2.status_code == 303
        matched = RE_Domain_new.match(res2.location)
        assert matched
        focus_id = matched.groups()[0]

        # get the record
        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s" % focus_id, status=200
        )
        assert """<th>AcmeDnsConfiguration</th>""" in res.text
        assert (
            """/.well-known/peter_sslers/domain/%s/acme-dns-server/new""" % focus_id
        ) in res.text

        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/acme-dns-server/new" % focus_id,
            status=200,
        )
        assert "form-acme_dns_server-new" in res.forms
        form = res.forms["form-acme_dns_server-new"]
        form.submit_fields()
        _options = [int(opt[0]) for opt in form["acme_dns_server_id"].options]
        if 1 not in _options:
            raise ValueError("we should have a `1` in _options")
        form["acme_dns_server_id"] = "1"
        res2 = form.submit()
        check_error_AcmeDnsServerError("html", res2)
        assert res2.status_code == 303
        assert RE_Domain_new_AcmeDnsServerAccount.match(res2.location)

        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s" % focus_id, status=200
        )
        assert """AcmeDnsServerAccounts - Existing""" in res.text
        assert (
            """href="/.well-known/peter_sslers/domain/%s/acme-dns-server-accounts"""
            % focus_id
        ) in res.text

        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/acme-dns-server-accounts" % focus_id,
            status=200,
        )
        assert "/.well-known/peter_sslers/acme-dns-server/" in res.text
        assert "/.well-known/peter_sslers/acme-dns-server-account/" in res.text

        # force a new AcmeDnsServerAccount, and it should fail
        # originally this had a 200 return with errors
        # now we do a 303 redirect
        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/acme-dns-server/new" % focus_id,
            status=303,
        )
        assert (
            res.location
            == """http://peter-sslers.example.com/.well-known/peter_sslers/domain/%s/acme-dns-server-accounts?result=error&error=accounts-exist&operation=new"""
            % focus_id
        )

    @unittest.skipUnless(RUN_API_TESTS__ACME_DNS_API, "Not Running Against: acme-dns")
    @routes_tested(
        (
            "admin:domain:new|json",
            "admin:domain:focus:acme_dns_server:new|json",
            "admin:domain:focus:acme_dns_server_accounts|json",
        )
    )
    def test_acme_dns_server_new__json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_Domain.test_acme_dns_server_new__json
        """
        res = self.testapp.post(
            "/.well-known/peter_sslers/domain/new.json", {}, status=200
        )
        assert res.json["result"] == "error"
        assert "form_errors" in res.json
        assert res.json["form_errors"]["Error_Main"] == "Nothing submitted."

        _payload = {
            "domain_name": TEST_FILES["AcmeDnsServerAccount"]["test-new-via-Domain"][
                "json"
            ]["Domain"],
        }
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/domain/new.json", _payload, status=200
        )
        assert res2.status_code == 200
        assert res2.json["result"] == "success"
        assert "Domain" in res2.json
        focus_id = res2.json["Domain"]["id"]

        # get the record
        res3 = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s.json" % focus_id, status=200
        )
        assert "Domain" in res3.json
        assert res3.json["Domain"]["id"] == focus_id
        # note: there is no signifier to add a new acme-dns server account

        res4 = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/acme-dns-server/new.json" % focus_id,
            status=200,
        )
        assert "instructions" in res4.json  # already covered
        assert "HTTP POST required" in res4.json["instructions"]  # already covered
        assert "valid_options" in res4.json
        assert "acme_dns_server_id" in res4.json["valid_options"]
        assert 1 in res4.json["valid_options"]["acme_dns_server_id"]

        res5 = self.testapp.post(
            "/.well-known/peter_sslers/domain/%s/acme-dns-server/new.json" % focus_id,
            {},
            status=200,
        )
        assert res5.json["result"] == "error"
        assert "form_errors" in res5.json
        assert res5.json["form_errors"]["Error_Main"] == "Nothing submitted."

        _payload = {
            "acme_dns_server_id": 1,
        }

        res6 = self.testapp.post(
            "/.well-known/peter_sslers/domain/%s/acme-dns-server/new.json" % focus_id,
            _payload,
            status=200,
        )
        assert res6.status_code == 200
        check_error_AcmeDnsServerError("json", res6)

        assert res6.json["result"] == "success"
        assert "AcmeDnsServer" in res6.json["AcmeDnsServerAccount"]
        assert res6.json["AcmeDnsServerAccount"]["AcmeDnsServer"]["id"] == 1
        acme_dns_server_account_id = res6.json["AcmeDnsServerAccount"]["id"]

        res7 = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/acme-dns-server-accounts.json"
            % focus_id,
            status=200,
        )
        assert "Domain" in res7.json
        assert res7.json["Domain"]["id"] == focus_id
        assert "AcmeDnsServerAccounts" in res7.json
        account_ids = [_acct["id"] for _acct in res7.json["AcmeDnsServerAccounts"]]
        assert acme_dns_server_account_id in account_ids

        # force a new AcmeDnsServerAccount, and it should fail
        res8 = self.testapp.post(
            "/.well-known/peter_sslers/domain/%s/acme-dns-server/new.json" % focus_id,
            _payload,
            # status=200,
        )
        assert res8.json["result"] == "error"
        assert "form_errors" in res8.json
        assert (
            res8.json["form_errors"]["Error_Main"]
            == "There was an error with your form."
        )
        assert (
            res8.json["form_errors"]["acme_dns_server_id"]
            == "Existing record for this AcmeDnsServer."
        )

    @unittest.skipUnless(RUN_NGINX_TESTS, "Not Running Against: nginx")
    @routes_tested(("admin:domain:focus:nginx_cache_expire",))
    def test_nginx_html(self):
        (focus_item, focus_id) = self._get_one()
        focus_name = focus_item.domain_name

        # this shifted to POST only
        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/nginx-cache-expire" % focus_id,
            status=303,
        )
        assert RE_Domain_operation_nginx_expire__GET.match(res.location)

        res = self.testapp.post(
            "/.well-known/peter_sslers/domain/%s/nginx-cache-expire" % focus_id
        )
        assert res.status_code == 303
        assert RE_Domain_operation_nginx_expire.match(res.location)

    @unittest.skipUnless(RUN_NGINX_TESTS, "Not Running Against: nginx")
    @routes_tested(("admin:domain:focus:nginx_cache_expire|json",))
    def test_nginx_json(self):
        (focus_item, focus_id) = self._get_one()
        focus_name = focus_item.domain_name

        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/nginx-cache-expire.json" % focus_id,
            status=200,
        )
        assert "HTTP POST required" in res.json["instructions"]

        res = self.testapp.post(
            "/.well-known/peter_sslers/domain/%s/nginx-cache-expire.json" % focus_id,
        )
        assert res.status_code == 200
        assert res.json["result"] == "success"

    def test_post_required_json(self):
        (focus_item, focus_id) = self._get_one()
        # the `focus_item` is active,

        # !!!: test `POST required` `domain/%s/update-recents.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/update-recents.json" % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `domain/%s/new.json`
        res = self.testapp.get("/.well-known/peter_sslers/domain/new.json", status=200)
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `domain/%s/acme-dns-server/new.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/domain/%s/acme-dns-server/new.json" % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]


class FunctionalTests_DomainAutocert(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_DomainAutocert
    """

    @routes_tested(
        (
            "admin:domain_autocerts",
            "admin:domain_autocerts_paginated",
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/peter_sslers/domain-autocerts", status=200)

        # paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/domain-autocerts/1", status=200
        )

    @routes_tested(
        (
            "admin:domain_autocerts|json",
            "admin:domain_autocerts_paginated|json",
        )
    )
    def test_list_json(self):
        # json root
        res = self.testapp.get(
            "/.well-known/peter_sslers/domain-autocerts.json", status=200
        )
        assert "DomainAutocerts" in res.json

        # json paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/domain-autocerts/1.json", status=200
        )
        assert "DomainAutocerts" in res.json


class FunctionalTests_DomainBlocklisted(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_DomainBlocklisted
    """

    @routes_tested(
        (
            "admin:domains_blocklisted",
            "admin:domains_blocklisted_paginated",
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get(
            "/.well-known/peter_sslers/domains-blocklisted", status=200
        )

        # paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/domains-blocklisted/1", status=200
        )

    @routes_tested(
        (
            "admin:domains_blocklisted|json",
            "admin:domains_blocklisted_paginated|json",
        )
    )
    def test_list_json(self):
        # json root
        res = self.testapp.get(
            "/.well-known/peter_sslers/domains-blocklisted.json", status=200
        )
        assert "DomainsBlocklisted" in res.json

        # json paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/domains-blocklisted/1.json", status=200
        )
        assert "DomainsBlocklisted" in res.json

    def test_AcmeOrder_new_fails(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_DomainBlocklisted.test_AcmeOrder_new_fails
        """
        _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]

        # "admin:acme_order:new:freeform",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/new/freeform", status=200
        )

        form = res.form
        _form_fields = form.fields.keys()
        assert "account_key_option" in _form_fields
        form["account_key_option"].force_value("account_key_global_default")
        form["private_key_option"].force_value("account_default")
        form["private_key_cycle"].force_value("account_default")
        form["domain_names_http01"] = "always-fail.example.com, foo.example.com"
        form["processing_strategy"].force_value("create_order")
        res2 = form.submit()

        assert res2.status_code == 200
        assert "There was an error with your form." in res2.text
        assert (
            "The following Domains are blocklisted: always-fail.example.com"
            in res2.text
        )


class FunctionalTests_Operations(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_Operations
    """

    @routes_tested(
        (
            "admin:operations",
            "admin:operations:log",
            "admin:operations:log_paginated",
            "admin:operations:log:focus",
            "admin:operations:object_log",
            "admin:operations:object_log_paginated",
            "admin:operations:object_log:focus",
            "admin:operations:nginx",
            "admin:operations:nginx_paginated",
            "admin:operations:redis",
            "admin:operations:redis_paginated",
        )
    )
    def test_passive(self):
        focus_item = (
            self.ctx.dbSession.query(model_objects.OperationsEvent)
            .order_by(model_objects.OperationsEvent.id.asc())
            .limit(1)
            .one()
        )

        focus_item_event = (
            self.ctx.dbSession.query(model_objects.OperationsObjectEvent)
            .order_by(model_objects.OperationsObjectEvent.id.asc())
            .limit(1)
            .one()
        )

        # this should redirect
        res = self.testapp.get("/.well-known/peter_sslers/operations", status=302)
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/operations/log"
        )

        res = self.testapp.get("/.well-known/peter_sslers/operations/log", status=200)
        res = self.testapp.get("/.well-known/peter_sslers/operations/log/1", status=200)
        res = self.testapp.get(
            "/.well-known/peter_sslers/operations/log/item/%s" % focus_item.id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/operations/object-log", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/operations/object-log/1", status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/operations/object-log/item/%s"
            % focus_item_event.id,
            status=200,
        )

        _nginx = (
            True
            if (
                (
                    "enable_nginx"
                    in self.testapp.app.registry.settings["application_settings"]
                )
                and (
                    self.testapp.app.registry.settings["application_settings"][
                        "enable_nginx"
                    ]
                    is True
                )
            )
            else False
        )
        if _nginx:
            res = self.testapp.get(
                "/.well-known/peter_sslers/operations/nginx", status=200
            )
            res = self.testapp.get(
                "/.well-known/peter_sslers/operations/nginx/1", status=200
            )
        else:
            res = self.testapp.get(
                "/.well-known/peter_sslers/operations/nginx", status=302
            )
            assert (
                res.location
                == "http://peter-sslers.example.com/.well-known/peter_sslers?result=error&error=nginx+is+not+enabled"
            )

            res = self.testapp.get(
                "/.well-known/peter_sslers/operations/nginx/1", status=302
            )
            assert (
                res.location
                == "http://peter-sslers.example.com/.well-known/peter_sslers?result=error&error=nginx+is+not+enabled"
            )

        res = self.testapp.get("/.well-known/peter_sslers/operations/redis", status=200)
        res = self.testapp.get(
            "/.well-known/peter_sslers/operations/redis/1", status=200
        )


class FunctionalTests_PrivateKey(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_PrivateKey
    """

    def _get_one(self):
        # grab a Key
        # loop these in desc order, because latter items shouldn't have anything associated on them.
        focus_item = (
            self.ctx.dbSession.query(model_objects.PrivateKey)
            .filter(
                model_objects.PrivateKey.is_active.is_(True),
                model_objects.PrivateKey.private_key_type_id
                != model_utils.PrivateKeyType.PLACEHOLDER,
            )
            .order_by(model_objects.PrivateKey.id.desc())
            .first()
        )
        assert focus_item is not None
        return focus_item, focus_item.id

    @routes_tested(
        (
            "admin:private_keys",
            "admin:private_keys_paginated",
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/peter_sslers/private-keys", status=200)

        # paginated
        res = self.testapp.get("/.well-known/peter_sslers/private-keys/1", status=200)

    @routes_tested(
        (
            "admin:private_keys|json",
            "admin:private_keys_paginated|json",
        )
    )
    def test_list_json(self):
        # json
        res = self.testapp.get(
            "/.well-known/peter_sslers/private-keys.json", status=200
        )
        assert "PrivateKeys" in res.json

        res = self.testapp.get(
            "/.well-known/peter_sslers/private-keys/1.json", status=200
        )
        assert "PrivateKeys" in res.json

    @routes_tested(
        (
            "admin:private_key:focus",
            "admin:private_key:focus:certificate_requests",
            "admin:private_key:focus:certificate_requests_paginated",
            "admin:private_key:focus:certificate_signeds",
            "admin:private_key:focus:certificate_signeds_paginated",
        )
    )
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/private-key/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/private-key/%s/certificate-requests" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/private-key/%s/certificate-requests/1"
            % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/private-key/%s/certificate-signeds" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/private-key/%s/certificate-signeds/1" % focus_id,
            status=200,
        )

    @routes_tested(
        (
            "admin:private_key:focus|json",
            "admin:private_key:focus:parse|json",
        )
    )
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/private-key/%s.json" % focus_id, status=200
        )
        assert "PrivateKey" in res.json
        assert res.json["PrivateKey"]["id"] == focus_id

        res = self.testapp.get(
            "/.well-known/peter_sslers/private-key/%s/parse.json" % focus_id, status=200
        )
        assert str(focus_id) in res.json

    @routes_tested(("admin:private_key:focus:raw",))
    def test_focus_raw(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/private-key/%s/key.key" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/private-key/%s/key.pem" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/private-key/%s/key.pem.txt" % focus_id,
            status=200,
        )

    @routes_tested(("admin:private_key:focus:mark",))
    def test_manipulate_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/private-key/%s/mark" % focus_id,
            status=303,
        )
        assert res.location.endswith("?result=error&error=post+required&operation=mark")

        # the `focus_item` is active, so it can't be compromised or inactive
        if focus_item.is_compromised:
            raise ValueError("focus_item.is_compromised")

        if not focus_item.is_active:
            raise ValueError("NOT focus_item.is_active")

        # fail making this active
        res = self.testapp.post(
            "/.well-known/peter_sslers/private-key/%s/mark" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 303
        assert res.location.endswith(
            "?result=error&error=Error_Main--There+was+an+error+with+your+form.+Already+activated.&operation=mark&action=active"
        )

        # inactive ROUNDTRIP
        res = self.testapp.post(
            "/.well-known/peter_sslers/private-key/%s/mark" % focus_id,
            {"action": "inactive"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=inactive")

        res = self.testapp.post(
            "/.well-known/peter_sslers/private-key/%s/mark" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=active")

        # then compromised
        res = self.testapp.post(
            "/.well-known/peter_sslers/private-key/%s/mark" % focus_id,
            {"action": "compromised"},
        )
        assert res.status_code == 303
        assert res.location.endswith(
            "?result=success&operation=mark&action=compromised"
        )

    @routes_tested(("admin:private_key:focus:mark|json",))
    def test_manipulate_json(self):
        (focus_item, focus_id) = self._get_one()

        # the `focus_item` is active, so it can't be compromised or inactive
        if focus_item.is_compromised:
            raise ValueError("focus_item.is_compromised")

        if not focus_item.is_active:
            raise ValueError("NOT focus_item.is_active")

        # fail making this active
        res = self.testapp.post(
            "/.well-known/peter_sslers/private-key/%s/mark.json" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 200
        assert res.json["result"] == "error"
        assert (
            res.json["form_errors"]["Error_Main"]
            == "There was an error with your form. Already activated."
        )

        # inactive ROUNDTRIP
        res = self.testapp.post(
            "/.well-known/peter_sslers/private-key/%s/mark.json" % focus_id,
            {"action": "inactive"},
        )
        assert res.status_code == 200
        assert "PrivateKey" in res.json
        assert res.json["PrivateKey"]["id"] == focus_id
        assert res.json["PrivateKey"]["is_active"] is False

        res = self.testapp.post(
            "/.well-known/peter_sslers/private-key/%s/mark.json" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 200
        assert "PrivateKey" in res.json
        assert res.json["PrivateKey"]["is_active"] is True

        # then compromised
        res = self.testapp.post(
            "/.well-known/peter_sslers/private-key/%s/mark.json" % focus_id,
            {"action": "compromised"},
        )
        assert res.status_code == 200
        assert "PrivateKey" in res.json
        assert res.json["PrivateKey"]["is_active"] is False
        assert res.json["PrivateKey"]["is_compromised"] is True

    @routes_tested(
        (
            "admin:private_key:upload",
            "admin:private_key:new",
        )
    )
    def test_new_html(self):
        # this should be creating a new key
        _key_filename = TEST_FILES["PrivateKey"]["2"]["file"]
        key_filepath = self._filepath_testfile(_key_filename)
        res = self.testapp.get(
            "/.well-known/peter_sslers/private-key/upload", status=200
        )
        form = res.form
        form["private_key_file_pem"] = Upload(key_filepath)
        res2 = form.submit()
        assert res2.status_code == 303
        assert """/.well-known/peter_sslers/private-key/""" in res2.location
        # for some reason, we don't always "create" this.
        assert """?result=success""" in res2.location
        res3 = self.testapp.get(res2.location, status=200)

        # okay now new
        res = self.testapp.get("/.well-known/peter_sslers/private-key/new", status=200)
        form = res.form
        new_fields = dict(form.submit_fields())
        assert "private_key_generate" in new_fields
        assert new_fields["private_key_generate"] == "EC_P256"  # system default

        res2 = form.submit()
        assert res2.status_code == 303
        # 'http://peter-sslers.example.com/.well-known/peter_sslers/private-key/3?result=success&is_created=1'
        assert res2.location.startswith(
            """http://peter-sslers.example.com/.well-known/peter_sslers/private-key/"""
        )
        # for some reason, we don't always "create" this.
        assert res2.location.endswith("""?result=success&is_created=1&operation=new""")
        res3 = self.testapp.get(res2.location, status=200)

    @routes_tested(
        (
            "admin:private_key:upload|json",
            "admin:private_key:new|json",
        )
    )
    def test_new_json(self):
        _key_filename = TEST_FILES["PrivateKey"]["2"]["file"]
        key_filepath = self._filepath_testfile(_key_filename)

        res = self.testapp.get(
            "/.well-known/peter_sslers/private-key/upload.json", status=200
        )
        assert "form_fields" in res.json

        form = {}
        form["private_key_file_pem"] = Upload(key_filepath)
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/private-key/upload.json", form
        )
        assert res2.status_code == 200
        assert "PrivateKey" in res2.json

        res = self.testapp.get(
            "/.well-known/peter_sslers/private-key/new.json", status=200
        )
        assert "form_fields" in res.json

        form = {"private_key_generate": "RSA_2048"}
        res2 = self.testapp.post("/.well-known/peter_sslers/private-key/new.json", form)
        assert res2.status_code == 200
        assert "PrivateKey" in res2.json

    def test_post_required_json(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `private-key/%s/mark.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/private-key/%s/mark.json" % focus_id,
            status=200,
        )
        assert "form_fields" in res.json
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]


class FunctionalTests_RenewalConfiguration(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_RenewalConfiguration
    """

    def _get_one(self):
        # grab an order
        focus_item = (
            self.ctx.dbSession.query(model_objects.RenewalConfiguration)
            .order_by(model_objects.RenewalConfiguration.id.asc())
            .first()
        )
        assert focus_item is not None
        return focus_item, focus_item.id

    def _make_one(self) -> model_objects.RenewalConfiguration:
        """
        make a random one, so we don't worry about competing challenges on a new order
        """
        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/new.json", status=200
        )
        assert "form_fields" in res.json

        account_key_global_default = res.json["valid_options"][
            "AcmeAccount_GlobalDefault"
        ]["AcmeAccountKey"]["key_pem_md5"]

        form = {}
        form["account_key_option"] = "account_key_global_default"
        form["account_key_global_default"] = account_key_global_default
        form["private_key_cycle"] = "account_default"
        form["key_technology"] = "account_default"
        form["domain_names_http01"] = generate_random_domain(testCase=self)

        res2 = self.testapp.post(
            "/.well-known/peter_sslers/renewal-configuration/new.json",
            form,
        )
        assert res2.json["result"] == "success"
        assert "RenewalConfiguration" in res2.json

        focus_item = (
            self.ctx.dbSession.query(model_objects.RenewalConfiguration)
            .filter(
                model_objects.RenewalConfiguration.id
                == res2.json["RenewalConfiguration"]["id"]
            )
            .first()
        )
        assert focus_item is not None
        return focus_item

    @routes_tested(
        (
            "admin:renewal_configurations",
            "admin:renewal_configurations:all",
            "admin:renewal_configurations:all_paginated",
            "admin:renewal_configurations:active",
            "admin:renewal_configurations:active_paginated",
            "admin:renewal_configurations:disabled",
            "admin:renewal_configurations:disabled_paginated",
        )
    )
    def test_list_html(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_RenewalConfiguration.test_list_html
        """
        # root
        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configurations", status=303
        )
        assert (
            res.location
            == """http://peter-sslers.example.com/.well-known/peter_sslers/renewal-configurations/active"""
        )

        for _type in (
            "all",
            "active",
            "disabled",
        ):
            res = self.testapp.get(
                "/.well-known/peter_sslers/renewal-configurations/%s" % _type,
                status=200,
            )
            res = self.testapp.get(
                "/.well-known/peter_sslers/renewal-configurations/%s/1" % _type,
                status=200,
            )

    @routes_tested(
        (
            "admin:renewal_configurations|json",
            "admin:renewal_configurations:all|json",
            "admin:renewal_configurations:all_paginated|json",
            "admin:renewal_configurations:active|json",
            "admin:renewal_configurations:active_paginated|json",
            "admin:renewal_configurations:disabled|json",
            "admin:renewal_configurations:disabled_paginated|json",
        )
    )
    def test_list_json(self):
        # json root
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_RenewalConfiguration.test_list_json
        """
        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configurations.json", status=303
        )
        assert (
            res.location
            == """http://peter-sslers.example.com/.well-known/peter_sslers/renewal-configurations/active.json"""
        )

        for _type in (
            "all",
            "active",
            "disabled",
        ):
            res = self.testapp.get(
                "/.well-known/peter_sslers/renewal-configurations/%s.json" % _type,
                status=200,
            )
            assert "RenewalConfigurations" in res.json
            res = self.testapp.get(
                "/.well-known/peter_sslers/renewal-configurations/%s/1.json" % _type,
                status=200,
            )
            assert "RenewalConfigurations" in res.json

    @routes_tested(
        (
            "admin:renewal_configuration:focus",
            "admin:renewal_configuration:focus:acme_orders",
            "admin:renewal_configuration:focus:acme_orders_paginated",
            "admin:renewal_configuration:focus:certificate_signeds",
            "admin:renewal_configuration:focus:certificate_signeds_paginated",
        )
    )
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/acme-orders" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/acme-orders/1"
            % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/certificate-signeds"
            % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/certificate-signeds/1"
            % focus_id,
            status=200,
        )

    @routes_tested(
        (
            "admin:renewal_configuration:focus|json",
            "admin:renewal_configuration:focus:acme_orders|json",
            "admin:renewal_configuration:focus:acme_orders_paginated|json",
            "admin:renewal_configuration:focus:certificate_signeds|json",
            "admin:renewal_configuration:focus:certificate_signeds_paginated|json",
        )
    )
    def test_focus_json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_RenewalConfiguration.test_focus_json
        """
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s.json" % focus_id,
            status=200,
        )
        assert "RenewalConfiguration" in res.json
        assert res.json["RenewalConfiguration"]["id"] == focus_id

        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/acme-orders.json"
            % focus_id,
            status=200,
        )
        assert "AcmeOrders" in res.json

        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/acme-orders/1.json"
            % focus_id,
            status=200,
        )
        assert "AcmeOrders" in res.json

        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/certificate-signeds.json"
            % focus_id,
            status=200,
        )
        assert "CertificateSigneds" in res.json

        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/certificate-signeds/1.json"
            % focus_id,
            status=200,
        )
        assert "CertificateSigneds" in res.json

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:renewal_configuration:focus:mark",
            "admin:renewal_configuration:focus:new_order",
            "admin:renewal_configuration:focus:new_configuration",
        )
    )
    def test_manipulate_html(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_RenewalConfiguration.test_manipulate_html
        """
        focus_item = self._make_one()
        focus_id = focus_item.id

        # !!!: mark

        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/mark" % focus_id,
            status=303,
        )
        assert res.location.endswith("?result=error&error=post+required&operation=mark")

        if focus_item.is_active:
            action_current = "active"
            action_target = "inactive"
            already = "Already+activated"
        else:
            action_current = "inactive"
            action_target = "active"
            already = "Already+deactivated"

        # fail making this active
        res = self.testapp.post(
            "/.well-known/peter_sslers/renewal-configuration/%s/mark" % focus_id,
            {"action": action_current},
        )
        assert res.status_code == 303
        assert res.location.endswith(
            "?result=error&error=Error_Main--There+was+an+error+with+your+form.+%s.&operation=mark&action=active"
            % already
        )

        # inactive ROUNDTRIP
        res = self.testapp.post(
            "/.well-known/peter_sslers/renewal-configuration/%s/mark" % focus_id,
            {"action": action_target},
        )
        assert res.status_code == 303
        assert res.location.endswith(
            "?result=success&operation=mark&action=%s" % action_target
        )

        res = self.testapp.post(
            "/.well-known/peter_sslers/renewal-configuration/%s/mark" % focus_id,
            {"action": action_current},
        )
        assert res.status_code == 303
        assert res.location.endswith(
            "?result=success&operation=mark&action=%s" % action_current
        )

        # !!!: new order
        note = generate_random_domain(testCase=self)
        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/new-order" % focus_id,
            status=200,
        )
        form = res.forms["form-renewal_configuration-new_order"]
        form["processing_strategy"].force_value("create_order")
        form["note"].force_value(note)
        res2 = form.submit()
        assert res2.status_code == 303
        assert res2.location.endswith("?result=success&operation=renewal+configuration")
        assert "/.well-known/peter_sslers/acme-order/" in res2.location
        res3 = self.testapp.get(res2.location)
        assert "<code>%s</code>" % note in res3.text

        # !!!: new configuration
        note = generate_random_domain(testCase=self)
        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/new-configuration"
            % focus_id,
            status=200,
        )
        form = res.forms["form-renewal_configuration-new_configuration"]
        form["domain_names_dns01"] = ""
        form["domain_names_http01"] = ",".join(
            [focus_item.domains_as_list[0], generate_random_domain(testCase=self)]
        )
        form["note"] = note
        res2 = form.submit()
        assert res2.status_code == 303
        matched = RE_RenewalConfiguration.match(res2.location)
        assert matched
        obj_id = matched.groups()[0]
        res3 = self.testapp.get(res2.location)
        assert "<code>%s</code>" % note in res3.text

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:renewal_configuration:focus:mark|json",
            "admin:renewal_configuration:focus:new_order|json",
            "admin:renewal_configuration:focus:new_configuration|json",
        )
    )
    def test_manipulate_json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_RenewalConfiguration.test_manipulate_json
        """

        focus_item = self._make_one()
        focus_id = focus_item.id

        # !!!: mark

        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/mark.json" % focus_id,
            status=200,
        )

        if focus_item.is_active:
            action_current = "active"
            action_target = "inactive"
            already = "Already activated"
        else:
            action_current = "inactive"
            action_target = "active"
            already = "Already deactivated"

        # fail making this active
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/renewal-configuration/%s/mark.json" % focus_id,
            {"action": action_current},
        )
        assert res2.status_code == 200
        assert res2.json["result"] == "error"
        assert (
            res2.json["form_errors"]["Error_Main"]
            == "There was an error with your form. %s." % already
        )

        # inactive ROUNDTRIP
        res3 = self.testapp.post(
            "/.well-known/peter_sslers/renewal-configuration/%s/mark.json" % focus_id,
            {"action": action_target},
        )
        assert res3.status_code == 200
        assert res3.json["result"] == "success"

        res4 = self.testapp.post(
            "/.well-known/peter_sslers/renewal-configuration/%s/mark.json" % focus_id,
            {"action": action_current},
        )
        assert res4.status_code == 200
        assert res4.json["result"] == "success"

        # !!!: new order
        note = generate_random_domain(testCase=self)
        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/new-order.json"
            % focus_id,
            status=200,
        )
        res = self.testapp.post(
            "/.well-known/peter_sslers/renewal-configuration/%s/new-order.json"
            % focus_id,
            {
                "processing_strategy": "create_order",
                "note": note,
            },
        )
        assert res.status_code == 200
        assert res.json["result"] == "success"
        assert "AcmeOrder" in res.json
        acme_order_id = res.json["AcmeOrder"]["id"]
        assert res.json["AcmeOrder"]["note"] == note

        # !!!: new configuration
        note = generate_random_domain(testCase=self)
        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/new-configuration.json"
            % focus_id,
            status=200,
        )
        form = {
            "account_key_option": "account_key_global_default",
            "account_key_global_default": res.json["valid_options"][
                "AcmeAccount_GlobalDefault"
            ]["AcmeAccountKey"]["key_pem_md5"],
            "private_key_cycle": "account_default",
            "key_technology": "account_default",
            "processing_strategy": "create_order",
            "domain_names_http01": ",".join(
                [focus_item.domains_as_list[0], generate_random_domain(testCase=self)]
            ),
            "note": note,
        }
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/renewal-configuration/%s/new-configuration.json"
            % focus_id,
            form,
        )
        assert res2.status_code == 200
        assert res2.json["result"] == "success"
        assert "RenewalConfiguration" in res2.json
        assert res2.json["RenewalConfiguration"]["note"] == note

    @routes_tested(("admin:renewal_configuration:new",))
    def test_new_html(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_RenewalConfiguration.test_new_html
        """

        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/new", status=200
        )

        note = generate_random_domain(testCase=self)

        form = res.form
        form["account_key_option"].force_value("account_key_global_default")
        # this is rendered in the html
        # form["account_key_global_default"] =
        form["private_key_cycle"].force_value("account_default")
        form["key_technology"].force_value("account_default")
        form["domain_names_http01"] = generate_random_domain(testCase=self)
        form["note"] = note

        res2 = form.submit()
        assert res2.status_code == 303

        matched = RE_RenewalConfiguration.match(res2.location)
        assert matched
        obj_id = matched.groups()[0]

        res3 = self.testapp.get(res2.location)
        assert "<code>%s</code>" % note in res3.text

    @routes_tested(("admin:renewal_configuration:new|json",))
    def test_new_json(self):

        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/new.json", status=200
        )
        assert "form_fields" in res.json

        account_key_global_default = res.json["valid_options"][
            "AcmeAccount_GlobalDefault"
        ]["AcmeAccountKey"]["key_pem_md5"]

        note = generate_random_domain(testCase=self)

        form = {}
        form["account_key_option"] = "account_key_global_default"
        form["account_key_global_default"] = account_key_global_default
        form["private_key_cycle"] = "account_default"
        form["key_technology"] = "account_default"
        form["domain_names_http01"] = generate_random_domain(testCase=self)
        form["note"] = note

        res2 = self.testapp.post(
            "/.well-known/peter_sslers/renewal-configuration/new.json",
            form,
        )
        assert res2.json["result"] == "success"
        assert "RenewalConfiguration" in res2.json
        assert res2.json["RenewalConfiguration"]["note"] == note

    def test_post_required_html(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `renewal-configuration/%s/mark`
        # "admin:renewal_configuration:focus:mark",
        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/mark?action=active"
            % focus_id,
            status=303,
        )

        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/renewal-configuration/%s?result=error&error=post+required&operation=mark"
            % focus_id
        )

    def test_post_required_json(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `renewal-configuration/new.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/new.json",
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `renewal-configuration/%s/mark.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/mark.json?action=active"
            % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `renewal-configuration/%s/new-order.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/new-order.json"
            % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `renewal-configuration/%s/new-configuration.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/new-configuration.json"
            % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]


class FunctionalTests_RootStore(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_RootStore
    """

    def _get_one(self):
        # grab a RootStore
        focus_item = (
            self.ctx.dbSession.query(model_objects.RootStore)
            .order_by(model_objects.RootStore.id.asc())
            .first()
        )
        assert focus_item is not None
        return focus_item, focus_item.id

    @routes_tested(
        (
            "admin:root_stores",
            "admin:root_stores_paginated",
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/peter_sslers/root-stores", status=200)

        # paginated
        res = self.testapp.get("/.well-known/peter_sslers/root-stores/1", status=200)

    @routes_tested(
        (
            "admin:root_stores|json",
            "admin:root_stores_paginated|json",
        )
    )
    def test_list_json(self):
        # root
        res = self.testapp.get("/.well-known/peter_sslers/root-stores.json", status=200)
        assert "RootStores" in res.json

        # paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/root-stores/1.json", status=200
        )
        assert "RootStores" in res.json

    @routes_tested(("admin:root_store:focus",))
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/root-store/%s" % focus_id, status=200
        )

    @routes_tested(("admin:root_store:focus|json",))
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/root-store/%s.json" % focus_id, status=200
        )
        assert "RootStore" in res.json
        assert res.json["RootStore"]["id"] == focus_id


class FunctionalTests_RootStoreVersion(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_RootStoreVersion
    """

    def _get_one(self):
        # grab a RootStoreVersion
        focus_item = (
            self.ctx.dbSession.query(model_objects.RootStoreVersion)
            .order_by(model_objects.RootStoreVersion.id.asc())
            .first()
        )
        assert focus_item is not None
        return focus_item, focus_item.id

    @routes_tested(("admin:root_store_version:focus",))
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/root-store-version/%s" % focus_id, status=200
        )

    @routes_tested(("admin:root_store_version:focus|json",))
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/root-store-version/%s.json" % focus_id,
            status=200,
        )
        assert "RootStoreVersion" in res.json
        assert res.json["RootStoreVersion"]["id"] == focus_id


class FunctionalTests_UniqueFQDNSet(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_UniqueFQDNSet
    """

    def _get_one(self):
        # grab a UniqueFQDNSet
        focus_item = (
            self.ctx.dbSession.query(model_objects.UniqueFQDNSet)
            .order_by(model_objects.UniqueFQDNSet.id.asc())
            .first()
        )
        assert focus_item is not None
        return focus_item, focus_item.id

    @routes_tested(
        (
            "admin:unique_fqdn_sets",
            "admin:unique_fqdn_sets_paginated",
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/peter_sslers/unique-fqdn-sets", status=200)

        # paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-sets/1", status=200
        )

    @routes_tested(
        (
            "admin:unique_fqdn_sets|json",
            "admin:unique_fqdn_sets_paginated|json",
        )
    )
    def test_list_json(self):
        # root
        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-sets.json", status=200
        )
        assert "UniqueFQDNSets" in res.json

        # paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-sets/1.json", status=200
        )
        assert "UniqueFQDNSets" in res.json

    @routes_tested(
        (
            "admin:unique_fqdn_set:focus",
            "admin:unique_fqdn_set:focus:acme_orders",
            "admin:unique_fqdn_set:focus:acme_orders_paginated",
            "admin:unique_fqdn_set:focus:certificate_requests",
            "admin:unique_fqdn_set:focus:certificate_requests_paginated",
            "admin:unique_fqdn_set:focus:certificate_signeds",
            "admin:unique_fqdn_set:focus:certificate_signeds_paginated",
            "admin:unique_fqdn_set:focus:uniquely_challenged_fqdn_sets",
            "admin:unique_fqdn_set:focus:uniquely_challenged_fqdn_sets_paginated",
        )
    )
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/%s" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/%s/acme-orders" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/%s/acme-orders/1" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/%s/certificate-requests"
            % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/%s/certificate-requests/1"
            % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/%s/certificate-signeds"
            % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/%s/certificate-signeds/1"
            % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/%s/uniquely-challenged-fqdn-sets"
            % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/%s/uniquely-challenged-fqdn-sets/1"
            % focus_id,
            status=200,
        )

    @routes_tested(
        (
            "admin:unique_fqdn_set:focus|json",
            "admin:unique_fqdn_set:focus:calendar|json",
        )
    )
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/%s.json" % focus_id, status=200
        )
        assert "UniqueFQDNSet" in res.json
        assert res.json["UniqueFQDNSet"]["id"] == focus_id

        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/%s/calendar.json" % focus_id,
            status=200,
        )

    @routes_tested(("admin:unique_fqdn_set:new",))
    def test_new_html(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_UniqueFQDNSet.test_new_html
        """
        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/new", status=200
        )
        form = res.form
        new_fields = dict(form.submit_fields())
        assert "domain_names" in new_fields
        form["domain_names"] = (
            "test--unique-fqdn-set--new-html--1.example.com, test--unique-fqdn-set--new-html--2.example.com"
        )
        res2 = form.submit()
        assert res2.status_code == 303
        # 'http://peter-sslers.example.com/.well-known/peter_sslers/unique-fqdn-set/3?result=success&is_created=True'
        matched = RE_UniqueFQDNSet_new.match(res2.location)
        assert matched
        (_id1, _is_created1) = matched.groups(0)
        assert _is_created1 == "True"

        # make it again, expect it to be NOT created
        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/new", status=200
        )
        form = res.form
        new_fields = dict(form.submit_fields())
        assert "domain_names" in new_fields
        form["domain_names"] = (
            "test--unique-fqdn-set--new-html--1.example.com, test--unique-fqdn-set--new-html--2.example.com"
        )
        res2 = form.submit()
        assert res2.status_code == 303
        # 'http://peter-sslers.example.com/.well-known/peter_sslers/unique-fqdn-set/3?result=success&is_created=True'
        matched = RE_UniqueFQDNSet_new.match(res2.location)
        assert matched
        (_id2, _is_created2) = matched.groups(0)
        assert _is_created2 == "False"
        assert _id2 == _id1

        # test no domains
        form["domain_names"] = ""
        res2 = form.submit()
        assert res2.status_code == 200
        assert (
            """<!-- for: domain_names -->\n<div class="alert alert-danger"><div class="control-group error"><span class="help-inline">Please enter a value</span></div></div>"""
            in res2.text
        )

        # test no valid domains
        form["domain_names"] = ",,"
        res2 = form.submit()
        assert res2.status_code == 200
        assert (
            """<!-- for: domain_names -->\n<div class="alert alert-danger"><div class="control-group error"><span class="help-inline">no valid domain names submitted</span></div></div>"""
            in res2.text
        )
        form["domain_names"] = "example.com."
        res2 = form.submit()
        assert res2.status_code == 200
        assert (
            """<!-- for: domain_names -->\n<div class="alert alert-danger"><div class="control-group error"><span class="help-inline">invalid domain names detected</span></div></div>"""
            in res2.text
        )

        # test valid + invalid domains
        form["domain_names"] = "example.com., example.com"
        res2 = form.submit()
        assert res2.status_code == 200
        assert (
            """<!-- for: domain_names -->\n<div class="alert alert-danger"><div class="control-group error"><span class="help-inline">invalid domain names detected</span></div></div>"""
            in res2.text
        )

        # test 100+ domains
        form["domain_names"] = ",".join(
            ["test-%s.example.com" % i for i in range(0, 101)]
        )
        res2 = form.submit()
        assert res2.status_code == 200
        assert (
            """<!-- for: domain_names -->\n<div class="alert alert-danger"><div class="control-group error"><span class="help-inline">more than 100 domain names submitted</span></div></div>"""
            in res2.text
        )

    @routes_tested(("admin:unique_fqdn_set:new|json",))
    def test_new_json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_UniqueFQDNSet.test_new_json
        """
        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/new.json", status=200
        )
        assert "form_fields" in res.json

        form = {}
        form["domain_names"] = (
            "test--unique-fqdn-set--new-json--1.example.com, test--unique-fqdn-set--new-json--2.example.com"
        )
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/unique-fqdn-set/new.json", form
        )
        assert res2.status_code == 200
        assert "result" in res2.json
        assert res2.json["result"] == "success"
        assert "operation" in res2.json
        assert res2.json["operation"] == "new"
        assert "is_created" in res2.json
        assert res2.json["is_created"] is True
        assert "UniqueFQDNSet" in res2.json

        form = {}
        form["domain_names"] = (
            "test--unique-fqdn-set--new-json--1.example.com, test--unique-fqdn-set--new-json--2.example.com"
        )
        res3 = self.testapp.post(
            "/.well-known/peter_sslers/unique-fqdn-set/new.json", form
        )
        assert res3.status_code == 200
        assert "result" in res3.json
        assert res3.json["result"] == "success"
        assert "operation" in res3.json
        assert res3.json["operation"] == "new"
        assert "is_created" in res3.json
        assert res3.json["is_created"] is False
        assert "UniqueFQDNSet" in res3.json

        assert res2.json["UniqueFQDNSet"]["id"] == res3.json["UniqueFQDNSet"]["id"]

        # test no domains
        form["domain_names"] = ""
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/unique-fqdn-set/new.json", form
        )
        assert res2.status_code == 200
        assert res2.json["result"] == "error"
        assert res2.json["form_errors"]["domain_names"] == "Please enter a value"

        # test no valid domains
        form["domain_names"] = ",,"
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/unique-fqdn-set/new.json", form
        )
        assert res2.status_code == 200
        assert res2.json["result"] == "error"
        assert (
            res2.json["form_errors"]["domain_names"]
            == "no valid domain names submitted"
        )

        form["domain_names"] = "example.com."
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/unique-fqdn-set/new.json", form
        )
        assert res2.status_code == 200
        assert res2.json["result"] == "error"
        assert (
            res2.json["form_errors"]["domain_names"] == "invalid domain names detected"
        )

        # test valid + invalid domains
        form["domain_names"] = "example.com., example.com"
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/unique-fqdn-set/new.json", form
        )
        assert res2.status_code == 200
        assert res2.json["result"] == "error"
        assert (
            res2.json["form_errors"]["domain_names"] == "invalid domain names detected"
        )

        # test 100+ domains
        form["domain_names"] = ",".join(
            ["test-%s.example.com" % i for i in range(0, 101)]
        )
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/unique-fqdn-set/new.json", form
        )
        assert res2.status_code == 200
        assert res2.json["result"] == "error"
        assert (
            res2.json["form_errors"]["domain_names"]
            == "more than 100 domain names submitted"
        )

    @routes_tested(
        (
            "admin:unique_fqdn_set:focus:update_recents",
            "admin:unique_fqdn_set:focus:modify",
            "admin:unique_fqdn_set:new",
        )
    )
    def test_manipulate_html(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_UniqueFQDNSet.test_manipulate_html
        """
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/%s/update-recents" % focus_id,
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/unique-fqdn-set/%s?result=error&operation=update-recents&message=POST+required"
            % focus_id
        )

        res = self.testapp.post(
            "/.well-known/peter_sslers/unique-fqdn-set/%s/update-recents" % focus_id,
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/unique-fqdn-set/%s?result=success&operation=update-recents"
            % focus_id
        )

        # MODIFY
        # create a new item
        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/new", status=200
        )
        form = res.form
        new_fields = dict(form.submit_fields())
        assert "domain_names" in new_fields
        form["domain_names"] = (
            "test--unique-fqdn-set--manipulate-html--1.example.com, test--unique-fqdn-set--manipulate-html--2.example.com"
        )
        res2 = form.submit()
        assert res2.status_code == 303
        matched = RE_UniqueFQDNSet_new.match(res2.location)
        assert matched
        (_id1, _is_created1) = matched.groups(0)
        assert _is_created1 == "True"
        # grab it
        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/%s" % _id1, status=200
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/%s/modify" % _id1, status=200
        )
        forms = res.forms
        assert "form-unique_fqdn_set-modify" in res.forms

        # test 1- add/del the same domain
        form = res.forms["form-unique_fqdn_set-modify"]
        form["domain_names_add"] = (
            "test--unique-fqdn-set--manipulate-html--1.example.com"
        )
        form["domain_names_del"] = (
            "test--unique-fqdn-set--manipulate-html--1.example.com"
        )
        res2 = form.submit()
        assert res2.status_code == 200
        assert (
            """<div class="alert alert-danger"><div class="control-group error"><span class="help-inline">There was an error with your form. Identical domain names submitted for add and delete operations</span></div></div>"""
            in res2.text
        )

        # test 2- add existing domain
        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/%s/modify" % _id1, status=200
        )
        forms = res.forms
        assert "form-unique_fqdn_set-modify" in res.forms
        form = res.forms["form-unique_fqdn_set-modify"]
        form["domain_names_add"] = (
            "test--unique-fqdn-set--manipulate-html--1.example.com"
        )
        res2 = form.submit()
        assert res2.status_code == 200
        assert (
            """<div class="alert alert-danger"><div class="control-group error"><span class="help-inline">There was an error with your form. The proposed UniqueFQDNSet is identical to the existing UniqueFQDNSet.</span></div></div>"""
            in res2.text
        )

        # test 3- remove a domain
        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/%s/modify" % _id1, status=200
        )
        forms = res.forms
        assert "form-unique_fqdn_set-modify" in res.forms
        form = res.forms["form-unique_fqdn_set-modify"]
        form["domain_names_del"] = (
            "test--unique-fqdn-set--manipulate-html--1.example.com"
        )
        res2 = form.submit()
        assert res2.status_code == 303
        matched = RE_UniqueFQDNSet_modify.match(res2.location)
        assert matched
        (_id, _is_created) = matched.groups(0)
        assert _is_created == "True"

    @routes_tested(
        (
            "admin:unique_fqdn_set:focus:update_recents|json",
            "admin:unique_fqdn_set:focus:modify|json",
            "admin:unique_fqdn_set:new|json",
        )
    )
    def test_manipulate_json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_UniqueFQDNSet.test_manipulate_json
        """
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.post(
            "/.well-known/peter_sslers/unique-fqdn-set/%s/update-recents.json"
            % focus_id,
            status=200,
        )
        assert res.status_code == 200
        assert res.json["result"] == "success"
        assert "UniqueFQDNSet" in res.json

        # MODIFY
        # create a new item
        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/new.json", status=200
        )
        assert "form_fields" in res.json

        form = {}
        form["domain_names"] = (
            "test--unique-fqdn-set--manipulate-json--1.example.com, test--unique-fqdn-set--manipulate-json--2.example.com"
        )
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/unique-fqdn-set/new.json", form
        )
        assert res2.status_code == 200
        assert "result" in res2.json
        assert res2.json["result"] == "success"
        assert "operation" in res2.json
        assert res2.json["operation"] == "new"
        assert "is_created" in res2.json
        assert res2.json["is_created"] is True
        assert "UniqueFQDNSet" in res2.json

        focus_id = res2.json["UniqueFQDNSet"]["id"]

        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/%s/modify.json" % focus_id,
            status=200,
        )
        assert "form_fields" in res.json

        form = {}
        form["domain_names_add"] = (
            "test--unique-fqdn-set--manipulate-json--1.example.com"
        )
        form["domain_names_del"] = (
            "test--unique-fqdn-set--manipulate-json--1.example.com"
        )
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/unique-fqdn-set/%s/modify.json" % focus_id,
            form,
            status=200,
        )
        assert res2.status_code == 200
        assert res2.json["result"] == "error"
        assert (
            res2.json["form_errors"]["Error_Main"]
            == "There was an error with your form. Identical domain names submitted for add and delete operations"
        )

        # test 2- add existing domain
        form = {}
        form["domain_names_add"] = (
            "test--unique-fqdn-set--manipulate-json--1.example.com"
        )
        form["domain_names_del"] = ""
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/unique-fqdn-set/%s/modify.json" % focus_id,
            form,
            status=200,
        )
        assert res2.status_code == 200
        assert res2.json["result"] == "error"
        assert (
            res2.json["form_errors"]["Error_Main"]
            == "There was an error with your form. The proposed UniqueFQDNSet is identical to the existing UniqueFQDNSet."
        )

        # test 3- remove a domain
        form = {}
        form["domain_names_add"] = ""
        form["domain_names_del"] = (
            "test--unique-fqdn-set--manipulate-json--1.example.com"
        )
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/unique-fqdn-set/%s/modify.json" % focus_id,
            form,
            status=200,
        )
        assert res2.status_code == 200
        assert "result" in res2.json
        assert res2.json["result"] == "success"
        assert "operation" in res2.json
        assert res2.json["operation"] == "modify"
        assert "is_created" in res2.json
        assert res2.json["is_created"] is True
        assert "UniqueFQDNSet" in res2.json

    def test_post_required_json(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `unique-fqdn-set/%s/update-recents.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/unique-fqdn-set/%s/update-recents.json"
            % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]


class FunctionalTests_UniquelyChallengedFQDNSet(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_UniquelyChallengedFQDNSet
    """

    def _get_one(self):
        # grab a UniqueFQDNSet
        focus_item = (
            self.ctx.dbSession.query(model_objects.UniquelyChallengedFQDNSet)
            .order_by(model_objects.UniquelyChallengedFQDNSet.id.asc())
            .first()
        )
        assert focus_item is not None
        return focus_item, focus_item.id

    @routes_tested(
        (
            "admin:uniquely_challenged_fqdn_sets",
            "admin:uniquely_challenged_fqdn_sets_paginated",
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get(
            "/.well-known/peter_sslers/uniquely-challenged-fqdn-sets", status=200
        )

        # paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/uniquely-challenged-fqdn-sets/1", status=200
        )

    @routes_tested(
        (
            "admin:uniquely_challenged_fqdn_sets|json",
            "admin:uniquely_challenged_fqdn_sets_paginated|json",
        )
    )
    def test_list_json(self):
        # root
        res = self.testapp.get(
            "/.well-known/peter_sslers/uniquely-challenged-fqdn-sets.json", status=200
        )
        assert "UniquelyChallengedFQDNSets" in res.json

        # paginated
        res = self.testapp.get(
            "/.well-known/peter_sslers/uniquely-challenged-fqdn-sets/1.json", status=200
        )
        assert "UniquelyChallengedFQDNSets" in res.json

    @routes_tested(
        (
            "admin:uniquely_challenged_fqdn_set:focus",
            "admin:uniquely_challenged_fqdn_set:focus:acme_orders",
            "admin:uniquely_challenged_fqdn_set:focus:acme_orders_paginated",
            "admin:uniquely_challenged_fqdn_set:focus:certificate_signeds",
            "admin:uniquely_challenged_fqdn_set:focus:certificate_signeds_paginated",
            "admin:uniquely_challenged_fqdn_set:focus:renewal_configurations",
            "admin:uniquely_challenged_fqdn_set:focus:renewal_configurations_paginated",
        )
    )
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/uniquely-challenged-fqdn-set/%s" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/uniquely-challenged-fqdn-set/%s/acme-orders"
            % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/uniquely-challenged-fqdn-set/%s/acme-orders/1"
            % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/uniquely-challenged-fqdn-set/%s/certificate-signeds"
            % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/uniquely-challenged-fqdn-set/%s/certificate-signeds/1"
            % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/uniquely-challenged-fqdn-set/%s/renewal-configurations"
            % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/peter_sslers/uniquely-challenged-fqdn-set/%s/renewal-configurations/1"
            % focus_id,
            status=200,
        )

    @routes_tested(("admin:uniquely_challenged_fqdn_set:focus|json",))
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/peter_sslers/uniquely-challenged-fqdn-set/%s.json" % focus_id,
            status=200,
        )
        assert "UniquelyChallengedFQDNSet" in res.json
        assert res.json["UniquelyChallengedFQDNSet"]["id"] == focus_id


class FunctionalTests_AlternateChains(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_AlternateChains
    """

    def setUp(self):
        AppTest.setUp(self)
        self._setUp_CertificateSigneds_FormatA("AlternateChains", "1")

    def _get_one(self):
        # grab an item
        # iterate backwards because we just added the AlternateChains
        focus_item = (
            self.ctx.dbSession.query(model_objects.CertificateSigned)
            .filter(model_objects.CertificateSigned.is_active.is_(True))
            .order_by(model_objects.CertificateSigned.id.desc())
            .first()
        )
        assert focus_item is not None
        assert focus_item.certificate_signed_chains
        return focus_item

    @routes_tested(
        (
            "admin:certificate_ca:focus:certificate_signeds_alt",
            "admin:certificate_ca:focus:certificate_signeds_alt_paginated",
        )
    )
    def test_CertificateCA_view(self):
        focus_CertificateSigned = self._get_one()
        for (
            _certificate_signed_chain
        ) in focus_CertificateSigned.certificate_signed_chains:
            chain_id = _certificate_signed_chain.certificate_ca_chain_id
            certificate_ca_id = (
                _certificate_signed_chain.certificate_ca_chain.certificate_ca_0_id
            )
            res = self.testapp.get(
                "/.well-known/peter_sslers/certificate-ca-chain/%s" % chain_id,
                status=200,
            )
            res = self.testapp.get(
                "/.well-known/peter_sslers/certificate-ca/%s" % certificate_ca_id,
                status=200,
            )
            res = self.testapp.get(
                "/.well-known/peter_sslers/certificate-ca/%s/certificate-signeds-alt"
                % certificate_ca_id,
                status=200,
            )
            res = self.testapp.get(
                "/.well-known/peter_sslers/certificate-ca/%s/certificate-signeds-alt/1"
                % certificate_ca_id,
                status=200,
            )

    @routes_tested(
        (
            "admin:certificate_signed:focus:via_certificate_ca_chain:config|json",
            "admin:certificate_signed:focus:via_certificate_ca_chain:config|zip",
            "admin:certificate_signed:focus:via_certificate_ca_chain:chain:raw",
            "admin:certificate_signed:focus:via_certificate_ca_chain:fullchain:raw",
        )
    )
    def test_CertificateSigned_view(self):
        focus_CertificateSigned = self._get_one()

        certificate_signed_id = focus_CertificateSigned.id
        # this will have the primary root and the alternate roots;
        # pre-cache this now
        certificate_ca_chain_ids = [
            i.certificate_ca_chain_id
            for i in focus_CertificateSigned.certificate_signed_chains
        ]

        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s" % certificate_signed_id,
            status=200,
        )

        for certificate_ca_chain_id in certificate_ca_chain_ids:
            focus_ids = (certificate_signed_id, certificate_ca_chain_id)

            # chain
            res = self.testapp.get(
                "/.well-known/peter_sslers/certificate-signed/%s/via-certificate-ca-chain/%s/chain.cer"
                % focus_ids,
                status=200,
            )
            res = self.testapp.get(
                "/.well-known/peter_sslers/certificate-signed/%s/via-certificate-ca-chain/%s/chain.crt"
                % focus_ids,
                status=200,
            )
            res = self.testapp.get(
                "/.well-known/peter_sslers/certificate-signed/%s/via-certificate-ca-chain/%s/chain.der"
                % focus_ids,
                status=200,
            )
            res = self.testapp.get(
                "/.well-known/peter_sslers/certificate-signed/%s/via-certificate-ca-chain/%s/chain.pem"
                % focus_ids,
                status=200,
            )
            res = self.testapp.get(
                "/.well-known/peter_sslers/certificate-signed/%s/via-certificate-ca-chain/%s/chain.pem.txt"
                % focus_ids,
                status=200,
            )

            # fullchain
            res = self.testapp.get(
                "/.well-known/peter_sslers/certificate-signed/%s/via-certificate-ca-chain/%s/fullchain.pem"
                % focus_ids,
                status=200,
            )
            res = self.testapp.get(
                "/.well-known/peter_sslers/certificate-signed/%s/via-certificate-ca-chain/%s/fullchain.pem.txt"
                % focus_ids,
                status=200,
            )

            # configs
            res = self.testapp.get(
                "/.well-known/peter_sslers/certificate-signed/%s/via-certificate-ca-chain/%s/config.json"
                % focus_ids,
                status=200,
            )

            res = self.testapp.get(
                "/.well-known/peter_sslers/certificate-signed/%s/via-certificate-ca-chain/%s/config.zip"
                % focus_ids,
                status=200,
            )
            assert res.headers["Content-Type"] == "application/zip"
            assert (
                res.headers["Content-Disposition"]
                == "attachment; filename= cert%s-chain%s.zip" % focus_ids
            )
            z = zipfile.ZipFile(BytesIO(res.body))
            assert len(z.infolist()) == 4
            expectations = [
                file_template % certificate_signed_id
                for file_template in (
                    "cert%s.pem",
                    "chain%s.pem",
                    "fullchain%s.pem",
                    "privkey%s.pem",
                )
            ]
            found = [zipped.filename for zipped in z.infolist()]
            expectations.sort()
            found.sort()
            assert found == expectations


class FunctionalTests_API(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_API
    """

    @routes_tested(("admin:api", "admin:api:domain:autocert"))
    def test_passive(self):
        res = self.testapp.get("/.well-known/peter_sslers/api", status=200)
        res = self.testapp.get(
            "/.well-known/peter_sslers/api/domain/autocert", status=200
        )

    @routes_tested(
        (
            "admin:api:deactivate_expired",
            "admin:api:update_recents",
            "admin:api:reconcile_cas",
        )
    )
    def test_manipulate_html(self):
        # deactivate-expired
        res = self.testapp.get(
            "/.well-known/peter_sslers/api/deactivate-expired", status=303
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/operations/log?result=error&operation=api--deactivate-expired&error=POST+required"
        )

        res = self.testapp.post(
            "/.well-known/peter_sslers/api/deactivate-expired", status=303
        )
        assert (
            "/.well-known/peter_sslers/operations/log?result=success&operation=api--deactivate-expired&event.id="
            in res.location
        )

        # update-recents
        res = self.testapp.get(
            "/.well-known/peter_sslers/api/update-recents", status=303
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/operations/log?result=error&operation=api--update-recents&error=POST+required"
        )

        res = self.testapp.post(
            "/.well-known/peter_sslers/api/update-recents", status=303
        )
        assert (
            "/.well-known/peter_sslers/operations/log?result=success&operation=api--update-recents&event.id="
            in res.location
        )

        # reconcile-cas
        res = self.testapp.get(
            "/.well-known/peter_sslers/api/reconcile-cas", status=303
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/operations/log?result=error&operation=api--reconcile-cas&error=POST+required"
        )

        res = self.testapp.post(
            "/.well-known/peter_sslers/api/reconcile-cas", status=303
        )
        assert (
            "/.well-known/peter_sslers/operations/log?result=success&operation=api--reconcile-cas&event.id="
            in res.location
        )

    @routes_tested(
        (
            "admin:api:deactivate_expired|json",
            "admin:api:update_recents|json",
            "admin:api:reconcile_cas|json",
        )
    )
    def test_manipulate_json(self):
        # deactivate-expired
        res = self.testapp.get(
            "/.well-known/peter_sslers/api/deactivate-expired.json", {}, status=200
        )
        assert "HTTP POST required" in res.json["instructions"]

        res = self.testapp.post(
            "/.well-known/peter_sslers/api/deactivate-expired.json", {}, status=200
        )
        assert res.json["result"] == "success"

        # update-recents
        res = self.testapp.get(
            "/.well-known/peter_sslers/api/update-recents.json", {}, status=200
        )
        assert "HTTP POST required" in res.json["instructions"]

        res = self.testapp.post(
            "/.well-known/peter_sslers/api/update-recents.json", {}, status=200
        )
        assert res.json["result"] == "success"

        # reconcile-cas
        res = self.testapp.get(
            "/.well-known/peter_sslers/api/reconcile-cas.json", {}, status=200
        )
        assert "HTTP POST required" in res.json["instructions"]

        res = self.testapp.post(
            "/.well-known/peter_sslers/api/reconcile-cas.json", {}, status=200
        )
        assert res.json["result"] == "success"

    @unittest.skipUnless(RUN_REDIS_TESTS, "Not Running Against: redis")
    @under_redis
    @routes_tested(
        (
            "admin:api:redis:prime",
            "admin:api:redis:prime|json",
        )
    )
    def test_redis(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_API.test_redis
        """
        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        # NOTE: prep work, ensure we updated recents
        res = self.testapp.post(
            "/.well-known/peter_sslers/api/update-recents.json", {}, status=200
        )
        assert res.json["result"] == "success"

        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

        res = self.testapp.get("/.well-known/peter_sslers/api/redis/prime", status=303)
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/operations/redis?result=error&operation=api--redis--prime&error=POST+required"
        )

        res = self.testapp.post(
            "/.well-known/peter_sslers/api/redis/prime", {}, status=303
        )
        assert (
            "/.well-known/peter_sslers/operations/redis?result=success&operation=redis_prime&event.id="
            in res.location
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/api/redis/prime.json", {}, status=200
        )
        assert "HTTP POST required" in res.json["instructions"]

        res = self.testapp.post(
            "/.well-known/peter_sslers/api/redis/prime.json", {}, status=200
        )
        assert res.json["result"] == "success"

    @unittest.skipUnless(RUN_NGINX_TESTS, "Not Running Against: nginx")
    @routes_tested(
        (
            "admin:api:nginx:cache_flush",
            "admin:api:nginx:cache_flush|json",
            "admin:api:nginx:status|json",
        )
    )
    def test_nginx(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_API.test_nginx
        """
        # TODO: this doesn't actually test nginx
        # this will test the nginx routes work, but they will catch exceptions when trying to talk upstream
        res = self.testapp.get(
            "/.well-known/peter_sslers/api/nginx/cache-flush", status=303
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/operations/nginx?result=error&operation=api--nginx--cache-flush&error=POST+required"
        )

        res = self.testapp.post(
            "/.well-known/peter_sslers/api/nginx/cache-flush", status=303
        )
        assert (
            "/.well-known/peter_sslers/operations/nginx?result=success&operation=nginx_cache_flush&event.id="
            in res.location
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/api/nginx/cache-flush.json", status=200
        )
        assert "HTTP POST required" in res.json["instructions"]

        res = self.testapp.post(
            "/.well-known/peter_sslers/api/nginx/cache-flush.json", {}, status=200
        )
        if False:
            print("################################################################")
            pprint.pprint(res.json)
            print("################################################################")
        assert res.json["result"] == "success"
        assert "servers_status" in res.json
        assert "errors" in res.json["servers_status"]
        assert not res.json["servers_status"]["errors"]

        for server in self.testapp.app.registry.settings["application_settings"][
            "nginx.servers_pool"
        ]:
            assert server in res.json["servers_status"]["success"]
            assert server in res.json["servers_status"]["servers"]
            assert res.json["servers_status"]["servers"][server]["result"] == "success"
            assert (
                res.json["servers_status"]["servers"][server]["server"]
                == "peter_sslers:openresty"
            )
            server_version = packaging.version.parse(
                res.json["servers_status"]["servers"][server]["server_version"]
            )
            self.assertGreaterEqual(server_version, OPENRESTY_PLUGIN_MINIMUM)
            assert res.json["servers_status"]["servers"][server]["expired"] == "all"

        res = self.testapp.get(
            "/.well-known/peter_sslers/api/nginx/status.json", status=200
        )
        assert "HTTP POST required" in res.json["instructions"]

        res = self.testapp.post(
            "/.well-known/peter_sslers/api/nginx/status.json", {}, status=200
        )
        assert res.json["result"] == "success"
        assert "servers_status" in res.json
        assert "errors" in res.json["servers_status"]
        assert not res.json["servers_status"]["errors"]
        for server in self.testapp.app.registry.settings["application_settings"][
            "nginx.servers_pool"
        ]:
            assert server in res.json["servers_status"]["success"]
            assert server in res.json["servers_status"]["servers"]
            assert res.json["servers_status"]["servers"][server]["result"] == "success"
            assert (
                res.json["servers_status"]["servers"][server]["server"]
                == "peter_sslers:openresty"
            )
            server_version = packaging.version.parse(
                res.json["servers_status"]["servers"][server]["server_version"]
            )
            self.assertGreaterEqual(server_version, OPENRESTY_PLUGIN_MINIMUM)

            # 'servers': {'https://127.0.0.1': {'config':
            assert "config" in res.json["servers_status"]["servers"][server]
            assert "expiries" in res.json["servers_status"]["servers"][server]["config"]
            assert (
                "ngx.shared.cert_cache"
                in res.json["servers_status"]["servers"][server]["config"]["expiries"]
            )
            assert (
                "resty.lrucache"
                in res.json["servers_status"]["servers"][server]["config"]["expiries"]
            )
            assert "maxitems" in res.json["servers_status"]["servers"][server]["config"]
            assert (
                "resty.lrucache"
                in res.json["servers_status"]["servers"][server]["config"]["maxitems"]
            )

            # 'servers': {'https://127.0.0.1': {'keys':
            assert "keys" in res.json["servers_status"]["servers"][server]
            assert "autocert" in res.json["servers_status"]["servers"][server]["keys"]
            assert "invalid" in res.json["servers_status"]["servers"][server]["keys"]
            assert "valid" in res.json["servers_status"]["servers"][server]["keys"]

    def test_post_required_json(self):
        # !!!: test `POST required` `api/domain/autocert.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/api/domain/autocert.json", status=200
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `api/deactivate-expired.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/api/deactivate-expired.json", status=200
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `api/update-recents.json`
        res = self.testapp.get(
            "/.well-known/peter_sslers/api/update-recents.json", status=200
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        try:
            res = self.testapp.get(
                "/.well-known/peter_sslers/api/redis/prime.json", status=200
            )
            assert "instructions" in res.json
            assert "HTTP POST required" in res.json["instructions"]
        except Exception as exc:
            if RUN_REDIS_TESTS:
                raise exc


class IntegratedTests_AcmeServer_AcmeAccount(AppTest):

    def tearDown(self):
        unset_testing_data(self)
        AppTest.tearDown(self)

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested("admin:acme_account:new")
    def test_new_html(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeAccount.test_new_html
        """

        # fields are:
        # {acme_server_id}
        # {account__contact}
        # {account__private_key_technology}
        # {account__order_default_private_key_cycle}
        # {account__order_default_private_key_technology}
        res = self.testapp.get("/.well-known/peter_sslers/acme-account/new", status=200)
        form = res.form
        form["acme_server_id"].force_value(str(1))  # acme_server_id(1) == pebble
        res2 = form.submit()
        assert res2.status_code == 200
        assert "There was an error with your form." in res2.text
        assert (
            "Can not validate on upstream ACME Server. Server says `urn:ietf:params:acme:error:unsupportedContact` contact method &quot;&quot; is not supported."
            in res2.text
        )

        form = res2.form
        form["account__contact"].force_value("AcmeAccount.new.html@example.com")
        res2 = form.submit()
        assert res2.status_code == 303
        matched = RE_AcmeAccount_new.match(res2.location)
        assert matched
        obj_id = matched.groups()[0]
        assert obj_id
        obj_id = int(obj_id)

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested("admin:acme_account:new|json")
    def test_new_json(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeAccount.test_new_json
        """
        form: Dict = {}
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/new.json", form
        )
        assert res2.json["result"] == "error"
        assert "form_errors" in res2.json
        assert isinstance(res2.json["form_errors"], dict)
        assert len(res2.json["form_errors"]) == 1
        assert res2.json["form_errors"]["Error_Main"] == "Nothing submitted."

        form = {
            "acme_server_id": 1,
            "account__contact": "AcmeAccount.new.json@example.com",
            "account__order_default_private_key_cycle": "single_use",
            "account__order_default_private_key_technology": "RSA_2048",
        }
        res3 = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/new.json", form
        )
        assert res3.json["result"] == "error"
        assert "form_errors" in res3.json
        assert isinstance(res3.json["form_errors"], dict)

        assert len(res3.json["form_errors"]) == 2
        assert (
            res3.json["form_errors"]["Error_Main"]
            == "There was an error with your form."
        )
        assert (
            res3.json["form_errors"]["account__private_key_technology"]
            == "Missing value"
        )

        form["account__private_key_technology"] = "RSA_2048"
        res4 = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/new.json", form
        )
        assert res4.json["result"] == "success"
        assert "AcmeAccount" in res4.json
        return True

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested("admin:acme_account:upload")
    def test_upload_html(self):
        """
        formecode must be patched for this:
            https://github.com/formencode/formencode/issues/101
            https://github.com/valos/formencode/commit/987d29922b2a37eb969fb40658a1057bacbe1129
        """
        # this should be creating a new key
        _key_filename = TEST_FILES["AcmeAccount"]["2"]["key"]
        key_filepath = self._filepath_testfile(_key_filename)

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/upload", status=200
        )
        form = res.form
        form["account__contact"] = TEST_FILES["AcmeAccount"]["2"]["contact"]
        form["account_key_file_pem"] = Upload(key_filepath)
        form["acme_server_id"].force_value(str(1))  # acme_server_id(1) == pebble
        res2 = form.submit()
        assert res2.status_code == 303
        assert res2.location.startswith(
            """http://peter-sslers.example.com/.well-known/peter_sslers/acme-account/"""
        )
        assert res2.location.endswith(
            """?result=success&operation=upload&is_created=1"""
        ) or res2.location.endswith(
            """?result=success&operation=upload&is_existing=1"""
        )
        res3 = self.testapp.get(res2.location, status=200)

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested("admin:acme_account:upload|json")
    def test_upload_json(self):
        _key_filename = TEST_FILES["AcmeAccount"]["2"]["key"]
        key_filepath = self._filepath_testfile(_key_filename)

        form = {}
        form["account__contact"] = TEST_FILES["AcmeAccount"]["2"]["contact"]
        form["account_key_file_pem"] = Upload(key_filepath)
        form["acme_server_id"] = "1"  # acme_server_id(1) == pebble
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/upload.json", form
        )
        assert res2.status_code == 200
        assert "result" in res2.json
        assert res2.json["result"] == "error"
        assert "form_errors" in res2.json

        assert isinstance(res2.json["form_errors"], dict)
        assert len(res2.json["form_errors"].keys()) == 3
        assert (
            res2.json["form_errors"]["Error_Main"]
            == "There was an error with your form."
        )
        assert (
            res2.json["form_errors"]["account__order_default_private_key_cycle"]
            == "Missing value"
        )
        assert (
            res2.json["form_errors"]["account__order_default_private_key_technology"]
            == "Missing value"
        )

        form = {}
        form["account_key_file_pem"] = Upload(key_filepath)
        form["acme_server_id"] = "1"  # acme_server_id(1) == pebble
        form["account__contact"] = TEST_FILES["AcmeAccount"]["2"]["contact"]
        form["account__order_default_private_key_cycle"] = TEST_FILES["AcmeAccount"][
            "2"
        ]["order_default_private_key_cycle"]
        form["account__order_default_private_key_technology"] = TEST_FILES[
            "AcmeAccount"
        ]["2"]["order_default_private_key_technology"]
        res3 = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/upload.json", form
        )
        assert res3.status_code == 200
        res3_json = json.loads(res3.text)
        assert "result" in res3_json
        assert res3_json["result"] == "success"

    def _get_one_AcmeAccount(self):
        # grab an item
        focus_item = (
            self.ctx.dbSession.query(model_objects.AcmeAccount)
            .filter(model_objects.AcmeAccount.is_active.is_(True))
            .filter(model_objects.AcmeAccount.acme_server_id == 1)
            .order_by(model_objects.AcmeAccount.id.asc())
            .first()
        )
        assert focus_item is not None
        return focus_item, focus_item.id

    def _make_one_AcmeAccount(self) -> Tuple[model_objects.AcmeAccount, int]:
        focus_item, focus_item_id = make_one__AcmeAccount__random(self)
        return (focus_item, focus_item_id)

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested("admin:acme_account:focus:acme_server:authenticate")
    def test_authenticate_html(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeAccount.test_authenticate_html
        # this hits Pebble via http
        """
        (focus_item, focus_id) = self._get_one_AcmeAccount()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/authenticate"
            % focus_id,
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/acme-account/%s?result=error&error=post+required&operation=acme-server--authenticate"
            % focus_id
        )

        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/authenticate"
            % focus_id,
            {},
        )
        assert (
            res.location
            == """http://peter-sslers.example.com/.well-known/peter_sslers/acme-account/%s?result=success&operation=acme-server--authenticate&is_authenticated=True"""
            % focus_id
        )

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested("admin:acme_account:focus:acme_server:authenticate|json")
    def test_authenticate_json(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeAccount.test_authenticate_json
        # this hits Pebble via http
        """
        (focus_item, focus_id) = self._get_one_AcmeAccount()

        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/authenticate.json"
            % focus_id,
            {},
        )
        assert res.status_code == 200
        assert res.location is None  # no redirect
        assert "AcmeAccount" in res.json

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested("admin:acme_account:focus:acme_server:check")
    def test_check_html(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeAccount.test_check_html
        # this hits Pebble via http
        """
        (focus_item, focus_id) = self._make_one_AcmeAccount()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/check" % focus_id,
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/acme-account/%s?result=error&error=post+required&operation=acme-server--check"
            % focus_id
        )

        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/check" % focus_id,
            {},
        )
        assert (
            res.location
            == """http://peter-sslers.example.com/.well-known/peter_sslers/acme-account/%s?result=success&operation=acme-server--check&is_checked=True&result=success&message="""
            % focus_id
        )

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested("admin:acme_account:focus:acme_server:check|json")
    def test_check_json(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeAccount.test_check_json
        # this hits Pebble via http
        """
        (focus_item, focus_id) = self._make_one_AcmeAccount()

        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/check.json"
            % focus_id,
            {},
        )
        assert res.status_code == 200
        assert res.location is None  # no redirect
        assert "AcmeAccount" in res.json
        assert res.json["is_checked"] is True
        assert res.json["result"] == "success"
        assert res.json["message"] is None

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested("admin:acme_account:focus:acme_server:deactivate")
    def test_deactivate_html(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeAccount.test_deactivate_html
        # this hits Pebble via http
        """
        (focus_item, focus_id) = self._make_one_AcmeAccount()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/deactivate"
            % focus_id,
            status=200,
        )
        assert "form-acme_account-deactivate" in res.forms
        form = res.forms["form-acme_account-deactivate"]

        res2 = form.submit()
        assert res2.status_code == 200
        assert (
            """<!-- for: key_pem -->\n<div class="alert alert-danger"><div class="control-group error"><span class="help-inline">Please enter a value</span></div></div>"""
            in res2.text
        )

        form["key_pem"] = focus_item.acme_account_key.key_pem_md5
        res3 = form.submit()
        assert res3.status_code == 303

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested("admin:acme_account:focus:acme_server:deactivate|json")
    def test_deactivate_json(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeAccount.test_deactivate_json
        # this hits Pebble via http
        """
        (focus_item, focus_id) = self._make_one_AcmeAccount()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/deactivate.json"
            % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "form_fields" in res.json
        assert "key_pem" in res.json["form_fields"]

        form: Dict = {}
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/deactivate.json"
            % focus_id,
            form,
        )
        assert res2.json["result"] == "error"
        assert res2.json["form_errors"]["Error_Main"] == "Nothing submitted."

        form["key_pem"] = "foo"
        res3 = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/deactivate.json"
            % focus_id,
            form,
        )
        assert res3.json["result"] == "error"
        assert (
            res3.json["form_errors"]["key_pem"]
            == "This does not match the active account key"
        )

        form["key_pem"] = focus_item.acme_account_key.key_pem_md5
        res4 = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/deactivate.json"
            % focus_id,
            form,
        )
        assert res4.json["result"] == "success"

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested("admin:acme_account:focus:acme_server:key_change")
    def test_key_change_html(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeAccount.test_key_change_html
        # this hits Pebble via http
        """
        (focus_item, focus_id) = self._make_one_AcmeAccount()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/key-change"
            % focus_id,
            status=200,
        )
        assert "form-acme_account-key_change" in res.forms
        form = res.forms["form-acme_account-key_change"]

        res2 = form.submit()
        assert res2.status_code == 200
        assert (
            """<!-- for: key_pem_existing -->\n<div class="alert alert-danger"><div class="control-group error"><span class="help-inline">Please enter a value</span></div></div>"""
            in res2.text
        )

        form["key_pem_existing"] = focus_item.acme_account_key.key_pem_md5
        res3 = form.submit()
        assert res3.status_code == 303

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested("admin:acme_account:focus:acme_server:key_change|json")
    def test_key_change_json(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeAccount.test_key_change_json
        # this hits Pebble via http
        """
        (focus_item, focus_id) = self._make_one_AcmeAccount()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/key-change.json"
            % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "form_fields" in res.json
        assert "key_pem_existing" in res.json["form_fields"]

        form: Dict = {}
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/key-change.json"
            % focus_id,
            form,
        )
        assert res2.json["result"] == "error"
        assert res2.json["form_errors"]["Error_Main"] == "Nothing submitted."

        form["key_pem_existing"] = "foo"
        res3 = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/key-change.json"
            % focus_id,
            form,
        )
        assert res3.json["result"] == "error"
        assert (
            res3.json["form_errors"]["key_pem_existing"]
            == "This does not match the active account key"
        )

        form["key_pem_existing"] = focus_item.acme_account_key.key_pem_md5
        res4 = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/key-change.json"
            % focus_id,
            form,
        )
        assert res4.json["result"] == "success"

    @routes_tested(
        (
            "admin:acme_order:new:freeform",
            "admin:acme_order:focus|json",
            "admin:acme_account:focus",
            "admin:acme_account:focus:acme_authorizations",
            "admin:acme_account:focus:acme_authorizations|json",
        )
    )
    def _prep__AcmeAccount_deactivate_pending_authorizations(self) -> int:
        """
        shared routine
        this runs `@under_pebble`, but the invoking function should wrap it
        """
        _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]
        # we need two for this test
        assert len(_test_data["acme-order/new/freeform#1"]["domain_names_http01"]) == 2

        (dbAcmeAccount, acme_account_id) = make_one__AcmeAccount__pem(
            self,
            account__contact=_test_data["acme-order/new/freeform#1"][
                "account__contact"
            ],
            pem_file_name=_test_data["acme-order/new/freeform#1"][
                "account_key_file_pem"
            ],
        )

        # "admin:acme_order:new:freeform",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/new/freeform", status=200
        )
        form = res.form
        _form_fields = form.fields.keys()
        assert "account_key_option" in _form_fields
        form["account_key_option"].force_value("account_key_existing")
        form["account_key_existing"].force_value(
            dbAcmeAccount.acme_account_key.key_pem_md5
        )
        form["private_key_option"].force_value("account_default")
        form["private_key_cycle"].force_value("account_default")
        form["domain_names_http01"] = ",".join(
            _test_data["acme-order/new/freeform#1"]["domain_names_http01"]
        )
        form["processing_strategy"].force_value("create_order")
        res2 = form.submit()
        assert res2.status_code == 303

        matched = RE_AcmeOrder.match(res2.location)
        assert matched
        obj_id = matched.groups()[0]

        # "admin:acme_order:focus|json",
        # this could be an: `?is_duplicate_renewal=true'
        url_json = "%s.json" % res2.location.split("?")[0]
        res = self.testapp.get(url_json, status=200)
        assert "AcmeOrder" in res.json
        acme_account_id = res.json["AcmeOrder"]["AcmeAccount"]["id"]
        assert acme_account_id

        # admin:acme_account:focus
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s" % acme_account_id, status=200
        )

        return acme_account_id

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_account:focus:acme_server:deactivate_pending_authorizations",  # real test
        )
    )
    def test_deactivate_pending_authorizations_html(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeAccount.test_deactivate_pending_authorizations_html
        # this hits Pebble via http
        """
        acme_account_id = self._prep__AcmeAccount_deactivate_pending_authorizations()

        # get - fail!
        res_bad = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/deactivate-pending-authorizations"
            % acme_account_id,
            status=303,
        )
        matched = RE_AcmeAccount_deactivate_pending_post_required.match(
            res_bad.location
        )
        assert matched

        # use the JSON route to grab authorization ids for our form
        # admin:acme_account:focus:acme_authorizations
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-authorizations"
            % acme_account_id,
            status=200,
        )
        res2 = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-authorizations.json"
            % acme_account_id,
            status=200,
        )
        acme_authorization_ids = [
            i["id"]
            for i in res2.json["AcmeAuthorizations"]
            if i["acme_status_authorization"]
            in model_utils.Acme_Status_Authorization.OPTIONS_DEACTIVATE_TESTING
        ]
        assert len(acme_authorization_ids) == 2
        form = res.form
        form["acme_authorization_id"] = acme_authorization_ids
        res3 = form.submit()

        assert res3.status_code == 303
        matched = RE_AcmeAccount_deactivate_pending_success.match(res3.location)

        res4 = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-authorizations.json"
            % acme_account_id,
            status=200,
        )
        acme_authorization_ids_2 = [
            i["id"]
            for i in res4.json["AcmeAuthorizations"]
            if i["acme_status_authorization"]
            in model_utils.Acme_Status_Authorization.OPTIONS_DEACTIVATE_TESTING
        ]
        assert len(acme_authorization_ids_2) == 0

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_account:focus:acme_server:deactivate_pending_authorizations|json",  # real test
        )
    )
    def test_deactivate_pending_authorizations_json(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeAccount.test_deactivate_pending_authorizations_json
        # this hits Pebble via http
        """
        acme_account_id = self._prep__AcmeAccount_deactivate_pending_authorizations()

        # get - fail!
        res_bad = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/deactivate-pending-authorizations.json"
            % acme_account_id,
            status=200,
        )
        assert "instructions" in res_bad.json

        # use the JSON route to grab authorization ids for our form
        # admin:acme_account:focus:acme_authorizations
        res2 = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-authorizations.json"
            % acme_account_id,
            status=200,
        )
        acme_authorization_ids = [
            i["id"]
            for i in res2.json["AcmeAuthorizations"]
            if i["acme_status_authorization"]
            in model_utils.Acme_Status_Authorization.OPTIONS_DEACTIVATE_TESTING
        ]
        assert len(acme_authorization_ids) == 2

        post_data = [
            ("acme_authorization_id", acme_authorization_id)
            for acme_authorization_id in acme_authorization_ids
        ]
        res3 = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/deactivate-pending-authorizations.json"
            % acme_account_id,
            post_data,
        )
        assert res3.status_code == 200

        res4 = self.testapp.get(
            "/.well-known/peter_sslers/acme-account/%s/acme-authorizations.json"
            % acme_account_id,
            status=200,
        )
        acme_authorization_ids_2 = [
            i["id"]
            for i in res4.json["AcmeAuthorizations"]
            if i["acme_status_authorization"]
            in model_utils.Acme_Status_Authorization.OPTIONS_DEACTIVATE_TESTING
        ]
        assert len(acme_authorization_ids_2) == 0


class IntegratedTests_AcmeServer_AcmeOrder(AppTest):

    @routes_tested(("admin:acme_order:new:freeform",))
    def _prep_AcmeOrder_html(
        self,
        processing_strategy: str = "create_order",
    ):
        """
        this runs `@under_pebble`, but the invoking function should wrap it
        """
        _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]

        # we need two for this test
        # originally these were scripted, but chaining tests might be mucking this up
        # domain_names_http01 = _test_data["acme-order/new/freeform#1"]["domain_names_http01"]
        # stash these onto the testCase so the actual test can access them
        self._domain_names_http01 = [
            generate_random_domain(testCase=self),
            generate_random_domain(testCase=self),
        ]
        assert len(self._domain_names_http01) == 2
        domain_names_http01 = ",".join(self._domain_names_http01)

        (dbAcmeAccount, acme_account_id) = make_one__AcmeAccount__pem(
            self,
            account__contact=_test_data["acme-order/new/freeform#1"][
                "account__contact"
            ],
            pem_file_name=_test_data["acme-order/new/freeform#1"][
                "account_key_file_pem"
            ],
        )

        # "admin:acme_order:new:freeform",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/new/freeform", status=200
        )

        form = res.form
        note = generate_random_domain(testCase=self)
        _form_fields = form.fields.keys()
        assert "account_key_option" in _form_fields
        form["account_key_option"].force_value("account_key_existing")
        form["account_key_existing"].force_value(
            dbAcmeAccount.acme_account_key.key_pem_md5
        )
        form["private_key_option"].force_value("account_default")
        form["private_key_cycle"].force_value("account_default")
        form["domain_names_http01"] = domain_names_http01
        form["processing_strategy"].force_value(processing_strategy)
        form["note"].force_value(note)
        res2 = form.submit()
        assert res2.status_code == 303

        res3 = self.testapp.get(res2.location)
        assert "<code>%s</code>" % note in res3.text

        # "admin:acme_order:focus",
        matched = RE_AcmeOrder.match(res2.location)
        assert matched
        obj_id = matched.groups()[0]

        return (obj_id, res2.location)

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_order:new:freeform",
            "admin:acme_order:focus",
            "admin:acme_order:focus:acme_server:sync",
            "admin:acme_order:focus:acme_server:sync_authorizations",
            "admin:acme_authorization:focus",
            "admin:acme_authorization:focus:acme_server:sync",
            "admin:acme_challenge:focus",
            "admin:acme_challenge:focus:acme_server:sync",
            "admin:acme_challenge:focus:acme_server:trigger",
            "admin:acme_order:focus:acme_finalize",
            "admin:acme_order:focus:acme_server:deactivate_authorizations",
        )
    )
    def test_AcmeOrder_extended_html(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeOrder.test_AcmeOrder_extended_html

        NOTE: if domains are not randomized for the order, one needs to reset the pebble instance
        NOTE^^^ this now runs with it's own pebble instance
        """
        _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]

        (obj_id, obj_url) = self._prep_AcmeOrder_html()
        acme_order_1__id = obj_id

        # /acme-order
        res = self.testapp.get(obj_url, status=200)

        # "admin:acme_order:focus:acme_server:sync",
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/acme-server/sync"
            % acme_order_1__id,
            {},
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/peter_sslers/acme-order/%s?result=success&operation=acme+server+sync"
            % acme_order_1__id
        )

        # "admin:acme_order:focus:acme_server:sync_authorizations",
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/acme-server/sync-authorizations"
            % acme_order_1__id,
            {},
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/peter_sslers/acme-order/%s?result=success&operation=acme+server+sync+authorizations"
            % acme_order_1__id
        )

        _dbAcmeOrder = self.ctx.dbSession.query(model_objects.AcmeOrder).get(
            acme_order_1__id
        )
        assert _dbAcmeOrder is not None
        renewal_configuration_1__id = _dbAcmeOrder.renewal_configuration_id

        assert len(_dbAcmeOrder.acme_authorizations) == len(self._domain_names_http01)
        _authorization_pairs = [
            (i.id, i.acme_challenge_http_01.id)
            for i in _dbAcmeOrder.acme_authorizations
        ]
        self.ctx.dbSession.rollback()

        assert len(_authorization_pairs) == 2

        # AuthPair 1
        (auth_id_1, challenge_id_1) = _authorization_pairs[0]

        # "admin:acme_authorization:focus",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authorization/%s" % auth_id_1, status=200
        )

        # "admin:acme_authorization:focus:sync"
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-authorization/%s/acme-server/sync"
            % auth_id_1,
            {},
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/peter_sslers/acme-authorization/%s?result=success&operation=acme+server+sync"
            % auth_id_1
        )

        # note: originally we triggered the AUTHORIZATION `acme-authorization/%s/acme-server/trigger`
        # that endpoint was removed
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-challenge/%s/acme-server/trigger"
            % challenge_id_1,
            {},
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/acme-challenge/%s?result=success&operation=acme+server+trigger"
            % challenge_id_1
        )
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-authorization/%s/acme-server/sync"
            % auth_id_1,
            {},
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/peter_sslers/acme-authorization/%s?result=success&operation=acme+server+sync"
            % auth_id_1
        )

        # AuthPair 2
        (auth_id_2, challenge_id_2) = _authorization_pairs[1]

        # "admin:acme_challenge:focus",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenge/%s" % challenge_id_2, status=200
        )

        # "admin:acme_challenge:focus:acme_server:sync",
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-challenge/%s/acme-server/sync"
            % challenge_id_2,
            {},
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/acme-challenge/%s?result=success&operation=acme+server+sync"
            % challenge_id_2
        )

        # "admin:acme_challenge:focus:acme_server:trigger",
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-challenge/%s/acme-server/trigger"
            % challenge_id_2,
            {},
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/peter_sslers/acme-challenge/%s?result=success&operation=acme+server+trigger"
            % challenge_id_2
        )

        # "admin:acme_authorization:focus:sync"
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-authorization/%s/acme-server/sync"
            % auth_id_2,
            {},
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/peter_sslers/acme-authorization/%s?result=success&operation=acme+server+sync"
            % auth_id_2
        )

        # now go back to the order
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s" % acme_order_1__id,
            status=200,
        )
        assert (
            """<td><span class="label label-default">processing_started</span></td>"""
            in res.text
        )

        # "admin:acme_order:focus:acme_server:sync",
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/acme-server/sync"
            % acme_order_1__id,
            {},
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/peter_sslers/acme-order/%s?result=success&operation=acme+server+sync"
            % acme_order_1__id
        )

        res2 = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/acme-server/sync.json"
            % acme_order_1__id
        )
        res2 = self.testapp.get(
            "/.well-known/peter_sslers/acme-authorization/%s.json" % auth_id_1
        )
        res2 = self.testapp.get(
            "/.well-known/peter_sslers/acme-authorization/%s.json" % auth_id_2
        )

        res2 = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % acme_order_1__id
        )

        # "admin:acme_order:focus:acme_finalize",
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/acme-finalize" % acme_order_1__id,
            {},
            status=303,
        )

        assert res.location == (
            "http://peter-sslers.example.com/.well-known/peter_sslers/acme-order/%s?result=success&operation=acme+finalize"
            % acme_order_1__id
        )

        # now go back to the order
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s" % acme_order_1__id,
            status=200,
        )
        assert (
            """<td><span class="label label-default">certificate_downloaded</span></td>"""
            in res.text
        )

        assert "form-acme_process" not in res.forms
        assert "form-acme_finalize" not in res.forms
        assert "form-deactivate_order" not in res.forms

        # what is the certificate_id?
        matched = RE_CertificateSigned_button.search(res.text)
        assert matched
        _certificate_id = matched.groups()[0]
        assert (
            'href="/.well-known/peter_sslers/renewal-configuration/%s/new-order?replaces.id=%s"'
            % (renewal_configuration_1__id, _certificate_id)
            in res.text
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/new-order"
            % renewal_configuration_1__id,
            status=200,
        )
        form = res.forms["form-renewal_configuration-new_order"]
        form["processing_strategy"].force_value("process_multi")
        res2 = form.submit()
        assert res2.status_code == 303

        matched = RE_AcmeOrder_renewal_configuration.match(res2.location)
        assert matched
        acme_order_2__id = int(matched.groups()[0])

        assert acme_order_2__id != acme_order_1__id

        # "admin:acme_order:focus",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s" % acme_order_2__id, status=200
        )
        # "admin:acme_order:focus:acme_server:sync",
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/acme-server/sync"
            % acme_order_2__id,
            {},
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/peter_sslers/acme-order/%s?result=success&operation=acme+server+sync"
            % acme_order_2__id
        )

        # "admin:acme_order:focus",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s" % acme_order_2__id, status=200
        )

        # IMPORTANT
        # pebble re-uses the authorizations
        # so we can either "process" or "finalize" here

        # let's call finalize
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/acme-finalize" % acme_order_2__id,
            {},
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/peter_sslers/acme-order/%s?result=success&operation=acme+finalize"
            % acme_order_2__id
        )

        # "admin:acme_order:focus",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s" % acme_order_2__id, status=200
        )
        matched = RE_AcmeOrder_status.search(res.text)
        assert matched
        assert matched.groups()[0] == "valid"

        assert (
            'href="/.well-known/peter_sslers/renewal-configuration/%s/new-configuration"'
            % renewal_configuration_1__id
            in res.text
        )

        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/new-configuration"
            % renewal_configuration_1__id,
            status=200,
        )
        form = res.forms["form-renewal_configuration-new_configuration"]

        # we can just change the `private_key_cycle`
        form["private_key_cycle"].force_value("single_use")
        res2 = form.submit()
        assert res2.status_code == 303
        matched = RE_RenewalConfiguration.match(res2.location)
        assert matched
        renewal_configuration_2__id = int(matched.groups()[0])
        assert renewal_configuration_2__id != renewal_configuration_1__id

        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s"
            % renewal_configuration_2__id,
            status=200,
        )

        assert (
            'href="/.well-known/peter_sslers/renewal-configuration/%s/new-order"'
            % renewal_configuration_2__id
            in res.text
        )

        res2 = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/new-order"
            % renewal_configuration_2__id,
            status=200,
        )
        form = res2.forms["form-renewal_configuration-new_order"]
        form["processing_strategy"].force_value("create_order")
        res3 = form.submit()
        assert res3.status_code == 303

        matched = RE_AcmeOrder_renewal_configuration.search(res3.location)
        assert matched
        acme_order_3__id = int(matched.groups()[0])
        assert acme_order_3__id != acme_order_2__id
        assert acme_order_3__id != acme_order_1__id

        res4 = self.testapp.get(res3.location, status=200)
        form = res4.forms["form-acme_server-sync"]
        res5 = form.submit()
        assert res5.status_code == 303

        assert res5.location == (
            "http://peter-sslers.example.com/.well-known/peter_sslers/acme-order/%s?result=success&operation=acme+server+sync"
            % acme_order_3__id
        )

        # "admin:acme_order:focus",
        res6 = self.testapp.get(res5.location, status=200)

        # deactivate so we don't block
        form = res6.forms["form-deactivate_order"]
        res7 = form.submit()
        assert res7.status_code == 303
        assert res7.location == (
            "http://peter-sslers.example.com/.well-known/peter_sslers/acme-order/%s?result=success&operation=mark&action=deactivate"
            % acme_order_3__id
        )

        #
        # to handle the next series, we must use a new order with different domains
        #
        # we need two for this test
        assert len(_test_data["acme-order/new/freeform#2"]["domain_names_http01"]) == 2

        # the original test setup was for an interface that accepted account data
        (dbAcmeAccount, acme_account_id) = make_one__AcmeAccount__pem(
            self,
            account__contact=_test_data["acme-order/new/freeform#2"][
                "account__contact"
            ],
            pem_file_name=_test_data["acme-order/new/freeform#2"][
                "account_key_file_pem"
            ],
        )

        # "admin:acme_order:new:freeform",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/new/freeform", status=200
        )

        form = res.form
        _form_fields = form.fields.keys()
        assert "account_key_option" in _form_fields
        form["account_key_option"].force_value("account_key_existing")
        form["account_key_existing"].force_value(
            dbAcmeAccount.acme_account_key.key_pem_md5
        )
        form["private_key_option"].force_value("account_default")
        form["private_key_cycle"].force_value("account_default")
        form["domain_names_http01"] = ",".join(
            _test_data["acme-order/new/freeform#2"]["domain_names_http01"]
        )
        form["processing_strategy"].force_value("create_order")
        res2 = form.submit()
        assert res2.status_code == 303

        # "admin:acme_order:focus",
        matched = RE_AcmeOrder.match(res2.location)
        assert matched
        acme_order_4__id = int(matched.groups()[0])
        assert acme_order_4__id != acme_order_3__id
        assert acme_order_3__id != acme_order_2__id
        assert acme_order_3__id != acme_order_1__id

        # grab the order
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s" % acme_order_4__id, status=200
        )

        # sync_authorizations
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/acme-server/sync-authorizations"
            % acme_order_4__id,
            {},
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/peter_sslers/acme-order/%s?result=success&operation=acme+server+sync+authorizations"
            % acme_order_4__id
        )

        # grab the order
        # look for deactivate-authorizations
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s" % acme_order_4__id, status=200
        )
        assert RE_AcmeOrder_btn_deactive_authorizations.findall(res.text)

        # "admin:acme_order:focus:acme_server:deactivate_authorizations",
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/acme-server/deactivate-authorizations"
            % acme_order_4__id,
            {},
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/peter_sslers/acme-order/%s?result=success&operation=acme+server+deactivate+authorizations"
            % acme_order_4__id
        )

        # grab the order
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s" % acme_order_4__id, status=200
        )
        # look for deactivate-authorizations
        assert RE_AcmeOrder_btn_deactive_authorizations__off.findall(res.text)

        # "admin:acme_order:focus:retry",
        assert "acme_order-retry" in res.forms
        form = res.forms["acme_order-retry"]
        res = form.submit()
        assert res.status_code == 303

        matched = RE_AcmeOrder_retry.match(res.location)
        assert matched
        acme_order_5__id = int(matched.groups()[0])

        assert acme_order_5__id != acme_order_4__id
        assert acme_order_5__id != acme_order_3__id
        assert acme_order_5__id != acme_order_2__id
        assert acme_order_5__id != acme_order_1__id

        # deactivate so we don't block
        res = self.testapp.get(res.location, status=200)
        form = res.forms["form-deactivate_order"]
        res2 = form.submit()
        assert res2.status_code == 303
        assert res2.location == (
            "http://peter-sslers.example.com/.well-known/peter_sslers/acme-order/%s?result=success&operation=mark&action=deactivate"
            % acme_order_5__id
        )

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_order:new:freeform",
            "admin:acme_order:focus",
            "admin:acme_order:focus:retry",
            "admin:acme_order:focus:mark",
        )
    )
    def test_AcmeOrder_mark_html(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeOrder.test_AcmeOrder_mark_html
        """
        (obj_id, obj_url) = self._prep_AcmeOrder_html()

        # grab the order
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s" % obj_id, status=200
        )
        obj = self.ctx.dbSession.query(model_objects.AcmeOrder).get(obj_id)
        assert obj
        # obj.as_json

        # "mark" deactivate
        # the raw html has a lot of whitespace, which may not show up in the test response
        assert "form-deactivate_order" in res.forms

        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/mark" % obj_id,
            {"action": "deactivate"},
            status=303,
        )
        matched = RE_AcmeOrder_deactivated.match(res.location)
        assert matched

        # grab the order
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s" % obj_id, status=200
        )

        # "mark" invalid
        assert "form-acme_order-mark_invalid" in res.forms
        form = res.forms["form-acme_order-mark_invalid"]
        res = form.submit()
        matched = RE_AcmeOrder_invalidated.match(res.location)
        assert matched

        # now try a manual post. it must fail.
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/mark" % obj_id,
            {"action": "invalid"},
            status=303,
        )
        matched = RE_AcmeOrder_invalidated_error.match(res.location)
        assert matched

        # grab the order
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s" % obj_id, status=200
        )

        # acme_order-retry is only available if we recently failed..

        obj_id__4: int

        # "admin:acme_order:focus:retry",
        if "acme_order-retry" in res.forms:
            form = res.forms["acme_order-retry"]
            res = form.submit()
            assert res.status_code == 303
            matched = RE_AcmeOrder_retry.match(res.location)
            """
            # Try to debug this block...
            log.debug("="*40)
            log.debug(res.location)
            log.debug(matched)
            dbAcmeOrdersAll = self.ctx.dbSession.query(model_objects.AcmeOrder).all()

            dbAllPotentials = self.ctx.dbSession.query(model_objects.AcmeAuthorizationPotential).all()
            dbAllAuthz= self.ctx.dbSession.query(model_objects.AcmeAuthorization).all()
            dbAllDamains = {d.id: d.domain_name for d in self.ctx.dbSession.query(model_objects.Domain).all()}

            """
            assert matched
            obj_id__4 = int(matched.groups()[0])

        else:
            # now look for a "new order" option
            dbAcmeOrder = self.ctx.dbSession.query(model_objects.AcmeOrder).get(obj_id)
            assert dbAcmeOrder
            url_expected = (
                '/renewal-configuration/%s/new-order"'
                % dbAcmeOrder.renewal_configuration_id
            )
            assert url_expected in res.content
            obj_id__4 = 1

        # grab the NEW order
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s" % obj_id__4, status=200
        )

        # go to the renewal configuration
        matched = RE_RenewalConfiguration_link.search(res.text)
        assert matched
        renewal_configuration_id = matched.groups()[0]

        # grab it
        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s"
            % renewal_configuration_id,
            status=200,
        )

        # new orders should default to auto-renew on
        try:
            assert "form-renewal_configuration-mark-inactive" in res.forms
        except:
            print(res.text)
        form = res.forms["form-renewal_configuration-mark-inactive"]
        res = form.submit()
        assert res.status_code == 303
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/peter_sslers/renewal-configuration/%s?result=success&operation=mark&action=inactive"
            % renewal_configuration_id
        )

        # grab the RenewalConfiguration again...
        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s"
            % renewal_configuration_id,
            status=200,
        )

        # and toggle it the other way
        assert "form-renewal_configuration-mark-active" in res.forms
        form = res.forms["form-renewal_configuration-mark-active"]
        res = form.submit()

        assert res.status_code == 303
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/peter_sslers/renewal-configuration/%s?result=success&operation=mark&action=active"
            % renewal_configuration_id
        )

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_order:new:freeform",
            "admin:acme_order:focus",
            "admin:certificate_signed:focus:ari_check",
        )
    )
    def test_AcmeOrder_process_single_html(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeOrder.test_AcmeOrder_process_single_html
        """
        (obj_id, obj_url) = self._prep_AcmeOrder_html(
            processing_strategy="process_single"
        )

        # /acme-order
        res = self.testapp.get(obj_url, status=200)
        assert (
            """<td><span class="label label-default">process_single</span></td>"""
            in res.text
        )
        assert """<td><code>valid</code>""" in res.text
        assert (
            """<td><span class="label label-default">certificate_downloaded</span></td>"""
            in res.text
        )

        # !!!: admin:certificate_signed:focus:ari_check
        dbAcmeOrder = self.ctx.dbSession.query(model_objects.AcmeOrder).get(obj_id)
        assert dbAcmeOrder
        certificate_signed_id = dbAcmeOrder.certificate_signed_id
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s" % certificate_signed_id,
            status=200,
        )
        form = res.forms["form-certificate_signed-ari_check"]
        res2 = form.submit()
        assert res2.status_code == 303
        assert "?result=success&operation=ari-check" in res2.location

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_order:new:freeform",
            "admin:acme_order:focus",
            "admin:acme_order:focus:acme_process",
        )
    )
    def test_AcmeOrder_process_multi_html(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeOrder.test_AcmeOrder_process_multi_html
        """
        (obj_id, obj_url) = self._prep_AcmeOrder_html(
            processing_strategy="process_multi"
        )

        # /acme-order
        res = self.testapp.get(obj_url, status=200)
        assert RE_AcmeOrder_btn_acme_process__can.findall(res.text)

        process_url = "/.well-known/peter_sslers/acme-order/%s/acme-process" % obj_id

        # get the first process
        res = self.testapp.post(process_url, {}, status=303)
        assert RE_AcmeOrder_processed.match(res.location)

        # get the order again, then the second process
        res = self.testapp.get(obj_url, status=200)
        assert RE_AcmeOrder_btn_acme_process__can.findall(res.text)
        res_p = self.testapp.post(process_url, {}, status=303)
        assert RE_AcmeOrder_processed.match(res_p.location)

        # get the order again, then the third process
        res = self.testapp.get(obj_url, status=200)
        assert RE_AcmeOrder_btn_acme_process__can.findall(res.text)
        res_p = self.testapp.post(process_url, {}, status=303)
        assert RE_AcmeOrder_processed.match(res_p.location)

        # get the order again, it should be done
        res = self.testapp.get(obj_url, status=200)
        assert not RE_AcmeOrder_btn_acme_process__can.findall(res.text)
        assert "<td><code>valid</code>" in res.text
        assert (
            """<td><span class="label label-default">certificate_downloaded</span></td>"""
            in res.text
        )

    @routes_tested(("admin:acme_order:new:freeform|json",))
    def _prep_AcmeOrder_json(self, processing_strategy: str = "create_order"):
        """
        this runs `@under_pebble`, but the invoking function should wrap it

        """
        _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]

        # we need two for this test
        # originally these were scripted, but chaining tests might be mucking this up
        # domain_names_http01 = _test_data["acme-order/new/freeform#1"]["domain_names_http01"]
        # stash these onto the testCase so the actual test can access them
        self._domain_names_http01 = [
            generate_random_domain(testCase=self),
            generate_random_domain(testCase=self),
        ]
        assert len(self._domain_names_http01) == 2
        domain_names_http01 = ",".join(self._domain_names_http01)

        (dbAcmeAccount, acme_account_id) = make_one__AcmeAccount__pem(
            self,
            account__contact=_test_data["acme-order/new/freeform#1"][
                "account__contact"
            ],
            pem_file_name=_test_data["acme-order/new/freeform#1"][
                "account_key_file_pem"
            ],
        )

        res1 = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/new/freeform.json", status=200
        )

        # "admin:acme_order:new:freeform",
        form = {}
        note = generate_random_domain(testCase=self)
        form["account_key_option"] = "account_key_existing"
        form["account_key_existing"] = dbAcmeAccount.acme_account_key.key_pem_md5
        form["private_key_option"] = "account_default"
        form["private_key_cycle"] = "account_default"
        form["domain_names_http01"] = domain_names_http01
        form["processing_strategy"] = processing_strategy
        form["note"] = note
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/new/freeform.json", form
        )
        assert res2.status_code == 200
        assert res2.json["result"] == "success"
        assert "AcmeOrder" in res2.json
        obj_id = res2.json["AcmeOrder"]["id"]
        assert res2.json["AcmeOrder"]["note"] == note

        return obj_id

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_order:new:freeform|json",
            "admin:acme_order:focus|json",
            "admin:acme_order:focus:acme_server:sync|json",
            "admin:acme_order:focus:acme_server:sync_authorizations|json",
            "admin:acme_authorization:focus|json",
            "admin:acme_authorization:focus:acme_server:sync|json",
            "admin:acme_challenge:focus|json",
            "admin:acme_challenge:focus:acme_server:sync|json",
            "admin:acme_challenge:focus:acme_server:trigger|json",
            "admin:acme_order:focus:acme_finalize|json",
            "admin:acme_order:focus:acme_server:deactivate_authorizations|json",
        )
    )
    def test_AcmeOrder_extended_json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_AcmeOrder_extended_json

        NOTE: if domains are not randomized for the order, one needs to reset the pebble instance
        NOTE^^^ this now runs with it's own pebble instance
        """
        _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]

        obj_id = self._prep_AcmeOrder_json()
        acme_order_1__id = obj_id

        # "admin:acme_order:focus|json",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % acme_order_1__id,
            status=200,
        )
        assert "AcmeOrder" in res.json

        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/acme-server/sync.json"
            % acme_order_1__id,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync"

        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/acme-server/sync-authorizations.json"
            % acme_order_1__id,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync-authorizations"

        _dbAcmeOrder = self.ctx.dbSession.query(model_objects.AcmeOrder).get(
            acme_order_1__id
        )
        assert _dbAcmeOrder is not None
        renewal_configuration_1__id = _dbAcmeOrder.renewal_configuration_id

        assert len(_dbAcmeOrder.acme_authorizations) == len(self._domain_names_http01)
        _authorization_pairs = [
            (i.id, i.acme_challenge_http_01.id)
            for i in _dbAcmeOrder.acme_authorizations
        ]
        self.ctx.dbSession.rollback()
        assert len(_authorization_pairs) == 2

        # AuthPair 1
        (auth_id_1, challenge_id_1) = _authorization_pairs[0]

        # "admin:acme_authorization:focus|json",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authorization/%s.json" % auth_id_1,
            status=200,
        )
        assert "AcmeAuthorization" in res.json

        # "admin:acme_authorization:focus:sync|json"
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-authorization/%s/acme-server/sync.json"
            % auth_id_1,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync"

        # note: originally we triggered the AUTHORIZATION `acme-authorization/%s/acme-server/trigger.json`
        # "admin:acme_challenge:focus:acme_server:trigger|json",
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-challenge/%s/acme-server/trigger.json"
            % challenge_id_1,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/trigger"

        # AuthPair 2
        (auth_id_2, challenge_id_2) = _authorization_pairs[1]

        # "admin:acme_challenge:focus|json"
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-challenge/%s.json" % challenge_id_2,
            status=200,
        )
        assert "AcmeChallenge" in res.json

        # "admin:acme_challenge:focus:acme_server:sync|json",
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-challenge/%s/acme-server/sync.json"
            % challenge_id_2,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync"

        # "admin:acme_challenge:focus:acme_server:trigger|json",
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-challenge/%s/acme-server/trigger.json"
            % challenge_id_2,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/trigger"

        # "admin:acme_authorization:focus:sync|json"
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-authorization/%s/acme-server/sync.json"
            % auth_id_2,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync"

        # now go back to the order
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % acme_order_1__id,
            status=200,
        )
        assert "AcmeOrder" in res.json
        assert (
            res.json["AcmeOrder"]["acme_order_processing_status"]
            == "processing_started"
        )

        # "admin:acme_order:focus:acme_server:sync|json",
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/acme-server/sync.json"
            % acme_order_1__id,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync"

        # "admin:acme_order:focus:acme_finalize|json",
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/acme-finalize.json"
            % acme_order_1__id,
            {},
            status=200,
        )

        assert res.json["result"] == "success"
        assert res.json["operation"] == "finalize-order"

        # now go back to the order
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % acme_order_1__id,
            status=200,
        )
        assert "AcmeOrder" in res.json
        assert (
            res.json["AcmeOrder"]["acme_order_processing_status"]
            == "certificate_downloaded"
        )

        assert not res.json["AcmeOrder"]["is_can_acme_process"]
        assert not res.json["AcmeOrder"]["is_can_mark_invalid"]

        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/new-order.json"
            % renewal_configuration_1__id,
            status=200,
        )
        assert "instructions" in res.json

        res2 = self.testapp.post(
            "/.well-known/peter_sslers/renewal-configuration/%s/new-order.json"
            % renewal_configuration_1__id,
            {"processing_strategy": "process_multi"},
        )
        assert res2.status_code == 200
        assert res2.json["result"] == "success"

        acme_order_2__id = res2.json["AcmeOrder"]["id"]
        assert acme_order_2__id != acme_order_1__id

        # "admin:acme_order:focus",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % acme_order_2__id,
            status=200,
        )
        # "admin:acme_order:focus:acme_server:sync",
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/acme-server/sync.json"
            % acme_order_2__id,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync"

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % acme_order_2__id,
            status=200,
        )

        # IMPORTANT
        # pebble re-uses the authorizations
        # so we can either "process" or "finalize" here

        # let's call finalize
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/acme-finalize.json"
            % acme_order_2__id,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "finalize-order"

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % acme_order_2__id,
            status=200,
        )
        assert res.json["AcmeOrder"]["acme_status_order"] == "valid"

        assert (
            res.json["AcmeOrder"]["renewal_configuration_id"]
            == renewal_configuration_1__id
        )
        renewal_configuration_1__domains = ",".join(
            res.json["AcmeOrder"]["RenewalConfiguration"]["domains_challenged"][
                "http-01"
            ]
        )
        account_key = res.json["AcmeOrder"]["AcmeAccount"]["AcmeAccountKey"][
            "key_pem_md5"
        ]

        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/new-configuration.json"
            % renewal_configuration_1__id,
            status=200,
        )
        assert "instructions" in res.json

        # we can just change the `private_key_cycle`
        form = {
            "account_key_option": "account_key_reuse",
            "account_key_reuse": account_key,
            "key_technology": "account_default",
            "private_key_cycle": "single_use",
            "domain_names_http01": renewal_configuration_1__domains,
        }
        res = self.testapp.post(
            "/.well-known/peter_sslers/renewal-configuration/%s/new-configuration.json"
            % renewal_configuration_1__id,
            form,
            status=200,
        )
        assert res.json["result"] == "success"
        assert "RenewalConfiguration" in res.json

        renewal_configuration_id__2 = res.json["RenewalConfiguration"]["id"]
        assert renewal_configuration_1__id != renewal_configuration_id__2

        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s.json"
            % renewal_configuration_id__2,
            status=200,
        )
        res2 = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/new-order.json"
            % renewal_configuration_id__2,
            status=200,
        )
        res3 = self.testapp.post(
            "/.well-known/peter_sslers/renewal-configuration/%s/new-order.json"
            % renewal_configuration_id__2,
            {"processing_strategy": "create_order"},
            status=200,
        )
        assert res3.json["result"] == "success"
        assert "AcmeOrder" in res3.json

        acme_order_3__id = res3.json["AcmeOrder"]["id"]
        assert acme_order_3__id != acme_order_2__id
        assert acme_order_3__id != acme_order_1__id

        assert "url_acme_process" in res3.json["AcmeOrder"]
        assert "url_acme_server_sync" in res3.json["AcmeOrder"]
        assert "url_deactivate" in res3.json["AcmeOrder"]

        res = self.testapp.get(
            res3.json["AcmeOrder"]["url_acme_server_sync"], status=200
        )
        assert "instructions" in res.json
        res = self.testapp.post(
            res3.json["AcmeOrder"]["url_acme_server_sync"], status=200
        )
        assert "instructions" not in res.json
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync"

        # deactivate so we don't block
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/mark.json" % acme_order_3__id,
            {"action": "deactivate"},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "mark"
        assert res.json["action"] == "deactivate"

        #
        # to handle the next series, we must use a new order with different domains
        #
        # we need two for this test
        assert len(_test_data["acme-order/new/freeform#2"]["domain_names_http01"]) == 2

        # the original test setup was for an interface that accepted account data
        (dbAcmeAccount, acme_account_id) = make_one__AcmeAccount__pem(
            self,
            account__contact=_test_data["acme-order/new/freeform#2"][
                "account__contact"
            ],
            pem_file_name=_test_data["acme-order/new/freeform#2"][
                "account_key_file_pem"
            ],
        )

        # "admin:acme_order:new:freeform",
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/new/freeform.json", status=200
        )
        assert "instructions" in res.json

        form = {}
        form["account_key_option"] = "account_key_existing"
        form["account_key_existing"] = dbAcmeAccount.acme_account_key.key_pem_md5
        form["private_key_option"] = "account_default"
        form["private_key_cycle"] = "single_use"
        form["domain_names_http01"] = ",".join(
            _test_data["acme-order/new/freeform#2"]["domain_names_http01"]
        )
        form["processing_strategy"] = "create_order"

        res2 = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/new/freeform.json", form
        )
        assert res2.status_code == 200
        assert res2.json["result"] == "success"
        assert "AcmeOrder" in res2.json

        acme_order_4__id = res2.json["AcmeOrder"]["id"]
        assert acme_order_4__id != acme_order_3__id
        assert acme_order_3__id != acme_order_2__id
        assert acme_order_3__id != acme_order_1__id

        # grab the order
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % acme_order_4__id,
            status=200,
        )
        assert "AcmeOrder" in res.json

        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/acme-server/sync-authorizations.json"
            % acme_order_4__id,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync-authorizations"

        # grab the order
        # look for deactivate-authorizations, ENABLED
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % acme_order_4__id,
            status=200,
        )
        assert "AcmeOrder" in res.json
        assert (
            res.json["AcmeOrder"]["is_can_acme_server_deactivate_authorizations"]
            is True
        )
        assert res.json["AcmeOrder"]["url_deactivate_authorizations"].endswith(
            "/.well-known/peter_sslers/acme-order/%s/acme-server/deactivate-authorizations.json"
            % acme_order_4__id
        )

        # "admin:acme_order:focus:acme_server:deactivate_authorizations",
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/acme-server/deactivate-authorizations.json"
            % acme_order_4__id,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/deactivate-authorizations"

        # grab the order
        # look for deactivate-authorizations, DISABLED
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % acme_order_4__id,
            status=200,
        )
        assert "AcmeOrder" in res.json
        assert (
            res.json["AcmeOrder"]["is_can_acme_server_deactivate_authorizations"]
            is False
        )
        assert res.json["AcmeOrder"]["url_deactivate_authorizations"] is None

        # "admin:acme_order:focus:retry",
        assert res.json["AcmeOrder"]["is_can_retry"] is True
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s/retry.json" % acme_order_4__id,
            status=200,
        )
        assert "HTTP POST required" in res.json["instructions"]

        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/retry.json" % acme_order_4__id,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert "AcmeOrder" in res.json
        acme_order_5__id = res.json["AcmeOrder"]["id"]
        assert acme_order_5__id != acme_order_4__id
        assert acme_order_5__id != acme_order_3__id
        assert acme_order_5__id != acme_order_2__id
        assert acme_order_5__id != acme_order_1__id

        # deactivate so we don't block
        res = self.testapp.post(
            res.json["AcmeOrder"]["url_deactivate_authorizations"], {}, status=200
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/deactivate-authorizations"

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_order:new:freeform|json",
            "admin:acme_order:focus|json",
            "admin:acme_order:focus:retry|json",
            "admin:acme_order:focus:mark|json",
        )
    )
    def test_AcmeOrder_mark_json(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeOrder.test_AcmeOrder_mark_json
        """

        obj_id = self._prep_AcmeOrder_json()

        # grab the order
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % obj_id, status=200
        )
        assert "AcmeOrder" in res.json

        # "mark" deactivate
        assert res.json["AcmeOrder"]["is_processing"]

        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/mark.json?action=deactivate"
            % obj_id,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "mark"
        assert res.json["action"] == "deactivate"

        # grab the order
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % obj_id, status=200
        )
        assert "AcmeOrder" in res.json

        # "mark" invalid
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/mark.json?action=invalid" % obj_id,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "mark"
        assert res.json["action"] == "invalid"

        # grab the order
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % obj_id, status=200
        )
        assert "AcmeOrder" in res.json

        # "admin:acme_order:focus:retry",
        assert "AcmeOrder" in res.json

        assert res.json["AcmeOrder"]["is_can_retry"] is True
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s/retry.json" % obj_id, status=200
        )
        assert "HTTP POST required" in res.json["instructions"]

        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-order/%s/retry.json" % obj_id,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert "AcmeOrder" in res.json
        obj_id__4 = res.json["AcmeOrder"]["id"]

        # grab the NEW order
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % obj_id__4, status=200
        )
        assert "AcmeOrder" in res.json

        renewal_configuration_id = res.json["AcmeOrder"]["renewal_configuration_id"]

        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s.json"
            % renewal_configuration_id,
            status=200,
        )

        # "mark" manual
        try:
            res = self.testapp.post(
                "/.well-known/peter_sslers/renewal-configuration/%s/mark.json"
                % renewal_configuration_id,
                {"action": "inactive"},
                status=200,
            )
            assert res.json["result"] == "success"
            assert res.json["operation"] == "mark"
            assert res.json["action"] == "inactive"

            # and toggle it the other way
            res = self.testapp.post(
                "/.well-known/peter_sslers/renewal-configuration/%s/mark.json"
                % renewal_configuration_id,
                {"action": "active"},
                status=200,
            )
            assert res.json["result"] == "success"
            assert res.json["operation"] == "mark"
            assert res.json["action"] == "active"

            # lets make sure we can't do it again!
            res = self.testapp.post(
                "/.well-known/peter_sslers/renewal-configuration/%s/mark.json"
                % renewal_configuration_id,
                {"action": "active"},
                status=200,
            )
            assert res.json["result"] == "error"
            assert (
                res.json["form_errors"]["Error_Main"]
                == "There was an error with your form. Already activated."
            )
        except Exception as exc:
            print("EXCEPTION test_AcmeOrder_mark_json")
            print(res.text)
            raise

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_order:new:freeform|json",
            "admin:acme_order:focus|json",
            "admin:certificate_signed:focus:ari_check|json",
        )
    )
    def test_AcmeOrder_process_single_json(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeOrder.test_AcmeOrder_process_single_json
        """
        obj_id = self._prep_AcmeOrder_json(processing_strategy="process_single")

        # /acme-order
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % obj_id, status=200
        )
        assert "AcmeOrder" in res.json
        assert res.json["AcmeOrder"]["is_can_acme_process"] is False
        assert res.json["AcmeOrder"]["acme_status_order"] == "valid"
        assert (
            res.json["AcmeOrder"]["acme_order_processing_status"]
            == "certificate_downloaded"
        )
        assert (
            res.json["AcmeOrder"]["acme_order_processing_strategy"] == "process_single"
        )
        certficate_id = res.json["AcmeOrder"]["certificate_signed_id"]

        # !!!: ari-check
        res = self.testapp.get(
            "/.well-known/peter_sslers/certificate-signed/%s/ari-check.json"
            % certficate_id,
            status=200,
        )
        res2 = self.testapp.post(
            "/.well-known/peter_sslers/certificate-signed/%s/ari-check.json"
            % certficate_id,
            {},
        )
        assert res2.status_code == 200
        assert res2.json["result"] == "success"
        assert "AriCheck" in res2.json

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_order:new:freeform|json",
            "admin:acme_order:focus|json",
            "admin:acme_order:focus:acme_process|json",
        )
    )
    def test_AcmeOrder_process_multi_json(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeOrder.test_AcmeOrder_process_multi_json
        """
        obj_id = self._prep_AcmeOrder_json(processing_strategy="process_multi")

        # /acme-order
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % obj_id, status=200
        )
        assert "AcmeOrder" in res.json
        assert (
            res.json["AcmeOrder"]["acme_order_processing_strategy"] == "process_multi"
        )
        assert res.json["AcmeOrder"]["is_can_acme_process"] is True

        process_url = (
            "/.well-known/peter_sslers/acme-order/%s/acme-process.json" % obj_id
        )

        # post the first process
        res = self.testapp.post(process_url, {}, status=200)
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-process"
        assert "AcmeOrder" in res.json
        assert res.json["AcmeOrder"]["is_can_acme_process"] is True

        # post the second process
        res = self.testapp.post(process_url, {}, status=200)
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-process"
        assert "AcmeOrder" in res.json
        assert res.json["AcmeOrder"]["is_can_acme_process"] is True

        # post the third process
        res = self.testapp.post(process_url, {}, status=200)
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-process"
        assert "AcmeOrder" in res.json
        assert res.json["AcmeOrder"]["is_can_acme_process"] is False
        assert res.json["AcmeOrder"]["acme_status_order"] == "valid"
        assert (
            res.json["AcmeOrder"]["acme_order_processing_status"]
            == "certificate_downloaded"
        )

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(("admin:acme_order:focus:acme_server:download_certificate",))
    def test_AcmeOrder_download_certificate_html(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeOrder.test_AcmeOrder_download_certificate_html
        """
        (obj_id, obj_url) = self._prep_AcmeOrder_html(
            processing_strategy="process_single"
        )
        dbAcmeOrder = lib_db_get.get__AcmeOrder__by_id(self.ctx, obj_id)
        assert dbAcmeOrder is not None
        assert dbAcmeOrder.certificate_signed_id is not None

        # stash the `certificate_signed_id` and delete it from the backend
        certificate_signed_id__og = dbAcmeOrder.certificate_signed_id
        dbAcmeOrder.certificate_signed_id = None
        self.ctx.pyramid_transaction_commit()

        # grab the order
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s" % obj_id, status=200
        )
        assert "acme_order-download_certificate" in res.forms
        form = res.forms["acme_order-download_certificate"]
        res2 = form.submit()
        assert res2.status_code == 303
        assert RE_AcmeOrder_downloaded_certificate.match(res2.location)

        # grab the order again!
        res3 = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s" % obj_id, status=200
        )
        assert "acme_order-download_certificate" not in res3.forms
        certificate_signed_ids = RE_CertificateSigned_main.findall(res3.text)
        assert certificate_signed_ids
        assert len(certificate_signed_ids) >= 1
        certificate_signed_id__downloaded = int(certificate_signed_ids[0])
        assert certificate_signed_id__og == certificate_signed_id__downloaded

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(("admin:acme_order:focus:acme_server:download_certificate|json",))
    def test_AcmeOrder_download_certificate_json(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeOrder.test_AcmeOrder_download_certificate_json
        """
        obj_id = self._prep_AcmeOrder_json(processing_strategy="process_single")
        dbAcmeOrder = lib_db_get.get__AcmeOrder__by_id(self.ctx, obj_id)
        assert dbAcmeOrder is not None
        assert dbAcmeOrder.certificate_signed_id is not None

        # stash the `certificate_signed_id` and delete it from the backend
        certificate_signed_id__og = dbAcmeOrder.certificate_signed_id
        dbAcmeOrder.certificate_signed_id = None
        self.ctx.pyramid_transaction_commit()

        # grab the order
        res2 = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % obj_id, status=200
        )
        assert "AcmeOrder" in res2.json
        assert res2.json["AcmeOrder"]["certificate_signed_id"] is None
        url_acme_certificate_signed_download = res2.json["AcmeOrder"][
            "url_acme_certificate_signed_download"
        ]
        assert url_acme_certificate_signed_download is not None

        # trigger a download
        res3 = self.testapp.post(url_acme_certificate_signed_download, {}, status=200)
        assert res3.json["AcmeOrder"]["url_acme_certificate_signed_download"] is None
        assert res3.json["AcmeOrder"]["certificate_signed_id"] is not None
        certificate_signed_id__downloaded = res3.json["AcmeOrder"][
            "certificate_signed_id"
        ]
        assert certificate_signed_id__downloaded is not None

        # compare the certs
        assert certificate_signed_id__og == certificate_signed_id__downloaded

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            # "admin:acme_order:focus|json",
            "admin:acme_authorization:focus",
            "admin:acme_authorization:focus:acme_server:deactivate",
            "admin:acme_authorization:focus:acme_server:sync",
        )
    )
    def test_AcmeAuthorization_manipulate_html(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeOrder.test_AcmeAuthorization_manipulate_html
        """

        (order_id, order_url) = self._prep_AcmeOrder_html()

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % order_id, status=200
        )
        assert "AcmeOrder" in res.json
        acme_authorization_ids = res.json["AcmeOrder"]["acme_authorization_ids"]
        assert len(acme_authorization_ids) == 2

        #
        # for #1, we deactivate then sync
        #
        id_ = acme_authorization_ids[0]
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authorization/%s" % id_, status=200
        )
        matched = RE_AcmeAuthorization_deactivate_btn.search(res.text)
        assert matched

        res_deactivated = self.testapp.post(
            "/.well-known/peter_sslers/acme-authorization/%s/acme-server/deactivate"
            % id_,
            {},
            status=303,
        )
        assert RE_AcmeAuthorization_deactivated.match(res_deactivated.location)

        # check the main record, ensure we don't have a match
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authorization/%s" % id_, status=200
        )
        matched_btn = RE_AcmeAuthorization_deactivate_btn.search(res.text)
        assert not matched_btn
        matched_btn = RE_AcmeAuthorization_sync_btn.search(res.text)
        assert matched_btn

        # try again, and fail
        res_deactivated = self.testapp.post(
            "/.well-known/peter_sslers/acme-authorization/%s/acme-server/deactivate"
            % id_,
            {},
            status=303,
        )
        assert RE_AcmeAuthorization_deactivate_fail.match(res_deactivated.location)

        # now sync
        res_synced = self.testapp.post(
            "/.well-known/peter_sslers/acme-authorization/%s/acme-server/sync" % id_,
            {},
            status=303,
        )
        assert RE_AcmeAuthorization_synced.match(res_synced.location)

        #
        # for #2, the flow was: sync, then trigger, then deactivate
        #
        # this flow is no longer applicable:
        # a) the AcmeAuthorization no longer has a trigger
        # b) AcmeChallenge can be reused by the AcmeServer

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            # "admin:acme_order:focus|json",
            "admin:acme_authorization:focus|json",
            "admin:acme_authorization:focus:acme_server:deactivate|json",
            "admin:acme_authorization:focus:acme_server:sync|json",
        )
    )
    def test_AcmeAuthorization_manipulate_json(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeOrder.test_AcmeAuthorization_manipulate_json
        """

        order_id = self._prep_AcmeOrder_json(processing_strategy="create_order")

        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % order_id, status=200
        )
        assert "AcmeOrder" in res.json
        acme_authorization_ids = res.json["AcmeOrder"]["acme_authorization_ids"]
        assert len(acme_authorization_ids) == 2

        # for #1, we deactivate then sync
        id_ = acme_authorization_ids[0]
        res = self.testapp.get(
            "/.well-known/peter_sslers/acme-authorization/%s.json" % id_, status=200
        )
        assert "AcmeAuthorization" in res.json
        assert res.json["AcmeAuthorization"]["url_acme_server_deactivate"] is not None

        res_deactivated = self.testapp.post(
            "/.well-known/peter_sslers/acme-authorization/%s/acme-server/deactivate.json"
            % id_,
            {},
            status=200,
        )
        assert res_deactivated.json["result"] == "success"
        assert res_deactivated.json["operation"] == "acme-server/deactivate"

        # check the main record, ensure we don't have a match
        assert "AcmeAuthorization" in res_deactivated.json
        assert (
            res_deactivated.json["AcmeAuthorization"]["url_acme_server_deactivate"]
            is None
        )
        assert (
            res_deactivated.json["AcmeAuthorization"]["url_acme_server_sync"]
            is not None
        )

        # try again, and fail
        res_deactivated = self.testapp.post(
            "/.well-known/peter_sslers/acme-authorization/%s/acme-server/deactivate.json"
            % id_,
            {},
            status=200,
        )
        assert res_deactivated.json["result"] == "error"
        assert res_deactivated.json["operation"] == "acme-server/deactivate"
        assert (
            res_deactivated.json["error"]
            == "ACME Server Sync is not allowed for this AcmeAuthorization"
        )

        # now sync
        res_synced = self.testapp.post(
            "/.well-known/peter_sslers/acme-authorization/%s/acme-server/sync.json"
            % id_,
            {},
            status=200,
        )
        assert res_synced.json["result"] == "success"
        assert res_synced.json["operation"] == "acme-server/sync"

        #
        # for #2, the flow was: sync, then trigger, then deactivate
        #
        # this flow is no longer applicable:
        # a) the AcmeAuthorization no longer has a trigger
        # b) AcmeChallenge can be reused by the AcmeServer

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_challenge:focus",
            "admin:acme_challenge:focus:acme_server:sync",
            "admin:acme_challenge:focus:acme_server:trigger",
        )
    )
    def test_AcmeChallenge_manipulate_html(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeOrder.test_AcmeChallenge_manipulate_html
        """
        (order_id, order_url) = self._prep_AcmeOrder_html()

        res_order = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % order_id, status=200
        )
        acme_authorization_ids = res_order.json["AcmeOrder"]["acme_authorization_ids"]
        assert len(acme_authorization_ids) == 2

        # loop these as an enumeration
        for idx, authorization_id in enumerate(acme_authorization_ids):
            # Auth1
            res_auth = self.testapp.get(
                "/.well-known/peter_sslers/acme-authorization/%s.json"
                % authorization_id,
                status=200,
            )
            # sync it to load the challenge
            res_auth = self.testapp.post(
                "/.well-known/peter_sslers/acme-authorization/%s/acme-server/sync.json"
                % authorization_id,
                {},
                status=200,
            )
            assert res_auth.json["result"] == "success"
            assert res_auth.json["operation"] == "acme-server/sync"
            assert (
                res_auth.json["AcmeAuthorization"]["acme_status_authorization"]
                == "pending"
            )
            challenge_id = res_auth.json["AcmeAuthorization"][
                "acme_challenge_http_01_id"
            ]
            assert challenge_id is not None

            if idx == 0:
                # iteration 1: sync then trigger

                # Get/Audit Main Record
                res_challenge = self.testapp.get(
                    "/.well-known/peter_sslers/acme-challenge/%s" % challenge_id,
                    status=200,
                )
                assert RE_AcmeChallenge_sync_btn.search(res_challenge.text)
                assert RE_AcmeChallenge_trigger_btn.search(res_challenge.text)

                # sync
                res_sync = self.testapp.post(
                    "/.well-known/peter_sslers/acme-challenge/%s/acme-server/sync"
                    % challenge_id,
                    {},
                    status=303,
                )
                assert RE_AcmeChallenge_synced.match(res_sync.location)

                # Get/Audit Main Record
                res_challenge = self.testapp.get(
                    "/.well-known/peter_sslers/acme-challenge/%s" % challenge_id,
                    status=200,
                )
                assert RE_AcmeChallenge_sync_btn.search(res_challenge.text)
                assert RE_AcmeChallenge_trigger_btn.search(res_challenge.text)

                # trigger
                res_trigger = self.testapp.post(
                    "/.well-known/peter_sslers/acme-challenge/%s/acme-server/trigger"
                    % challenge_id,
                    {},
                    status=303,
                )
                assert RE_AcmeChallenge_triggered.match(res_trigger.location)

                # Get/Audit Main Record
                res_challenge = self.testapp.get(
                    "/.well-known/peter_sslers/acme-challenge/%s" % challenge_id,
                    status=200,
                )
                assert RE_AcmeChallenge_sync_btn.search(res_challenge.text)
                assert not RE_AcmeChallenge_trigger_btn.search(res_challenge.text)

                # trigger fail
                res_trigger = self.testapp.post(
                    "/.well-known/peter_sslers/acme-challenge/%s/acme-server/trigger"
                    % challenge_id,
                    {},
                    status=303,
                )
                assert RE_AcmeChallenge_trigger_fail.match(res_trigger.location)

            else:
                # iteration 2: trigger then sync

                # Get/Audit Main Record
                res_challenge = self.testapp.get(
                    "/.well-known/peter_sslers/acme-challenge/%s" % challenge_id,
                    status=200,
                )
                assert RE_AcmeChallenge_sync_btn.search(res_challenge.text)
                assert RE_AcmeChallenge_trigger_btn.search(res_challenge.text)

                # trigger
                res_trigger = self.testapp.post(
                    "/.well-known/peter_sslers/acme-challenge/%s/acme-server/trigger"
                    % challenge_id,
                    {},
                    status=303,
                )
                assert RE_AcmeChallenge_triggered.match(res_trigger.location)

                # Get/Audit Main Record
                res_challenge = self.testapp.get(
                    "/.well-known/peter_sslers/acme-challenge/%s" % challenge_id,
                    status=200,
                )
                assert RE_AcmeChallenge_sync_btn.search(res_challenge.text)
                assert not RE_AcmeChallenge_trigger_btn.search(res_challenge.text)

                # sync
                res_sync = self.testapp.post(
                    "/.well-known/peter_sslers/acme-challenge/%s/acme-server/sync"
                    % challenge_id,
                    {},
                    status=303,
                )
                assert RE_AcmeChallenge_synced.match(res_sync.location)

                # Get/Audit Main Record
                res_challenge = self.testapp.get(
                    "/.well-known/peter_sslers/acme-challenge/%s" % challenge_id,
                    status=200,
                )
                assert RE_AcmeChallenge_sync_btn.search(res_challenge.text)
                assert not RE_AcmeChallenge_trigger_btn.search(res_challenge.text)

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_challenge:focus|json",
            "admin:acme_challenge:focus:acme_server:sync|json",
            "admin:acme_challenge:focus:acme_server:trigger|json",
        )
    )
    def test_AcmeChallenge_manipulate_json(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeOrder.test_AcmeChallenge_manipulate_json
        """

        order_id = self._prep_AcmeOrder_json()

        res_order = self.testapp.get(
            "/.well-known/peter_sslers/acme-order/%s.json" % order_id, status=200
        )
        acme_authorization_ids = res_order.json["AcmeOrder"]["acme_authorization_ids"]
        assert len(acme_authorization_ids) == 2

        # loop these as an enumeration
        for idx, authorization_id in enumerate(acme_authorization_ids):
            # Auth1
            res_auth = self.testapp.get(
                "/.well-known/peter_sslers/acme-authorization/%s.json"
                % authorization_id,
                status=200,
            )
            # sync it to load the challenge
            res_auth = self.testapp.post(
                "/.well-known/peter_sslers/acme-authorization/%s/acme-server/sync.json"
                % authorization_id,
                {},
                status=200,
            )
            assert res_auth.json["result"] == "success"
            assert res_auth.json["operation"] == "acme-server/sync"
            assert (
                res_auth.json["AcmeAuthorization"]["acme_status_authorization"]
                == "pending"
            )
            challenge_id = res_auth.json["AcmeAuthorization"][
                "acme_challenge_http_01_id"
            ]
            assert challenge_id is not None

            if idx == 0:
                # iteration 1: sync then trigger

                # Get/Audit Main Record
                res_challenge = self.testapp.get(
                    "/.well-known/peter_sslers/acme-challenge/%s.json" % challenge_id,
                    status=200,
                )
                assert (
                    res_challenge.json["AcmeChallenge"]["acme_status_challenge"]
                    == "pending"
                )
                assert (
                    res_challenge.json["AcmeChallenge"]["url_acme_server_sync"]
                    is not None
                )
                assert (
                    res_challenge.json["AcmeChallenge"]["url_acme_server_trigger"]
                    is not None
                )

                # sync
                res_sync = self.testapp.post(
                    "/.well-known/peter_sslers/acme-challenge/%s/acme-server/sync.json"
                    % challenge_id,
                    {},
                    status=200,
                )
                assert res_sync.json["result"] == "success"
                assert res_sync.json["operation"] == "acme-server/sync"
                # Audit Main Record
                assert (
                    res_sync.json["AcmeChallenge"]["acme_status_challenge"] == "pending"
                )
                assert (
                    res_sync.json["AcmeChallenge"]["url_acme_server_sync"] is not None
                )
                assert (
                    res_sync.json["AcmeChallenge"]["url_acme_server_trigger"]
                    is not None
                )

                # trigger
                res_trigger = self.testapp.post(
                    "/.well-known/peter_sslers/acme-challenge/%s/acme-server/trigger.json"
                    % challenge_id,
                    {},
                    status=200,
                )
                assert res_trigger.json["result"] == "success"
                assert res_trigger.json["operation"] == "acme-server/trigger"
                # Audit Main Record
                assert (
                    res_trigger.json["AcmeChallenge"]["acme_status_challenge"]
                    == "valid"
                )
                assert (
                    res_trigger.json["AcmeChallenge"]["url_acme_server_sync"]
                    is not None
                )
                assert (
                    res_trigger.json["AcmeChallenge"]["url_acme_server_trigger"] is None
                )

                # trigger fail
                res_trigger = self.testapp.post(
                    "/.well-known/peter_sslers/acme-challenge/%s/acme-server/trigger.json"
                    % challenge_id,
                    {},
                    status=200,
                )
                assert res_trigger.json["result"] == "error"
                assert res_trigger.json["operation"] == "acme-server/trigger"
                assert (
                    res_trigger.json["error"]
                    == "ACME Server Trigger is not allowed for this AcmeChallenge"
                )

            else:
                # iteration 2: trigger then sync

                # Get/Audit Main Record
                res_challenge = self.testapp.get(
                    "/.well-known/peter_sslers/acme-challenge/%s.json" % challenge_id,
                    status=200,
                )
                assert (
                    res_challenge.json["AcmeChallenge"]["acme_status_challenge"]
                    == "pending"
                )
                assert (
                    res_challenge.json["AcmeChallenge"]["url_acme_server_sync"]
                    is not None
                )
                assert (
                    res_challenge.json["AcmeChallenge"]["url_acme_server_trigger"]
                    is not None
                )

                # trigger
                res_trigger = self.testapp.post(
                    "/.well-known/peter_sslers/acme-challenge/%s/acme-server/trigger.json"
                    % challenge_id,
                    {},
                    status=200,
                )
                assert res_trigger.json["result"] == "success"
                assert res_trigger.json["operation"] == "acme-server/trigger"
                # Audit Main Record
                assert (
                    res_trigger.json["AcmeChallenge"]["acme_status_challenge"]
                    == "valid"
                )
                assert (
                    res_trigger.json["AcmeChallenge"]["url_acme_server_sync"]
                    is not None
                )
                assert (
                    res_trigger.json["AcmeChallenge"]["url_acme_server_trigger"] is None
                )

                # sync
                res_sync = self.testapp.post(
                    "/.well-known/peter_sslers/acme-challenge/%s/acme-server/sync.json"
                    % challenge_id,
                    {},
                    status=200,
                )
                assert res_sync.json["result"] == "success"
                assert res_sync.json["operation"] == "acme-server/sync"
                # Audit Main Record
                assert (
                    res_sync.json["AcmeChallenge"]["acme_status_challenge"] == "valid"
                )
                assert (
                    res_sync.json["AcmeChallenge"]["url_acme_server_sync"] is not None
                )
                assert res_sync.json["AcmeChallenge"]["url_acme_server_trigger"] is None

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(("admin:api:domain:autocert|json",))
    def test_Api_Domain_autocert_json(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeOrder.test_Api_Domain_autocert_json
        """
        res = self.testapp.post(
            "/.well-known/peter_sslers/api/domain/autocert.json", {}, status=200
        )
        assert "result" in res.json
        assert res.json["result"] == "error"
        assert "form_errors" in res.json
        assert res.json["form_errors"]["Error_Main"] == "Nothing submitted."
        assert res.json["Domain"] is None
        assert res.json["certificate_signed__latest_single"] is None
        assert res.json["certificate_signed__latest_multi"] is None

        # Test 1 -- autocert a domain we don't know, but want to pass
        res = self.testapp.post(
            "/.well-known/peter_sslers/api/domain/autocert.json",
            {"domain_name": "test-domain-autocert-1.example.com"},
            status=200,
        )
        assert res.json["result"] == "success"
        assert "Domain" in res.json
        assert "certificate_signed__latest_multi" in res.json
        assert "certificate_signed__latest_single" in res.json
        assert res.json["certificate_signed__latest_single"] is not None
        assert "AcmeOrder" in res.json

        # Test 2 -- autocert that same domain
        res = self.testapp.post(
            "/.well-known/peter_sslers/api/domain/autocert.json",
            {"domain_name": "test-domain-autocert-1.example.com"},
            status=200,
        )
        assert res.json["result"] == "success"
        assert "Domain" in res.json
        assert "certificate_signed__latest_multi" in res.json
        assert "certificate_signed__latest_single" in res.json
        assert res.json["certificate_signed__latest_single"] is not None
        assert "AcmeOrder" not in res.json

        # Test 3 -- blocklist a domain, then try to autocert
        dbDomainBlocklisted = make_one__DomainBlocklisted(
            testCase=self,
            domain_name="test-domain-autocert-2.example.com",
        )

        res = self.testapp.post(
            "/.well-known/peter_sslers/api/domain/autocert.json",
            {"domain_name": "test-domain-autocert-2.example.com"},
            status=200,
        )
        assert "result" in res.json
        assert res.json["result"] == "error"
        assert "form_errors" in res.json
        assert (
            res.json["form_errors"]["Error_Main"]
            == "There was an error with your form."
        )
        assert (
            res.json["form_errors"]["domain_name"]
            == "This domain_name has been blocklisted"
        )
        assert res.json["Domain"] is None
        assert res.json["certificate_signed__latest_single"] is None
        assert res.json["certificate_signed__latest_multi"] is None

        # Test 4 -- autocert a domain that we do know
        # 4.1 add the domain
        res = self.testapp.get("/.well-known/peter_sslers/domain/new", status=200)
        assert "form-domain-new" in res.forms
        form = res.forms["form-domain-new"]
        form["domain_name"] = "test-domain-autocert-3.example.com"
        res2 = form.submit()
        assert res2.status_code == 303
        matched = RE_Domain_new.match(res2.location)
        assert matched
        focus_id = matched.groups()[0]

        # 4.2 autocert
        res = self.testapp.post(
            "/.well-known/peter_sslers/api/domain/autocert.json",
            {"domain_name": "test-domain-autocert-3.example.com"},
            status=200,
        )
        assert "result" in res.json
        assert res.json["result"] == "success"
        assert "Domain" in res.json

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @unittest.skipUnless(RUN_API_TESTS__ACME_DNS_API, "Not Running Against: acme-dns")
    @under_pebble
    def test_replaces(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer_AcmeOrder.test_replaces

        Test to handle `replaces`:
          1 FAIL replace an unknown certificate
          2 PASS replace a cert from the same renewal
          3 FAIL replace a replaced certificate
          4 PASS replace a cert from a different renewal with the same fqdn set
          5 FAIL replace a cert from a different renewal with a different fqdn set
          6 PASS replace an imported cert with the same fqdn set
          7 FAIL replace an imported cert with a different fqdn set

        These tests will use the following domains:
            a.example.com
            b.example.com
        Uploadable certs for these domains are in the test-data folder
        """

        def _upload_pebble_cert(privkey_id: int, lineage_name: str) -> Tuple[int, str]:
            # returns a Tuple[id, ari_identifier]
            # upload a test cert
            res = self.testapp.get(
                "/.well-known/peter_sslers/certificate-signed/upload.json", status=200
            )
            form = {}
            form["private_key_file_pem"] = Upload(
                self._filepath_testfile("pebble-certs/privkey%s.pem" % privkey_id)
            )
            form["certificate_file"] = Upload(
                self._filepath_testfile(
                    "pebble-certs/privkey%s/%s/cert.pem" % (privkey_id, lineage_name)
                )
            )
            form["chain_file"] = Upload(
                self._filepath_testfile(
                    "pebble-certs/privkey%s/%s/chain.pem" % (privkey_id, lineage_name)
                )
            )
            res2 = self.testapp.post(
                "/.well-known/peter_sslers/certificate-signed/upload.json", form
            )
            assert res2.status_code == 200
            assert res2.json["result"] == "success"
            assert res2.json["CertificateSigned"]["created"] in (True, False)
            certificate_id = res2.json["CertificateSigned"]["id"]
            res3 = self.testapp.get(
                "/.well-known/peter_sslers/certificate-signed/%s.json" % certificate_id,
                status=200,
            )
            assert "CertificateSigned" in res3.json
            ari_identifier = res3.json["CertificateSigned"]["ari_identifier"]
            return (certificate_id, ari_identifier)

        def _make_one__AcmeOrder_Renewal(
            _dbAcmeOrder: model_objects.AcmeOrder,
            _replaces: Optional[str],
            _expected_result: Literal["FAIL", "PASS"],
        ):
            """
            _dbAcmeOrder: use this AcmeOrder's RenewalConfiguration for new order
            _replaces: ari.identifier we are replacing
            _expected_result: json value
            """
            _res = self.testapp.get(
                "/.well-known/peter_sslers/renewal-configuration/%s/new-order.json"
                % _dbAcmeOrder.renewal_configuration_id,
                status=200,
            )
            _post_args = {
                "processing_strategy": "process_single",
            }
            if _replaces:
                _post_args["replaces"] = _replaces
            _res2 = self.testapp.post(
                "/.well-known/peter_sslers/renewal-configuration/%s/new-order.json"
                % _dbAcmeOrder.renewal_configuration_id,
                _post_args,
            )
            assert _res2.status_code == 200
            try:
                if _expected_result == "FAIL":
                    assert _res2.json["result"] == "error"
                elif _expected_result == "PASS":
                    assert _res2.json["result"] == "success"
            except:
                print("=============================")
                print("EXCEPTION _make_one__AcmeOrder_Renewal")
                pprint.pprint(_res2.json)
                raise

        # these are all single domain certs sharing a single key
        _existing_certs = (
            # privkey, lineage
            (1, "a.test-replaces.example.com"),
            (1, "b.test-replaces.example.com"),
            # (1, "c.test-replaces.example.com"),
        )
        lineage_2_certdata = {}
        for _privkey_id, _lineage_name in _existing_certs:
            _cert_id, _ari_id = _upload_pebble_cert(_privkey_id, _lineage_name)
            lineage_2_certdata[_lineage_name] = (_cert_id, _ari_id)

        # prep with some orders of different lineage
        dbAcmeOrder_1 = make_one__AcmeOrder(
            self,
            domain_names_http01="a.test-replaces.example.com",
            processing_strategy="process_single",
        )
        # same UniqueFQDNSet, different UniquelyChallengedFqdnSet
        dbAcmeOrder_2 = make_one__AcmeOrder(
            self,
            domain_names_http01="a.test-replaces.example.com",
            processing_strategy="process_single",
        )
        # different domains
        dbAcmeOrder_3 = make_one__AcmeOrder(
            self,
            domain_names_http01="b.test-replaces.example.com",
            processing_strategy="process_single",
        )

        # we need ARI that is incompatible
        # 1=a.example.com
        # this is a tuple: (certificate_id, ari_identifier)
        # pebble-certs/cert1.pem: a.example.com
        # pebble-certs/cert2.pem: b.example.com

        # note: TestCase 1- FAIL replace an unknown `replaces`
        _result = _make_one__AcmeOrder_Renewal(
            dbAcmeOrder_1,
            _replaces="fake.ari",
            _expected_result="FAIL",
        )
        log.info("test_replaces- Passed: TestCase 1")

        # note: TestCase 2- PASS replace a cert from the same renewal configuration
        _result = _make_one__AcmeOrder_Renewal(
            dbAcmeOrder_1,
            _replaces=dbAcmeOrder_1.certificate_signed.ari_identifier,
            _expected_result="PASS",
        )
        log.info("test_replaces- Passed: TestCase 2")

        # note: TestCase 3- FAIL replace a replaced certificate
        # the replacement was just consumed in test 3
        _result = _make_one__AcmeOrder_Renewal(
            dbAcmeOrder_1,
            _replaces=dbAcmeOrder_1.certificate_signed.ari_identifier,
            _expected_result="FAIL",
        )
        log.info("test_replaces- Passed: TestCase 3")

        # note: TestCase 4- PASS replace a cert from a different config with the same fqdn set
        # dbAcmeOrder_2 has the same fqdns, but a different config due to the dns challenges
        _result = _make_one__AcmeOrder_Renewal(
            dbAcmeOrder_1,
            _replaces=dbAcmeOrder_2.certificate_signed.ari_identifier,
            _expected_result="PASS",
        )
        log.info("test_replaces- Passed: TestCase 4")

        # note: TestCase 5- FAIL replace a cert from a different renewal with a different fqdn set
        _result = _make_one__AcmeOrder_Renewal(
            dbAcmeOrder_1,
            _replaces=dbAcmeOrder_3.certificate_signed.ari_identifier,
            _expected_result="FAIL",
        )
        log.info("test_replaces- Passed: TestCase 5")

        # note: TestCase 6- PASS replace an imported cert with the same fqdn set
        # uploaded_pebble_cert_data a tuple: (certificate_id, ari_identifier)
        _result = _make_one__AcmeOrder_Renewal(
            dbAcmeOrder_1,
            _replaces=lineage_2_certdata["a.test-replaces.example.com"][1],
            _expected_result="PASS",
        )
        log.info("test_replaces- Passed: TestCase 6")

        # note: TestCase 7- FAIL replace an imported cert with a different fqdn set
        # uploaded_pebble_cert_data a tuple: (certificate_id, ari_identifier)
        _result = _make_one__AcmeOrder_Renewal(
            dbAcmeOrder_3,
            _replaces=lineage_2_certdata["a.test-replaces.example.com"][1],
            _expected_result="FAIL",
        )
        log.info("test_replaces- Passed: TestCase 7")


class IntegratedTests_Renewals(AppTestWSGI):
    """
    python -m unittest tests.test_pyramid_app.IntegratedTests_Renewals
    """

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble_alt
    @under_pebble
    def test_multi_pebble_renewal__simple(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_Renewals.test_multi_pebble_renewal__simple

        This tests a SIMPLE renewal situation:

        1- create `RenewalConfiguration.1` with Primary and Backup
        2- Manually order the Primary
        3- Manually order the Backup
        4- Run Renewal Script, which should:
            Renew BOTH certs
        """

        do__AcmeServers_sync(self)

        # this will generate the primary cert
        dbAcmeOrder_1 = make_one__AcmeOrder(
            self,
            domain_names_http01="test-multi-pebble-renewal-simple.example.com",
            processing_strategy="process_single",
            account_key_option_backup="account_key_global_backup",
            acme_profile="shortlived",
            acme_profile__backup="shortlived",
        )

        # order the backup...
        res = self.testapp.get(
            "/.well-known/peter_sslers/renewal-configuration/%s/new-order"
            % dbAcmeOrder_1.renewal_configuration_id,
            status=200,
        )
        form = res.forms["form-renewal_configuration-new_order"]
        form["replaces"].force_value("backup")
        form["processing_strategy"].force_value("process_single")
        res2 = form.submit()
        assert res2.status_code == 303
        assert res2.location.endswith("?result=success&operation=renewal+configuration")

        # sleep 5 seconds
        time.sleep(5)

        _results = lib_db_actions.routine__renew_expiring(
            self.ctx,
            {},
            create_public_server=lib_db_actions._create_public_server__fake,
            renewal_configuration_ids__only_process=(
                dbAcmeOrder_1.renewal_configuration_id,
            ),
            count_expected_configurations=2,
        )

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble_alt
    @under_pebble
    def test_multi_pebble_renewal__realistic(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_Renewals.test_multi_pebble_renewal__realistic

        This tests a SIMPLE renewal situation:

        1- create `RenewalConfiguration.1` with Primary and Backup
        2- Manually order the Primary
        3- DO NOT order the Backup
        4- Run Renewal Script, which should:
            Renew PRIMARY
            Issue Backup
        """

        do__AcmeServers_sync(self)

        # this will generate the primary cert
        dbAcmeOrder_1 = make_one__AcmeOrder(
            self,
            domain_names_http01="test-multi-pebble-renewal-realistic.example.com",
            processing_strategy="process_single",
            account_key_option_backup="account_key_global_backup",
            acme_profile="shortlived",
            acme_profile__backup="shortlived",
        )

        # sleep 5 seconds
        time.sleep(5)

        # actually, we order the backups first
        lib_db_actions.routine__order_backups(
            self.ctx,
            {},
            create_public_server=lib_db_actions._create_public_server__fake,
        )

        # then we renew the expiring
        _results = lib_db_actions.routine__renew_expiring(
            self.ctx,
            {},
            create_public_server=lib_db_actions._create_public_server__fake,
            renewal_configuration_ids__only_process=(
                dbAcmeOrder_1.renewal_configuration_id,
            ),
            count_expected_configurations=2,
        )


class IntegratedTests_AcmeOrder_PrivateKeyCycles(AppTestWSGI):
    """
    python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeOrder_PrivateKeyCycles
    """

    @unittest.skipUnless(RUN_API_TESTS__EXTENDED, "Not Running Extended Tests")
    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    def test_PrivateKey_options(self):

        # this tests a new order using every PrivateKey Option

        domain_names_http01 = "test-AcmeOrder-multiple-domains-1.example.com"
        (dbAcmeAccount, acme_account_id) = make_one__AcmeAccount__random(self)

        def _update_AcmeAccount(acc__pkey_cycle: str, acc__pkey_technology: str):
            dbAcmeAccount.order_default_private_key_cycle_id = (
                model_utils.PrivateKeyCycle.from_string(acc__pkey_cycle)
            )
            dbAcmeAccount.order_default_private_key_technology_id = (
                model_utils.KeyTechnology.from_string(acc__pkey_technology)
            )
            self.ctx.dbSession.commit()

        # # original idea was to edit a RenewalConfiguration, but RCs do not support edit
        # def _update_RenewalConfiguration(rc__pkey_cycle: str, rc__pkey_technology: str):
        #    dbRenewalConfiguration.private_key_cycle_id = model_utils.PrivateKeyCycle.from_string(rc__pkey_cycle)
        #    dbRenewalConfiguration.private_key_technology_id = model_utils.KeyTechnology.from_string(rc__pkey_technology)
        #    self.ctx.dbSession.commit()

        def _new_AcmeOrder(
            dbRenewalConfiguration: model_objects.RenewalConfiguration,
        ) -> model_objects.AcmeOrder:
            res = self.testapp.post(
                "/.well-known/peter_sslers/renewal-configuration/%s/new-order.json"
                % dbRenewalConfiguration.id,
                {"processing_strategy": "process_single"},
            )
            assert res.status_code == 200
            assert res.json["result"] == "success"
            assert "AcmeOrder" in res.json
            acme_order_id = res.json["AcmeOrder"]["id"]

            dbAcmeOrder = self.ctx.dbSession.query(model_objects.AcmeOrder).get(
                acme_order_id
            )
            assert dbAcmeOrder
            return dbAcmeOrder

        # we don't need to test the WHOLE matrix, just the unique settings:
        # always run for account_default
        # otherwise, we just need to run 1x of the RenewalConfiguration options
        # current permutations:
        # TESTED :  216
        # SKIPPED:  1044
        seen_RenewalConfiguration: Dict[str, Dict[str, int]] = {}
        _skips = 0
        _testeds = 0

        # iterate: AcmeAccount.private_key_cycle
        for (
            acc__pkey_cycle
        ) in model_utils.PrivateKeyCycle._options_AcmeAccount_order_default:
            # iterate: AcmeAccount.private_key_technology
            for (
                acc__pkey_technology
            ) in model_utils.KeyTechnology._options_AcmeAccount_order_default:
                _update_AcmeAccount(acc__pkey_cycle, acc__pkey_technology)

                # global_weekly, RSA_2048
                #       account_default, account_default
                #       account_default, RSA_2048

                # iterate: RenewalConfiguration.private_key_cycle
                for (
                    rc__pkey_cycle
                ) in (
                    model_utils.PrivateKeyCycle._options_RenewalConfiguration_private_key_cycle
                ):

                    # iterate: RenewalConfiguration.private_key_technology
                    for (
                        rc__pkey_technology
                    ) in (
                        model_utils.KeyTechnology._options_RenewalConfiguration_private_key_technology
                    ):

                        # try to skip out early:
                        # AcmeAccount(single_use, RSA_3072), RenewalConfiguration(global_daily, RSA_2048)
                        if (rc__pkey_cycle != "account_default") and (
                            rc__pkey_cycle != "account_default"
                        ):
                            if rc__pkey_cycle not in seen_RenewalConfiguration:
                                seen_RenewalConfiguration[rc__pkey_cycle] = {}
                            if (
                                rc__pkey_technology
                                not in seen_RenewalConfiguration[rc__pkey_cycle]
                            ):
                                seen_RenewalConfiguration[rc__pkey_cycle][
                                    rc__pkey_technology
                                ] = 1
                            else:
                                log.debug(
                                    "Skipping: AcmeAccount(%s, %s), RenewalConfiguration(%s, %s)"
                                    % (
                                        acc__pkey_cycle,
                                        acc__pkey_technology,
                                        rc__pkey_cycle,
                                        rc__pkey_technology,
                                    )
                                )
                                _skips += 1
                                continue

                        log.debug(
                            "Testing: AcmeAccount(%s, %s), RenewalConfiguration(%s, %s)"
                            % (
                                acc__pkey_cycle,
                                acc__pkey_technology,
                                rc__pkey_cycle,
                                rc__pkey_technology,
                            )
                        )

                        _dbRenewalConfiguration = make_one__RenewalConfiguration(
                            self,
                            dbAcmeAccount=dbAcmeAccount,
                            domain_names_http01=domain_names_http01,
                            private_key_cycle=rc__pkey_cycle,
                            key_technology=rc__pkey_technology,
                        )

                        _dbAcmeOrder = _new_AcmeOrder(_dbRenewalConfiguration)
                        _testeds += 1

            log.info("TESTED : ", _testeds)
            log.info("SKIPPED: ", _skips)


class IntegratedTests_EdgeCases_AcmeServer(AppTestWSGI):
    """
    python -m unittest tests.test_pyramid_app.IntegratedTests_EdgeCases_AcmeServer
    """

    def test_AcmeAccount_new(self):

        # note: NEW without a required field
        form = {
            "acme_server_id": 1,
            "account__contact": generate_random_emailaddress(),
            "account__private_key_technology": "EC_P256",
            "account__order_default_private_key_cycle": "single_use",
            "account__order_default_private_key_technology": "EC_P256",
        }
        for field in list(form.keys()):
            log.info("testing new: %s" % field)
            _form = form.copy()
            del _form[field]
            res = self.testapp.post(
                "/.well-known/peter_sslers/acme-account/new.json", _form
            )
            assert res.status_code == 200
            assert res.json["result"] == "error"
            assert "form_errors" in res.json
            assert field in res.json["form_errors"]

        # note: UPLOAD without a required field - PEM
        form = {
            "account_key_file_pem": Upload(
                self._filepath_testfile("pebble-certs/privkey1.pem")
            ),
            "acme_server_id": 1,
            "account__contact": generate_random_emailaddress(),
            "account__order_default_private_key_cycle": "account_daily",
            "account__order_default_private_key_technology": "EC_P256",
        }
        for field in list(form.keys()):
            log.info("testing upload PEM: %s" % field)
            _form = form.copy()
            del _form[field]
            res = self.testapp.post(
                "/.well-known/peter_sslers/acme-account/upload.json", _form
            )
            assert res.status_code == 200
            assert res.json["result"] == "error"
            assert "form_errors" in res.json
            assert field in res.json["form_errors"]

        # note: UPLOAD without a required field - LE
        form_le = {
            "account_key_file_le_meta": Upload(
                self._filepath_testfile("unit_tests/account_001/meta.json")
            ),
            "account_key_file_le_pkey": Upload(
                self._filepath_testfile("unit_tests/account_001/private_key.json")
            ),
            "account_key_file_le_reg": Upload(
                self._filepath_testfile("unit_tests/account_001/regr.json")
            ),
            "account__order_default_private_key_cycle": "account_daily",
            "account__order_default_private_key_technology": "EC_P256",
        }
        for field in list(form_le.keys()):
            log.info("testing upload LE: %s" % field)
            _form = form_le.copy()
            del _form[field]
            res = self.testapp.post(
                "/.well-known/peter_sslers/acme-account/upload.json", _form
            )
            assert res.status_code == 200
            assert res.json["result"] == "error"
            assert "form_errors" in res.json
            assert field in res.json["form_errors"]

        # note: UPLOAD with an unrequired field - LE
        form_le_bad = {
            "acme_server_id": 1,
            "account__contact": generate_random_emailaddress(),
            "account_key_file_pem": Upload(
                self._filepath_testfile("pebble-certs/privkey1.pem")
            ),
        }
        for field in list(form_le_bad.keys()):
            log.info("testing upload MISC: %s" % field)
            _form = form_le.copy()
            _form[field] = form_le_bad[field]
            res = self.testapp.post(
                "/.well-known/peter_sslers/acme-account/upload.json", _form
            )
            assert res.status_code == 200
            assert res.json["result"] == "error"
            assert "form_errors" in res.json
            if field == "acme_server_id":
                assert "account_key_file_pem" in res.json["form_errors"]
            elif field == "account_key_file_pem":
                assert "acme_server_id" in res.json["form_errors"]
            else:
                assert field in res.json["form_errors"]

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    def test_AcmeAccount_duplicate(self):
        """
        this test is designed to trigger the AcmeAccount duplicate error

        1- Create an Account on PeterSSLers that is linked to Pebble
        2- Update the dbAccount to have a different AcmeURL
        3- Authenticate the dbAccount to Pebble

        this should trip the conflicting account
        perhaps instead of auto migration, we do a warning and offer a manual
        migration tool
        """
        # Scenario A
        # step 1 - create the account
        (dbAcmeAccount, acme_account_id) = make_one__AcmeAccount__pem(
            self,
            account__contact="dbAcmeAccount@example.com",
            pem_file_name="key_technology-rsa/AcmeAccountKey-3.pem",
        )

        # step 1b - create the account AGAIN, this should work
        (dbAcmeAccount2, acme_account_id2) = make_one__AcmeAccount__pem(
            self,
            account__contact="dbAcmeAccount@example.com",
            pem_file_name="key_technology-rsa/AcmeAccountKey-3.pem",
        )

        assert dbAcmeAccount.id == dbAcmeAccount2.id

        # Scenario B
        # same key, different contact
        try:
            (dbAcmeAccount3, acme_account_id3) = make_one__AcmeAccount__pem(
                self,
                account__contact="dbAcmeAccount3@example.com",
                pem_file_name="key_technology-rsa/AcmeAccountKey-3.pem",
                expect_failure=True,
            )
        except ResponseFailureOkay as exc_ok:
            res = exc_ok.args[0]
            assert res.status_code == 200
            assert res.json["result"] == "error"
            assert "Error_Main" in res.json["form_errors"]
            assert (
                res.json["form_errors"]["Error_Main"]
                == "There was an error with your form. The submited AcmeAccountKey is already associated with another AcmeAccount."
            )

        # Scenario C
        # different key, same contact
        try:
            (dbAcmeAccount4, acme_account_id4) = make_one__AcmeAccount__pem(
                self,
                account__contact="dbAcmeAccount@example.com",
                pem_file_name="key_technology-rsa/AcmeAccountKey-4.pem",
                expect_failure=True,
            )
        except ResponseFailureOkay as exc_ok:
            res = exc_ok.args[0]
            assert res.status_code == 200
            assert res.json["result"] == "error"
            assert "Error_Main" in res.json["form_errors"]
            assert (
                res.json["form_errors"]["Error_Main"]
                == "There was an error with your form. The submitted AcmeServer and contact info is already associated with another AcmeAccountKey."
            )

        # Scenario D
        # The account URL has changed
        _account_url = dbAcmeAccount.account_url
        _account_url_altered = "%s?altered=1" % dbAcmeAccount.account_url

        # alter the database
        dbAcmeAccount.account_url = _account_url_altered
        self.ctx.dbSession.flush(
            objects=[
                dbAcmeAccount,
            ]
        )
        self.ctx.dbSession.commit()

        # authenticate should reset it
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/authenticate.json"
            % dbAcmeAccount.id,
        )
        assert res.status_code == 200
        assert res.location is None  # no redirect
        assert "AcmeAccount" in res.json
        assert res.json["AcmeAccount"]["account_url"] == _account_url

        # Scenario E
        # alter the database, so db1 has db5s AcmeAccountKey and url
        (dbAcmeAccount5, acme_account_id5) = make_one__AcmeAccount__pem(
            self,
            account__contact="dbAcmeAccount5@example.com",
            pem_file_name="key_technology-rsa/AcmeAccountKey-4.pem",
        )

        assert dbAcmeAccount.id != dbAcmeAccount5.id
        dbAcmeAccount.acme_account_key.is_active = False
        dbAcmeAccount5.acme_account_key.acme_account_id = dbAcmeAccount.id
        self.ctx.dbSession.flush(objects=[dbAcmeAccount, dbAcmeAccount5])
        self.ctx.dbSession.commit()

        # authenticate should trigger this
        res = self.testapp.post(
            "/.well-known/peter_sslers/acme-account/%s/acme-server/authenticate.json"
            % dbAcmeAccount.id,
        )


class IntegratedTests_AcmeServer(AppTestWSGI):
    """
    This test suite runs against a Pebble instance, which will try to validate the domains.
    This tests serving and responding to validations.

    python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer
    """

    def tearDown(self):
        unset_testing_data(self)
        AppTestWSGI.tearDown(self)

    def _calculate_stats(self):
        stats = {}
        stats["count-Domain"] = self.ctx.dbSession.query(model_objects.Domain).count()
        stats["count-AcmeOrder"] = self.ctx.dbSession.query(
            model_objects.AcmeOrder
        ).count()
        stats["count-AcmeChallenge"] = self.ctx.dbSession.query(
            model_objects.AcmeChallenge
        ).count()
        stats["count-AcmeAuthorization"] = self.ctx.dbSession.query(
            model_objects.AcmeAuthorization
        ).count()
        stats["count-AcmeAuthorization-all"] = self.ctx.dbSession.query(
            model_objects.AcmeAuthorization
        ).count()
        stats["count-AcmeAuthorization-pending"] = (
            self.ctx.dbSession.query(model_objects.AcmeAuthorization)
            .filter(
                model_objects.AcmeAuthorization.acme_status_authorization_id.in_(
                    model_utils.Acme_Status_Authorization.IDS_POSSIBLY_PENDING
                )
            )
            .count()
        )
        stats["count-UniqueFQDNSet"] = self.ctx.dbSession.query(
            model_objects.UniqueFQDNSet
        ).count()
        return stats

    def _place_order(self, account_key_file_pem, account__contact, domain_names):
        resp = requests.get(
            "http://peter-sslers.example.com:5002/.well-known/peter_sslers/acme-order/new/freeform.json"
        )
        assert resp.status_code == 200
        assert "instructions" in resp.json()

        form: Dict
        files: Dict

        # we need an account!
        pem = self._filedata_testfile(account_key_file_pem)
        pem = cert_utils.cleanup_pem_text(pem)
        dbAcmeAccountKey = lib_db_get.get__AcmeAccountKey__by_key_pem(self.ctx, pem)
        if not dbAcmeAccountKey:
            # the original form accepted creating an account; sigh:

            # /.well-known/peter_sslers/acme-account/new
            # {acme_server_id}
            # {contact}
            # {private_key_technology}
            # {order_default_private_key_technology}
            # {order_default_private_key_cycling}

            # /.well-known/peter_sslers/acme-account/upload
            # {order_default_private_key_technology}
            # {order_default_private_key_cycling}
            # {acme_server_id}
            # {contact}
            # {account_key_file}

            resp = requests.get(
                "http://peter-sslers.example.com:5002/.well-known/peter_sslers/acme-account/upload.json"
            )
            assert resp.status_code == 200
            assert "instructions" in resp.json()

            form = {}
            files = {}

            try:
                form["account__order_default_private_key_cycle"] = "account_daily"
                form["account__order_default_private_key_technology"] = "RSA_2048"
                form["acme_server_id"] = "1"
                form["account__contact"] = account__contact
                files["account_key_file_pem"] = open(
                    self._filepath_testfile(account_key_file_pem),
                    "rb",
                )

                resp = requests.post(
                    "http://peter-sslers.example.com:5002/.well-known/peter_sslers/acme-account/upload.json",
                    data=form,
                    files=files,
                )
                assert resp.status_code == 200
            finally:
                for _field, _file in files.items():
                    _file.close()

            _json = resp.json()
            assert "AcmeAccount" in _json
            acme_account_id = _json["AcmeAccount"]["id"]
            assert "AcmeAccountKey" in _json["AcmeAccount"]
            acme_account_key_id = _json["AcmeAccount"]["AcmeAccountKey"]["id"]

            dbAcmeAccountKey = lib_db_get.get__AcmeAccountKey__by_key_pem(self.ctx, pem)
            assert dbAcmeAccountKey

            assert dbAcmeAccountKey.id == acme_account_key_id

        assert dbAcmeAccountKey
        form = {}
        form["account_key_option"] = "account_key_existing"
        form["account_key_existing"] = dbAcmeAccountKey.key_pem_md5
        form["private_key_option"] = "account_default"
        form["private_key_cycle"] = "account_default"
        form["domain_names_http01"] = ",".join(domain_names)
        form["processing_strategy"] = "process_single"
        resp = requests.post(
            "http://peter-sslers.example.com:5002/.well-known/peter_sslers/acme-order/new/freeform.json",
            data=form,
        )
        return resp

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble_strict
    def test_AcmeOrder_multiple_domains(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer.test_AcmeOrder_multiple_domains

        this test is not focused on routes, but a success
        """

        # don't re-use the domains, but use the core info
        _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]

        domain_names = [
            "test-AcmeOrder-multiple-domains-%s.example.com" % i for i in range(1, 20)
        ]

        resp = self._place_order(
            _test_data["acme-order/new/freeform#1"]["account_key_file_pem"],
            _test_data["acme-order/new/freeform#1"]["account__contact"],
            domain_names,
        )
        assert resp.status_code == 200
        assert resp.json()["result"] == "success"
        assert "AcmeOrder" in resp.json()
        obj_id = resp.json()["AcmeOrder"]["id"]
        assert resp.json()["AcmeOrder"]["certificate_url"] is not None
        assert resp.json()["AcmeOrder"]["acme_status_order"] == "valid"
        assert (
            resp.json()["AcmeOrder"]["acme_order_processing_status"]
            == "certificate_downloaded"
        )

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble_strict
    def test_AcmeOrder_cleanup(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer.test_AcmeOrder_cleanup

        this test is not focused on routes, but cleaning up an order
        """
        # ALL TESTS: self._pyramid_app
        # Functional Tests: self._testapp.app.registry.settings
        # Integrated Tests: self._testapp_wsgi.test_app.registry.settings
        # by default, this should be True
        assert (
            self._pyramid_app.registry.settings["application_settings"][
                "cleanup_pending_authorizations"
            ]
            is True
        )

        # don't re-use the domains, but use the core info
        _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]

        # our domains
        domain_names = [
            "test-AcmeOrder-cleanup-%s.example.com" % i for i in range(1, 20)
        ]

        # prepend domain to fail
        _fail_domain = "test-AcmeOrder-cleanup-fail.example.com"
        domain_names.insert(0, _fail_domain)

        stats_og = self._calculate_stats()
        resp = self._place_order(
            _test_data["acme-order/new/freeform#1"]["account_key_file_pem"],
            _test_data["acme-order/new/freeform#1"]["account__contact"],
            domain_names,
        )

        assert resp.status_code == 200
        assert resp.json()["result"] == "error"

        # somehow, this is now being returned:
        # "(400, {'type': 'urn:ietf:params:acme:error:malformed', 'detail': 'Cannot update challenge with status invalid, only status pending', 'status': 400})"

        assert resp.json()["error"] == "`pending` AcmeOrder failed an AcmeAuthorization"
        assert "AcmeOrder" in resp.json()
        obj_id = resp.json()["AcmeOrder"]["id"]

        # # test for resync bug
        # url = "http://peter-sslers.example.com:5002/.well-known/peter_sslers/acme-order/%s/acme-server/sync.json" % obj_id
        # rrr = requests.post(url)
        # pdb.set_trace()

        assert resp.json()["AcmeOrder"]["certificate_url"] is None
        assert resp.json()["AcmeOrder"]["acme_status_order"] == "invalid"
        assert (
            resp.json()["AcmeOrder"]["acme_order_processing_status"]
            == "processing_deactivated"
        )

        stats_a = self._calculate_stats()

        # compare backend stats
        assert stats_a["count-Domain"] == stats_og["count-Domain"] + 20
        assert stats_a["count-UniqueFQDNSet"] == stats_og["count-UniqueFQDNSet"] + 1
        assert stats_a["count-AcmeOrder"] == stats_og["count-AcmeOrder"] + 1
        assert (
            stats_a["count-AcmeAuthorization"]
            == stats_og["count-AcmeAuthorization"] + 20
        )
        assert (
            stats_a["count-AcmeAuthorization-pending"]
            == stats_og["count-AcmeAuthorization-pending"]
        )

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble_strict
    def test_AcmeOrder_nocleanup(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer.test_AcmeOrder_nocleanup

        this test is not focused on routes, but cleaning up an order

        must use pebble_strict so there are no reused auths
        """
        obj_id: Optional[int] = None
        try:
            # ALL TESTS: self._pyramid_app
            # Functional Tests: self._testapp.app.registry.settings
            # Integrated Tests: self._testapp_wsgi.test_app.registry.settings
            # by default, this should be True
            assert (
                self._pyramid_app.registry.settings["application_settings"][
                    "cleanup_pending_authorizations"
                ]
                is True
            )
            # now set this as False
            self._pyramid_app.registry.settings["application_settings"][
                "cleanup_pending_authorizations"
            ] = False

            # don't re-use the domains, but use the core info
            _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]

            # our domains
            domain_names = [
                "test-AcmeOrder-nocleanup-%s.example.com" % i for i in range(1, 20)
            ]

            # prepend domain to fail
            _fail_domain = "test-AcmeOrder-nocleanup-fail.example.com"
            domain_names.insert(0, _fail_domain)

            # 1 fail + 19 integer-based attempts
            # just here to raise an error if the above numbers fail,
            # as that will fail the rest of the tests
            assert len(domain_names) == 20
            _order_domains_len = 20

            stats_og = self._calculate_stats()
            resp = self._place_order(
                _test_data["acme-order/new/freeform#1"]["account_key_file_pem"],
                _test_data["acme-order/new/freeform#1"]["account__contact"],
                domain_names,
            )
            assert resp.status_code == 200
            assert resp.json()["result"] == "error"
            assert (
                resp.json()["error"]
                == "`pending` AcmeOrder failed an AcmeAuthorization"
            )
            assert "AcmeOrder" in resp.json()
            obj_id = resp.json()["AcmeOrder"]["id"]
            assert resp.json()["AcmeOrder"]["certificate_url"] is None
            assert resp.json()["AcmeOrder"]["acme_status_order"] == "invalid"
            assert (
                resp.json()["AcmeOrder"]["acme_order_processing_status"]
                == "processing_completed_failure"
            )

            stats_b = self._calculate_stats()

            # compare backend stats
            assert stats_b["count-AcmeOrder"] == stats_og["count-AcmeOrder"] + 1
            assert (
                stats_b["count-AcmeAuthorization"]
                == stats_og["count-AcmeAuthorization"] + _order_domains_len
            )
            assert (
                stats_b["count-Domain"] == stats_og["count-Domain"] + _order_domains_len
            )
            assert stats_b["count-UniqueFQDNSet"] == stats_og["count-UniqueFQDNSet"] + 1
            # this one is hard to figure out
            # because we could have failed on any of the 20 authorizations
            # start with 20 auths
            _expected_max = (
                stats_og["count-AcmeAuthorization-pending"] + _order_domains_len
            )
            # no need to assume one for the failed auth
            _expected_min = stats_og["count-AcmeAuthorization-pending"]

            def _debug_flaky(fatal=None):
                """
                this test sometimes doesn't work. it's a flaky test.
                this debugger is here to help debug it

                :param fatal: boolean. True if this was a fatal test error
                """
                _auths = []
                _auths_all = self.ctx.dbSession.query(
                    model_objects.AcmeAuthorization
                ).all()
                _domain_names = [i.lower() for i in domain_names]
                for i in _auths_all:
                    if i.domain and (i.domain.domain_name in _domain_names):
                        _auths.append(i)
                _auths = sorted(
                    _auths,
                    key=lambda auth: (
                        auth.acme_status_authorization_id,
                        auth.domain.domain_name,
                    ),
                )
                print("===================== AcmeAuthorization/")
                print("_expected_min:", _expected_min)
                print("_expected_max:", _expected_max)
                print(
                    "count-AcmeAuthorization-all:",
                    stats_b["count-AcmeAuthorization-all"],
                )
                print(
                    "count-AcmeAuthorization-pending:",
                    stats_b["count-AcmeAuthorization-pending"],
                )
                print("---------------------------------------------")
                print("acme_status_authorization_id, id, domain_name")
                for _auth in _auths:
                    print(
                        _auth.acme_status_authorization_id,
                        _auth.id,
                        _auth.domain.domain_name,
                    )
                print("---------------------------------------------")
                print("===================== /AcmeAuthorization")

            try:
                assert stats_b["count-AcmeAuthorization-pending"] <= _expected_max
                assert stats_b["count-AcmeAuthorization-pending"] >= _expected_min
            except:
                _debug_flaky(fatal=True)
                raise

            if stats_b["count-AcmeAuthorization-pending"] == _expected_min:
                # early tests reliably had this 1 higher
                # just debug this
                _debug_flaky(fatal=False)

        finally:
            # reset
            self._pyramid_app.registry.settings["application_settings"][
                "cleanup_pending_authorizations"
            ] = True

            if obj_id:
                dbAcmeOrder = self.ctx.dbSession.query(model_objects.AcmeOrder).get(
                    obj_id
                )
                assert dbAcmeOrder
                lib_db_actions_acme.do__AcmeV2_AcmeOrder__acme_server_deactivate_authorizations(
                    self.ctx,
                    dbAcmeOrder=dbAcmeOrder,
                )
                self.ctx.dbSession.commit()

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble_strict
    @routes_tested(("admin:api:domain:certificate-if-needed",))
    def test_domain_certificate_if_needed(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer.test_domain_certificate_if_needed
        """
        res = self.testapp.get(
            "/.well-known/peter_sslers/api/domain/certificate-if-needed", status=200
        )
        assert "instructions" in res.json
        assert "AcmeAccount_GlobalDefault" in res.json["valid_options"]
        key_pem_md5 = res.json["valid_options"]["AcmeAccount_GlobalDefault"][
            "AcmeAccountKey"
        ]["key_pem_md5"]

        res2 = self.testapp.post(
            "/.well-known/peter_sslers/api/domain/certificate-if-needed", {}, status=200
        )
        assert "instructions" not in res2.json
        assert res2.json["result"] == "error"

        # prep the form
        form = {}
        form["account_key_option"] = "account_key_global_default"
        form["account_key_global_default"] = key_pem_md5
        form["account__order_default_private_key_cycle"] = "account_daily"
        form["private_key_option"] = "account_default"
        form["private_key_cycle"] = "account_default"
        form["processing_strategy"] = "process_single"

        # Pass 1 - Generate a single domain
        _domain_name = "test-domain-certificate-if-needed-1.example.com"
        form["domain_name"] = _domain_name
        res3 = self.testapp.post(
            "/.well-known/peter_sslers/api/domain/certificate-if-needed", form
        )
        assert res3.status_code == 200
        assert res3.json["result"] == "success"
        assert "domain_results" in res3.json
        assert _domain_name in res3.json["domain_results"]
        assert (
            res3.json["domain_results"][_domain_name]["certificate_signed.status"]
            == "new"
        )
        assert res3.json["domain_results"][_domain_name]["domain.status"] == "new"
        assert res3.json["domain_results"][_domain_name]["acme_order.id"] is not None

        # Pass 2 - Try multiple domains
        _domain_names = (
            "test-domain-certificate-if-needed-1.example.com",
            "test-domain-certificate-if-needed-2.example.com",
        )
        form["domain_name"] = ",".join(_domain_names)
        res4 = self.testapp.post(
            "/.well-known/peter_sslers/api/domain/certificate-if-needed", form
        )
        assert res4.status_code == 200
        assert res4.json["result"] == "error"
        assert (
            res4.json["form_errors"]["domain_name"]
            == "This endpoint currently supports only 1 domain name"
        )

        # Pass 3 - Try a failure domain
        _domain_name = "fail-a-1.example.com"
        form["domain_name"] = _domain_name
        res5 = self.testapp.post(
            "/.well-known/peter_sslers/api/domain/certificate-if-needed", form
        )
        assert res5.status_code == 200
        assert res5.json["result"] == "success"
        assert (
            res5.json["domain_results"][_domain_name]["certificate_signed.status"]
            == "fail"
        )
        assert res5.json["domain_results"][_domain_name]["domain.status"] == "new"
        assert res5.json["domain_results"][_domain_name]["acme_order.id"] is not None
        assert (
            res5.json["domain_results"][_domain_name]["error"]
            == "Could not process AcmeOrder, `pending` AcmeOrder failed an AcmeAuthorization"
        )

        # Pass 4 - redo the first domain, again
        _domain_name = "test-domain-certificate-if-needed-1.example.com"
        form["domain_name"] = _domain_name
        res6 = self.testapp.post(
            "/.well-known/peter_sslers/api/domain/certificate-if-needed", form
        )
        assert res6.status_code == 200
        assert res6.json["result"] == "success"
        assert "domain_results" in res6.json
        assert _domain_name in res6.json["domain_results"]
        assert (
            res6.json["domain_results"][_domain_name]["certificate_signed.status"]
            == "exists"
        )
        assert res6.json["domain_results"][_domain_name]["domain.status"] == "existing"
        assert res6.json["domain_results"][_domain_name]["acme_order.id"] is None

        # Pass 5 - do it again
        # originally this disabled the domain, but now we just do a duplicate

        _domain_name = "test-domain-certificate-if-needed-1.example.com"
        form["domain_name"] = _domain_name
        res7 = self.testapp.post(
            "/.well-known/peter_sslers/api/domain/certificate-if-needed", form
        )
        assert res7.status_code == 200
        assert res7.json["result"] == "success"
        assert "domain_results" in res7.json
        assert _domain_name in res7.json["domain_results"]
        assert (
            res7.json["domain_results"][_domain_name]["certificate_signed.status"]
            == "exists"
        )
        assert res7.json["domain_results"][_domain_name]["domain.status"] == "existing"
        assert res7.json["domain_results"][_domain_name]["acme_order.id"] is None

    @unittest.skipUnless(RUN_REDIS_TESTS, "Not Running Against: redis")
    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @under_redis
    @routes_tested(
        (
            # "admin:api:redis:prime",
            "admin:api:redis:prime|json",
            "admin:api:domain:certificate-if-needed",  # used to prep
            "admin:api:update_recents|json",  # used to prep
        )
    )
    def test_redis(self):
        """
        python -munittest tests.test_pyramid_app.IntegratedTests_AcmeServer.test_redis
        """

        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        # NOTE: prep work, ensure we have a cert
        # prep the form
        res = self.testapp.get(
            "/.well-known/peter_sslers/api/domain/certificate-if-needed", status=200
        )
        assert "instructions" in res.json
        assert "AcmeAccount_GlobalDefault" in res.json["valid_options"]
        key_pem_md5 = res.json["valid_options"]["AcmeAccount_GlobalDefault"][
            "AcmeAccountKey"
        ]["key_pem_md5"]

        form = {}
        form["account_key_option"] = "account_key_global_default"
        form["account_key_global_default"] = key_pem_md5
        form["account__order_default_private_key_cycle"] = "account_daily"
        form["private_key_option"] = "account_default"
        form["private_key_cycle"] = "account_default"
        form["processing_strategy"] = "process_single"
        # Pass 1 - Generate a single domain
        _domain_name = "test-redis-1.example.com"
        form["domain_name"] = _domain_name
        res = self.testapp.post(
            "/.well-known/peter_sslers/api/domain/certificate-if-needed", form
        )
        assert res.status_code == 200
        assert res.json["result"] == "success"
        assert "domain_results" in res.json
        assert _domain_name in res.json["domain_results"]
        assert (
            res.json["domain_results"][_domain_name]["certificate_signed.status"]
            == "new"
        )
        assert res.json["domain_results"][_domain_name]["domain.status"] == "new"
        assert res.json["domain_results"][_domain_name]["acme_order.id"] is not None

        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        # NOTE: prep work, ensure we updated recents
        res = self.testapp.post(
            "/.well-known/peter_sslers/api/update-recents.json", {}, status=200
        )
        assert res.json["result"] == "success"

        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

        # okay, loop the prime styles
        _prime_styles = ("1", "2")
        _existing_prime_style = self.testapp.app.registry.settings[
            "application_settings"
        ]["redis.prime_style"]
        try:
            for _prime_style in _prime_styles:
                if _prime_style == _existing_prime_style:
                    continue
                self.testapp.app.registry.settings["application_settings"][
                    "redis.prime_style"
                ] = _prime_style

                res = self.testapp.post(
                    "/.well-known/peter_sslers/api/redis/prime.json", {}, status=200
                )
                assert res.json["result"] == "success"

        finally:
            # reset
            self.testapp.app.registry.settings["application_settings"][
                "redis.prime_style"
            ] = _existing_prime_style


class CoverageAssurance_AuditTests(AppTest):
    """
    python -m unittest tests.test_pyramid_app.CoverageAssurance_AuditTests
    """

    def test_audit_route_coverage(self):
        """
        This test is used to audit the pyramid app's registered routes for coverage
        against tests that are registered with the `@routes_tested` decorator
        """
        pyramid_route_names = [
            r
            for r in [i.name for i in self.testapp.app.routes_mapper.routelist]
            if r[:3] != "__."
        ]
        names_missing = [
            r for r in pyramid_route_names if r not in _ROUTES_TESTED.keys()
        ]
        if names_missing:
            raise ValueError(
                "no coverage for %s routes: %s" % (len(names_missing), names_missing)
            )
