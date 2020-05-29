from __future__ import print_function

# stdlib
import datetime
import json
import os
import pdb
import pprint
import re
import unittest
from functools import wraps

# pypi
from webtest import Upload
from webtest.http import StopableWSGIServer
import requests

# local
from ._utils import FakeRequest
from ._utils import TEST_FILES
from ._utils import AppTest
from ._utils import AppTestWSGI
from ._utils import under_pebble
from ._utils import under_pebble_strict
from ._utils import under_redis

from ..lib.db import get as lib_db_get
from ..model import objects as model_objects
from ..model import utils as model_utils

# local, flags
from ._utils import LETSENCRYPT_API_VALIDATES
from ._utils import RUN_API_TESTS__PEBBLE
from ._utils import RUN_NGINX_TESTS
from ._utils import RUN_REDIS_TESTS
from ._utils import SSL_TEST_PORT


# ==============================================================================


_ROUTES_TESTED = {}


def tests_routes(*args):
    """
    `@tests_routes` is a decorator
    when writing/editing a test, declare what routes the test covers, like such:

        @tests_routes(("foo", "bar"))
        def test_foo_bar(self):
            ...

    this will populate a global variable `_ROUTES_TESTED` with the name of the
    tested routes.

    invoking the Audit test:

        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AuditRoutes

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

RE_AcmeAccount_deactivate_pending_post_required = re.compile(
    r"""http://peter-sslers\.example\.com/\.well-known/admin/acme-account/(\d+)/acme-authorizations\?status=active&result=error&error=post\+required&operation=acme-server--deactivate-pending-authorizations"""
)
RE_AcmeAccount_deactivate_pending_success = re.compile(
    r"""http://peter-sslers\.example\.com/\.well-known/admin/acme-account/(\d+)/acme-authorizations\?status=active&result=success&operation=acme-server--deactivate-pending-authorizations"""
)


RE_AcmeAuthorization_sync_btn = re.compile(
    r'''href="/\.well-known/admin/acme-authorization/(\d+)/acme-server/sync"[\n\s\ ]+class="btn btn-xs btn-info "'''
)
RE_AcmeAuthorization_deactivate_btn = re.compile(
    r'''href="/\.well-known/admin/acme-authorization/(\d+)/acme-server/deactivate"[\n\s\ ]+class="btn btn-xs btn-info "'''
)
RE_AcmeAuthorization_trigger_btn = re.compile(
    r'''href="/\.well-known/admin/acme-authorization/(\d+)/acme-server/trigger"[\n\s\ ]+class="btn btn-xs btn-info "'''
)

RE_AcmeAuthorization_deactivated = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/admin/acme-authorization/\d+\?result=success&operation=acme\+server\+deactivate"""
)
RE_AcmeAuthorization_deactivate_fail = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/admin/acme-authorization/\d+\?result=error&error=ACME\+Server\+Sync\+is\+not\+allowed\+for\+this\+AcmeAuthorization&operation=acme\+server\+deactivate"""
)

RE_AcmeAuthorization_triggered = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/admin/acme-authorization/\d+\?result=success&operation=acme\+server\+trigger"""
)

RE_AcmeAuthorization_synced = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/admin/acme-authorization/\d+\?result=success&operation=acme\+server\+sync"""
)


RE_AcmeChallenge_sync_btn = re.compile(
    r'''href="/\.well-known/admin/acme-challenge/(\d+)/acme-server/sync"[\n\s\ ]+class="btn btn-xs btn-info"'''
)
RE_AcmeChallenge_trigger_btn = re.compile(
    r'''href="/\.well-known/admin/acme-challenge/(\d+)/acme-server/trigger"[\n\s\ ]+class="btn btn-xs btn-info "'''
)
RE_AcmeChallenge_triggered = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/admin/acme-challenge/\d+\?result=success&operation=acme\+server\+trigger"""
)
RE_AcmeChallenge_synced = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/admin/acme-challenge/\d+\?result=success&operation=acme\+server\+sync"""
)
RE_AcmeChallenge_trigger_fail = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/admin/acme-challenge/\d+\?result=error&error=ACME\+Server\+Trigger\+is\+not\+allowed\+for\+this\+AcmeChallenge&operation=acme\+server\+trigger"""
)


RE_AcmeOrder = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/admin/acme-order/(\d+)$"""
)
RE_AcmeOrder_retry = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/admin/acme-order/(\d+)\?result=success&operation=retry\+order$"""
)
RE_AcmeOrder_deactivated = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/admin/acme-order/(\d+)\?result=success&operation=mark&action=deactivate$"""
)
RE_AcmeOrder_invalidated = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/admin/acme-order/(\d+)\?result=success&operation=mark&action=invalid$"""
)
RE_AcmeOrder_processed = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/admin/acme-order/(\d+)\?result=success&operation=acme\+process$"""
)
RE_AcmeOrder_can_process = re.compile(
    r'''href="/\.well-known/admin/acme-order/\d+/acme-process"[\n\s\ ]+class="btn btn-xs btn-info "'''
)
RE_AcmeOrder_downloaded_certificate = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/admin/acme-order/(\d+)\?result=success&operation=acme\+server\+download\+certificate$"""
)
RE_AcmeOrderless = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/admin/acme-orderless/(\d+)$"""
)

RE_QueueDomain_process_success = re.compile(
    """^http://peter-sslers\.example\.com/\.well-known/admin/queue-domains\?result=success&operation=processed&acme-order-id=(\d+)"""
)

RE_QueueCertificate = re.compile(
    """^http://peter-sslers\.example\.com/\.well-known/admin/queue-certificate/(\d+)$"""
)

RE_server_certificate_link = re.compile(
    r"""href="/\.well-known/admin/server-certificate/(\d+)"""
)


# =====


class FunctionalTests_Passes(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_Passes
    this is only used to test setup
    """

    def test_passes(self):
        return True


class FunctionalTests_Main(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_Main
    """

    @tests_routes("admin")
    def test_root(self):
        res = self.testapp.get("/.well-known/admin", status=200)

    @tests_routes("admin:whoami")
    def test_admin_whoami(self):
        res = self.testapp.get("/.well-known/admin/whoami", status=200)

    @tests_routes("admin:help")
    def test_help(self):
        res = self.testapp.get("/.well-known/admin/help", status=200)

    @tests_routes("admin:settings")
    def test_settings(self):
        res = self.testapp.get("/.well-known/admin/settings", status=200)

    @tests_routes("admin:api")
    def test_api_docs(self):
        res = self.testapp.get("/.well-known/admin/api", status=200)

    @tests_routes("admin:search")
    def test_search(self):
        res = self.testapp.get("/.well-known/admin/search", status=200)

    @tests_routes("public_whoami")
    def test_public_whoami(self):
        res = self.testapp.get("/.well-known/public/whoami", status=200)


class FunctionalTests_AcmeAccount(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeAccount
    """

    def _get_one(self):
        # grab a Key
        focus_item = (
            self.ctx.dbSession.query(model_objects.AcmeAccount)
            .filter(model_objects.AcmeAccount.is_active.op("IS")(True))
            .filter(model_objects.AcmeAccount.is_global_default.op("IS NOT")(True))
            .order_by(model_objects.AcmeAccount.id.asc())
            .first()
        )
        return focus_item

    @tests_routes("admin:acme_account:upload")
    def test_upload_html(self):
        """
        formecode must be patched for this:
            https://github.com/formencode/formencode/issues/101
            https://github.com/valos/formencode/commit/987d29922b2a37eb969fb40658a1057bacbe1129
        """
        # this should be creating a new key
        _key_filename = TEST_FILES["AcmeAccount"]["2"]["key"]
        _private_key_cycle = TEST_FILES["AcmeAccount"]["2"]["private_key_cycle"]
        key_filepath = self._filepath_testfile(_key_filename)

        res = self.testapp.get("/.well-known/admin/acme-account/upload", status=200)
        form = res.form
        form["account__contact"] = TEST_FILES["AcmeAccount"]["2"]["contact"]
        form["account_key_file_pem"] = Upload(key_filepath)
        form["acme_account_provider_id"].force_value(
            str(1)
        )  # acme_account_provider_id(1) == pebble
        res2 = form.submit()
        assert res2.status_code == 303
        assert res2.location.startswith(
            """http://peter-sslers.example.com/.well-known/admin/acme-account/"""
        )
        assert res2.location.endswith(
            """?result=success&operation=upload&is_created=1"""
        ) or res2.location.endswith(
            """?result=success&operation=upload&is_existing=1"""
        )
        res3 = self.testapp.get(res2.location, status=200)

    @tests_routes("admin:acme_account:upload|json")
    def test_upload_json(self):
        _key_filename = TEST_FILES["AcmeAccount"]["2"]["key"]
        _private_key_cycle = TEST_FILES["AcmeAccount"]["2"]["private_key_cycle"]
        key_filepath = self._filepath_testfile(_key_filename)

        res = self.testapp.get(
            "/.well-known/admin/acme-account/upload.json", status=200
        )
        assert "instructions" in res.json

        form = {}
        form["account__contact"] = TEST_FILES["AcmeAccount"]["2"]["contact"]
        form["account_key_file_pem"] = Upload(key_filepath)
        form["acme_account_provider_id"] = "1"  # acme_account_provider_id(1) == pebble
        res2 = self.testapp.post("/.well-known/admin/acme-account/upload.json", form)
        assert res2.status_code == 200
        assert "result" in res2.json
        assert res2.json["result"] == "error"
        assert "form_errors" in res2.json
        assert isinstance(res2.json["form_errors"], dict)
        assert len(res2.json["form_errors"].keys()) == 2
        assert (
            res2.json["form_errors"]["Error_Main"]
            == "There was an error with your form."
        )
        assert res2.json["form_errors"]["account__private_key_cycle"] == "Missing value"

        form = {}
        form["account_key_file_pem"] = Upload(key_filepath)
        form["acme_account_provider_id"] = "1"  # acme_account_provider_id(1) == pebble
        form["account__contact"] = TEST_FILES["AcmeAccount"]["2"]["contact"]
        form["account__private_key_cycle"] = TEST_FILES["AcmeAccount"]["2"][
            "private_key_cycle"
        ]
        res3 = self.testapp.post("/.well-known/admin/acme-account/upload.json", form)
        assert res3.status_code == 200
        res3_json = json.loads(res3.text)
        assert "result" in res3_json
        assert res3_json["result"] == "success"

    @tests_routes(("admin:acme_accounts", "admin:acme_accounts_paginated"))
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/acme-accounts", status=200)
        # paginated
        res = self.testapp.get("/.well-known/admin/acme-accounts/1", status=200)

    @tests_routes(("admin:acme_accounts|json", "admin:acme_accounts_paginated|json"))
    def test_list_json(self):
        # json root
        res = self.testapp.get("/.well-known/admin/acme-accounts.json", status=200)
        assert "AcmeAccounts" in res.json

        # json paginated
        res = self.testapp.get("/.well-known/admin/acme-accounts/1.json", status=200)
        assert "AcmeAccounts" in res.json

    @tests_routes(
        (
            "admin:acme_account:focus",
            "admin:acme_account:focus:acme_authorizations",
            "admin:acme_account:focus:acme_authorizations_paginated",
            "admin:acme_account:focus:acme_orders",
            "admin:acme_account:focus:acme_orders_paginated",
            "admin:acme_account:focus:private_keys",
            "admin:acme_account:focus:private_keys_paginated",
            "admin:acme_account:focus:server_certificates",
            "admin:acme_account:focus:server_certificates_paginated",
            "admin:acme_account:focus:queue_certificates",
            "admin:acme_account:focus:queue_certificates_paginated",
        )
    )
    def test_focus_html(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/acme-authorizations" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/acme-authorizations/1" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/acme-orders" % focus_id, status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/acme-orders/1" % focus_id, status=200,
        )

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/private-keys" % focus_id, status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/private-keys/1" % focus_id, status=200,
        )

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/server-certificates" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/server-certificates/1" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/queue-certificates" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/queue-certificates/1" % focus_id,
            status=200,
        )

    @tests_routes(
        (
            "admin:acme_account:focus|json",
            "admin:acme_account:focus:config|json",
            "admin:acme_account:focus:parse|json",
            "admin:acme_account:focus:acme_authorizations|json",
            "admin:acme_account:focus:acme_authorizations_paginated|json",
        )
    )
    def test_focus_json(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s.json" % focus_id, status=200
        )
        assert "AcmeAccount" in res.json

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/config.json" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/parse.json" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/acme-authorizations.json" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/acme-authorizations/1.json" % focus_id,
            status=200,
        )

    @tests_routes("admin:acme_account:focus:raw")
    def test_focus_raw(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/key.key" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/key.pem" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/key.pem.txt" % focus_id, status=200
        )

    @tests_routes(("admin:acme_account:focus:edit", "admin:acme_account:focus:mark"))
    def test_manipulate_html(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/mark" % focus_id, status=303,
        )
        assert res.location.endswith("?result=error&error=post+required&operation=mark")

        if focus_item.is_global_default:
            raise ValueError("this should not be the global default")

        if not focus_item.is_active:
            raise ValueError("this should be active")

        # fail making this active
        res = self.testapp.post(
            "/.well-known/admin/acme-account/%s/mark" % focus_id, {"action": "active"},
        )
        assert res.status_code == 303
        assert res.location.endswith(
            "?result=error&error=Error_Main--There+was+an+error+with+your+form.+Already+activated.&operation=mark&action=active"
        )

        # inactive ROUNDTRIP
        res = self.testapp.post(
            "/.well-known/admin/acme-account/%s/mark" % focus_id,
            {"action": "inactive"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=inactive")

        res = self.testapp.post(
            "/.well-known/admin/acme-account/%s/mark" % focus_id, {"action": "active"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=active")

        res = self.testapp.post(
            "/.well-known/admin/acme-account/%s/mark" % focus_id,
            {"action": "global_default"},
        )
        assert res.status_code == 303
        assert res.location.endswith(
            "?result=success&operation=mark&action=global_default"
        )

        # edit it
        # only the private_key_cycle
        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/edit" % focus_id, status=200
        )
        form = res.form
        _existing = form["account__private_key_cycle"].value
        _new = None
        if _existing == "single_certificate":
            _new = "account_daily"
        else:
            _new = "single_certificate"
        form["account__private_key_cycle"] = _new
        res2 = form.submit()
        assert res2.status_code == 303
        assert (
            res2.location
            == """http://peter-sslers.example.com/.well-known/admin/acme-account/%s?result=success&operation=edit"""
            % focus_id
        )
        res3 = self.testapp.get(res2.location, status=200)

    @tests_routes(
        ("admin:acme_account:focus:edit|json", "admin:acme_account:focus:mark|json",)
    )
    def test_manipulate_json(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/mark.json" % focus_id, status=200,
        )
        assert "form_fields" in res.json
        assert "instructions" in res.json

        if focus_item.is_global_default:
            raise ValueError("this should not be the global default")

        if not focus_item.is_active:
            raise ValueError("this should be active")

        # fail making this active
        res = self.testapp.post(
            "/.well-known/admin/acme-account/%s/mark.json" % focus_id,
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
            "/.well-known/admin/acme-account/%s/mark.json" % focus_id,
            {"action": "inactive"},
        )
        assert res.status_code == 200
        assert "AcmeAccount" in res.json
        assert res.json["AcmeAccount"]["is_active"] is False

        res = self.testapp.post(
            "/.well-known/admin/acme-account/%s/mark.json" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 200
        assert "AcmeAccount" in res.json
        assert res.json["AcmeAccount"]["is_active"] is True

        # then global_default
        res = self.testapp.post(
            "/.well-known/admin/acme-account/%s/mark.json" % focus_id,
            {"action": "global_default"},
        )
        assert res.status_code == 200
        assert "AcmeAccount" in res.json
        assert res.json["AcmeAccount"]["is_global_default"] is True

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/edit.json" % focus_id, status=200
        )
        assert "form_fields" in res.json

        form = {}
        res2 = self.testapp.post(
            "/.well-known/admin/acme-account/%s/edit.json" % focus_id, form
        )
        assert res2.json["result"] == "error"
        assert "form_errors" in res2.json
        assert isinstance(res2.json["form_errors"], dict)
        assert len(res2.json["form_errors"]) == 1
        assert res2.json["form_errors"]["Error_Main"] == "Nothing submitted."

        _existing = focus_item.private_key_cycle
        _new = None
        if _existing == "single_certificate":
            _new = "account_daily"
        else:
            _new = "single_certificate"
        form = {"account__private_key_cycle": _new}
        res3 = self.testapp.post(
            "/.well-known/admin/acme-account/%s/edit.json" % focus_id, form
        )
        assert res3.json["result"] == "success"
        assert "AcmeAccount" in res3.json


class FunctionalTests_AcmeAuthorizations(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeAuthorizations
    """

    def _get_one(self):
        # grab an order
        focus_item = (
            self.ctx.dbSession.query(model_objects.AcmeAuthorization)
            .order_by(model_objects.AcmeAuthorization.id.asc())
            .first()
        )
        return focus_item

    @tests_routes(("admin:acme_authorizations", "admin:acme_authorizations_paginated"))
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/acme-authorizations", status=200)
        # paginated
        res = self.testapp.get("/.well-known/admin/acme-authorizations/1", status=200)

    @tests_routes(
        ("admin:acme_authorizations|json", "admin:acme_authorizations_paginated|json")
    )
    def test_list_json(self):
        # json root
        res = self.testapp.get(
            "/.well-known/admin/acme-authorizations.json", status=200
        )
        assert "AcmeAuthorizations" in res.json
        # json paginated
        res = self.testapp.get(
            "/.well-known/admin/acme-authorizations/1.json", status=200
        )
        assert "AcmeAuthorizations" in res.json

    @tests_routes(
        (
            "admin:acme_authorization:focus",
            "admin:acme_authorization:focus:acme_orders",
            "admin:acme_authorization:focus:acme_orders_paginated",
            "admin:acme_authorization:focus:acme_challenges",
            "admin:acme_authorization:focus:acme_challenges_paginated",
        )
    )
    def test_focus_html(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-orders" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-orders/1" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-challenges" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-challenges/1" % focus_id,
            status=200,
        )

    @tests_routes("admin:acme_authorization:focus|json")
    def test_focus_json(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s.json" % focus_id, status=200
        )
        assert "AcmeAuthorization" in res.json


class FunctionalTests_AcmeChallenges(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeChallenges
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
        return focus_item

    @tests_routes(("admin:acme_challenges", "admin:acme_challenges_paginated"))
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/acme-challenges", status=200)
        res = self.testapp.get(
            "/.well-known/admin/acme-challenges?status=active", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-challenges?status=resolved", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-challenges?status=processing", status=200
        )
        # paginated
        res = self.testapp.get("/.well-known/admin/acme-challenges/1", status=200)
        res = self.testapp.get(
            "/.well-known/admin/acme-challenges/1?status=active", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-challenges/1?status=resolved", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-challenges/1?status=processing", status=200
        )

    @tests_routes(
        ("admin:acme_challenges|json", "admin:acme_challenges_paginated|json")
    )
    def test_list_json(self):
        # json root
        res = self.testapp.get("/.well-known/admin/acme-challenges.json", status=200)
        assert "AcmeChallenges" in res.json
        res = self.testapp.get(
            "/.well-known/admin/acme-challenges.json?status=active", status=200
        )
        assert "AcmeChallenges" in res.json
        res = self.testapp.get(
            "/.well-known/admin/acme-challenges.json?status=resolved", status=200
        )
        assert "AcmeChallenges" in res.json
        res = self.testapp.get(
            "/.well-known/admin/acme-challenges.json?status=processing", status=200
        )
        assert "AcmeChallenges" in res.json

        # json paginated
        res = self.testapp.get("/.well-known/admin/acme-challenges/1.json", status=200)
        assert "AcmeChallenges" in res.json
        res = self.testapp.get(
            "/.well-known/admin/acme-challenges/1.json?status=active", status=200
        )
        assert "AcmeChallenges" in res.json
        res = self.testapp.get(
            "/.well-known/admin/acme-challenges/1.json?status=resolved", status=200
        )
        assert "AcmeChallenges" in res.json
        res = self.testapp.get(
            "/.well-known/admin/acme-challenges/1.json?status=processing", status=200
        )
        assert "AcmeChallenges" in res.json

    @tests_routes(("admin:acme_challenge:focus"))
    def test_focus_html(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-challenge/%s" % focus_id, status=200
        )

    @tests_routes(("public_challenge"))
    def test_public_challenge(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id
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

    @tests_routes(("admin:acme_challenge:focus|json"))
    def test_focus_json(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-challenge/%s.json" % focus_id, status=200
        )
        assert "AcmeChallenge" in res.json


class FunctionalTests_AcmeChallengePolls(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeChallengePolls
    """

    @tests_routes(
        ("admin:acme_challenge_polls", "admin:acme_challenge_polls_paginated")
    )
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/acme-challenge-polls", status=200)
        # paginated
        res = self.testapp.get("/.well-known/admin/acme-challenge-polls/1", status=200)

    @tests_routes(
        ("admin:acme_challenge_polls|json", "admin:acme_challenge_polls_paginated|json")
    )
    def test_list_json(self):
        # json paginated
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge-polls/1.json", status=200
        )
        assert "AcmeChallengePolls" in res.json

        # json paginated
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge-polls/1.json", status=200
        )
        assert "AcmeChallengePolls" in res.json
        assert "pagination" in res.json
        assert res.json["pagination"]["total_items"] >= 1


class FunctionalTests_AcmeChallengeUnknownPolls(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeChallengeUnknownPolls
    """

    @tests_routes(
        (
            "admin:acme_challenge_unknown_polls",
            "admin:acme_challenge_unknown_polls_paginated",
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge-unknown-polls", status=200
        )
        # paginated
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge-unknown-polls/1", status=200
        )

    @tests_routes(
        (
            "admin:acme_challenge_unknown_polls|json",
            "admin:acme_challenge_unknown_polls_paginated|json",
        )
    )
    def test_list_json(self):
        # json paginated
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge-unknown-polls/1.json", status=200
        )
        assert "AcmeChallengeUnknownPolls" in res.json

        # json paginated
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge-unknown-polls/1.json", status=200
        )
        assert "AcmeChallengeUnknownPolls" in res.json
        assert "pagination" in res.json
        assert res.json["pagination"]["total_items"] >= 1


class FunctionalTests_AcmeEventLog(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeEventLog
    """

    def _get_one(self):
        # grab an event
        focus_item = self.ctx.dbSession.query(model_objects.AcmeEventLog).first()
        return focus_item

    @tests_routes(("admin:acme_event_log", "admin:acme_event_log_paginated"))
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/acme-event-logs", status=200)
        # paginated
        res = self.testapp.get("/.well-known/admin/acme-event-logs/1", status=200)

    @tests_routes(("admin:acme_event_log|json", "admin:acme_event_log_paginated|json"))
    def test_list_json(self):
        # json root
        res = self.testapp.get("/.well-known/admin/acme-event-logs.json", status=200)
        assert "AcmeEventLogs" in res.json
        # json paginated
        res = self.testapp.get("/.well-known/admin/acme-event-logs/1.json", status=200)
        assert "AcmeEventLogs" in res.json

    @tests_routes(("admin:acme_event_log:focus"))
    def test_focus_html(self):
        """
        AcmeEventLog entries are normally only created when hitting the ACME Server
        BUT
        We faked one when creating a new AcmeOrder in the setup routine
        """
        # focus
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-event-log/%s" % focus_id, status=200
        )

    @tests_routes(("admin:acme_event_log:focus|json"))
    def test_focus_json(self):
        """
        AcmeEventLog entries are normally only created when hitting the ACME Server
        BUT
        We faked one when creating a new AcmeOrder in the setup routine
        """
        # focus
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-event-log/%s.json" % focus_id, status=200
        )
        assert "AcmeEventLog" in res.json


class FunctionalTests_AcmeOrder(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeOrder
    """

    def _get_one(self):
        # grab an order
        focus_item = (
            self.ctx.dbSession.query(model_objects.AcmeOrder)
            .order_by(model_objects.AcmeOrder.id.asc())
            .first()
        )
        return focus_item

    @tests_routes(("admin:acme_orders", "admin:acme_orders_paginated",))
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/acme-orders", status=200)
        res = self.testapp.get("/.well-known/admin/acme-orders/1", status=200)

    @tests_routes(("admin:acme_orders|json", "admin:acme_orders_paginated|json",))
    def test_list_json(self):
        # json root
        res = self.testapp.get("/.well-known/admin/acme-orders.json", status=200)
        assert "AcmeOrders" in res.json

        res = self.testapp.get("/.well-known/admin/acme-orders/1.json", status=200)
        assert "AcmeOrders" in res.json

    @tests_routes(
        (
            "admin:acme_order:focus",
            "admin:acme_order:focus:acme_event_logs",
            "admin:acme_order:focus:acme_event_logs_paginated",
            "admin:acme_order:focus:audit",
        )
    )
    def test_focus_html(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-event-logs" % focus_id, status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-event-logs/1" % focus_id, status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/audit" % focus_id, status=200
        )

    @tests_routes(("admin:acme_order:focus|json", "admin:acme_order:focus:audit|json"))
    def test_focus_json(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % focus_id, status=200
        )
        assert "AcmeOrder" in res.json

        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/audit.json" % focus_id, status=200
        )
        assert "AuditReport" in res.json
        assert "AcmeOrder" in res.json["AuditReport"]
        assert "AcmeAccount" in res.json["AuditReport"]
        assert "AcmeAccountProvider" in res.json["AuditReport"]
        assert "PrivateKey" in res.json["AuditReport"]
        assert "UniqueFQDNSet" in res.json["AuditReport"]
        assert "AcmeAuthorizations" in res.json["AuditReport"]


class FunctionalTests_AcmeOrderless(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeOrderless
    """

    def _get_one(self):
        # grab an order
        focus_item = (
            self.ctx.dbSession.query(model_objects.AcmeOrderless)
            .order_by(model_objects.AcmeOrderless.id.asc())
            .first()
        )
        return focus_item

    @tests_routes(("admin:acme_orderlesss", "admin:acme_orderlesss_paginated",))
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/acme-orderlesss", status=200)
        res = self.testapp.get("/.well-known/admin/acme-orderlesss/1", status=200)

    @tests_routes(
        ("admin:acme_orderlesss|json", "admin:acme_orderlesss_paginated|json",)
    )
    def test_list_json(self):
        # json root
        res = self.testapp.get("/.well-known/admin/acme-orderlesss.json", status=200)
        assert "AcmeOrderless" in res.json
        res = self.testapp.get("/.well-known/admin/acme-orderlesss/1.json", status=200)
        assert "AcmeOrderless" in res.json

    @tests_routes(("admin:acme_orderless:focus",))
    def test_focus_html(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id
        challenge_id = focus_item.acme_challenges[0].id

        res = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s/acme-challenge/%s"
            % (focus_id, challenge_id),
            status=200,
        )

    @tests_routes(("admin:acme_orderless:focus|json",))
    def test_focus_json(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id
        challenge_id = focus_item.acme_challenges[0].id

        res = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s.json" % focus_id, status=200
        )
        assert "AcmeOrderless" in res.json

        res = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s/acme-challenge/%s.json"
            % (focus_id, challenge_id),
            status=200,
        )
        assert "AcmeOrderless" in res.json
        assert "AcmeChallenge" in res.json

    @tests_routes(
        (
            "admin:acme_orderless:new",
            "admin:acme_orderless:focus",
            "admin:acme_orderless:focus:add",
            "admin:acme_orderless:focus:update",
            "admin:acme_orderless:focus:deactivate",
            "admin:acme_orderless:focus:acme_challenge",
        )
    )
    def test_new_html(self):
        # TODO - test with acmeaccountkey and challenge url

        res = self.testapp.get("/.well-known/admin/acme-orderless/new", status=200)
        form = res.form
        form["domain_names"] = ",".join(TEST_FILES["AcmeOrderless"]["new-1"]["domains"])
        res2 = form.submit()
        assert res2.status_code == 303

        matched = RE_AcmeOrderless.match(res2.location)
        assert matched
        obj_id = matched.groups()[0]

        # build a new form and submit edits
        res3 = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s" % obj_id, status=200,
        )
        form = res3.forms["acmeorderless-update"]
        update_fields = dict(form.submit_fields())
        _challenge_ids = update_fields["_challenges"].split(",")
        assert len(_challenge_ids) == len(
            TEST_FILES["AcmeOrderless"]["new-1"]["domains"]
        )
        for _id in _challenge_ids:
            _field_token = "%s_token" % _id
            assert _field_token in update_fields
            assert update_fields[_field_token] == ""
            form[_field_token] = "token_%s" % _id

            _field_keyauthorization = "%s_keyauthorization" % _id
            assert _field_keyauthorization in update_fields
            assert update_fields[_field_keyauthorization] == ""
            form[_field_keyauthorization] = "keyauthorization_%s" % _id

        res4 = form.submit()
        assert res4.status_code == 303
        assert (
            res4.location
            == "http://peter-sslers.example.com/.well-known/admin/acme-orderless/%s?result=success"
            % obj_id
        )
        res5 = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s?result=success" % obj_id, status=200,
        )

        # build a new form to assert the previous edits worked
        form = res5.forms["acmeorderless-update"]
        update_fields = dict(form.submit_fields())
        _challenge_ids = update_fields["_challenges"].split(",")
        assert len(_challenge_ids) == len(
            TEST_FILES["AcmeOrderless"]["new-1"]["domains"]
        )
        for _id in _challenge_ids:
            _field_token = "%s_token" % _id
            assert _field_token in update_fields
            assert update_fields[_field_token] == "token_%s" % _id
            _field_keyauthorization = "%s_keyauthorization" % _id
            assert _field_keyauthorization in update_fields
            assert update_fields[_field_keyauthorization] == "keyauthorization_%s" % _id

        # try adding a challenge
        form = res5.forms["acmeorderless-add_challenge"]
        add_fields = dict(form.submit_fields())
        assert "keyauthorization" in add_fields
        assert "domain" in add_fields
        assert "token" in add_fields
        form["keyauthorization"] = "keyauthorization_add"
        form["domain"] = "domain_add.example.com"
        form["token"] = "token_add"

        res6 = form.submit()
        assert res6.status_code == 303
        assert (
            res6.location
            == "http://peter-sslers.example.com/.well-known/admin/acme-orderless/%s?result=success"
            % obj_id
        )
        res7 = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s?status=success" % obj_id, status=200,
        )

        form = res7.forms["acmeorderless-update"]
        update_fields = dict(form.submit_fields())
        _challenge_ids = update_fields["_challenges"].split(",")
        # we just added 1
        assert len(_challenge_ids) == (
            len(TEST_FILES["AcmeOrderless"]["new-1"]["domains"]) + 1
        )

        form = res7.forms["acmeorderless-deactivate"]
        res8 = form.submit()
        assert res8.status_code == 303
        assert (
            res8.location
            == "http://peter-sslers.example.com/.well-known/admin/acme-orderless/%s?result=success"
            % obj_id
        )

        res9 = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s?result=success" % obj_id, status=200,
        )
        assert not res9.forms

        res10 = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s/acme-challenge/%s"
            % (obj_id, _challenge_ids[0]),
            status=200,
        )

    @tests_routes(
        (
            "admin:acme_orderless:new|json",
            "admin:acme_orderless:focus|json",
            "admin:acme_orderless:focus:add|json",
            "admin:acme_orderless:focus:update|json",
            "admin:acme_orderless:focus:deactivate|json",
            "admin:acme_orderless:focus:acme_challenge|json",
        )
    )
    def test_new_json(self):
        # TODO - test with acmeaccountkey and challenge url

        res = self.testapp.get("/.well-known/admin/acme-orderless/new.json", status=200)
        assert "form_fields" in res.json

        form = {}
        form["domain_names"] = ",".join(TEST_FILES["AcmeOrderless"]["new-1"]["domains"])
        res2 = self.testapp.post("/.well-known/admin/acme-orderless/new.json", form)
        assert res2.status_code == 200
        assert res2.json["result"] == "error"
        assert "form_errors" in res2.json
        assert "account_key_option" in res2.json["form_errors"]
        assert res2.json["form_errors"]["account_key_option"] == "Missing value"

        form["account_key_option"] = "none"
        res2b = self.testapp.post("/.well-known/admin/acme-orderless/new.json", form)
        assert res2b.status_code == 200
        assert res2b.json["result"] == "success"
        assert "AcmeOrderless" in res2b.json

        obj_id = res2b.json["AcmeOrderless"]["id"]

        res3 = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s.json" % obj_id, status=200,
        )
        assert "AcmeOrderless" in res3.json
        assert "forms" in res3.json
        assert "acmeorderless-update" in res3.json["forms"]

        # build a new form and submit edits
        form = res3.json["forms"]["acmeorderless-update"]
        update_fields = dict(form.items())
        _challenge_ids = update_fields["_challenges"].split(",")
        assert len(_challenge_ids) == len(
            TEST_FILES["AcmeOrderless"]["new-1"]["domains"]
        )
        for _id in _challenge_ids:
            _field_token = "%s_token" % _id
            assert _field_token in update_fields
            assert update_fields[_field_token] == ""
            update_fields[_field_token] = "token_%s" % _id

            _field_keyauthorization = "%s_keyauthorization" % _id
            assert _field_keyauthorization in update_fields
            assert update_fields[_field_keyauthorization] == ""
            update_fields[_field_keyauthorization] = "keyauthorization_%s" % _id
        res4 = self.testapp.post(
            "/.well-known/admin/acme-orderless/%s/update.json" % obj_id, update_fields
        )
        assert res4.status_code == 200
        assert "AcmeOrderless" in res4.json
        assert res4.json["changed"] is True

        # build a new form to assert the previous edits worked
        res3 = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s.json" % obj_id, status=200,
        )
        assert "AcmeOrderless" in res3.json
        assert "forms" in res3.json
        assert "acmeorderless-update" in res3.json["forms"]
        form = res3.json["forms"]["acmeorderless-update"]
        update_fields = dict(form.items())
        _challenge_ids = update_fields["_challenges"].split(",")
        assert len(_challenge_ids) == len(
            TEST_FILES["AcmeOrderless"]["new-1"]["domains"]
        )
        for _id in _challenge_ids:
            _field_token = "%s_token" % _id
            assert _field_token in update_fields
            assert form[_field_token] == "token_%s" % _id
            _field_keyauthorization = "%s_keyauthorization" % _id
            assert _field_keyauthorization in update_fields
            assert form[_field_keyauthorization] == "keyauthorization_%s" % _id

        # try adding a challenge
        form = res3.json["forms"]["acmeorderless-add_challenge"]
        add_fields = dict(form.items())
        assert "keyauthorization" in add_fields
        assert "domain" in add_fields
        assert "token" in add_fields
        add_fields["keyauthorization"] = "keyauthorization_add"
        add_fields["domain"] = "domain_add.example.com"
        add_fields["token"] = "token_add"

        res6 = self.testapp.post(
            "/.well-known/admin/acme-orderless/%s/add.json" % obj_id, add_fields
        )
        assert res6.status_code == 200
        assert "AcmeOrderless" in res6.json
        assert add_fields["domain"] in res6.json["AcmeOrderless"]["domains_status"]

        form = res3.json["forms"]["acmeorderless-deactivate"]
        res7 = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s/deactivate.json" % obj_id
        )
        assert "error" in res7.json
        assert res7.json["error"] == "This route requires a POST"

        res8 = self.testapp.post(
            "/.well-known/admin/acme-orderless/%s/deactivate.json" % obj_id, {}
        )
        assert res8.status_code == 200
        assert "result" in res8.json
        assert res8.json["result"] == "success"
        assert "AcmeOrderless" in res8.json
        assert res8.json["AcmeOrderless"]["is_processing"] is False

        res10 = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s/acme-challenge/%s.json"
            % (obj_id, _challenge_ids[0]),
            status=200,
        )
        assert "result" in res10.json
        assert res10.json["result"] == "success"
        assert "AcmeOrderless" in res10.json
        assert "AcmeChallenge" in res10.json


class FunctionalTests_AcmeAccountProvider(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeAccountProvider
    """

    @tests_routes("admin:acme_account_providers")
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/acme-account-providers", status=200)

    @tests_routes("admin:acme_account_providers|json")
    def test_list_json(self):
        # json root
        res = self.testapp.get(
            "/.well-known/admin/acme-account-providers.json", status=200
        )
        assert "AcmeAccountProviders" in res.json


class FunctionalTests_CACertificate(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_CACertificate
    """

    @tests_routes(("admin:ca_certificates", "admin:ca_certificates_paginated",))
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/ca-certificates", status=200)
        # paginated
        res = self.testapp.get("/.well-known/admin/ca-certificates/1", status=200)

    @tests_routes(
        ("admin:ca_certificates|json", "admin:ca_certificates_paginated|json",)
    )
    def test_list_json(self):
        # JSON root
        res = self.testapp.get("/.well-known/admin/ca-certificates.json", status=200)
        assert "CACertificates" in res.json

        # JSON paginated
        res = self.testapp.get("/.well-known/admin/ca-certificates/1.json", status=200)
        assert "CACertificates" in res.json

    @tests_routes(
        (
            "admin:ca_certificate:focus",
            "admin:ca_certificate:focus:raw",
            "admin:ca_certificate:focus:server_certificates",
            "admin:ca_certificate:focus:server_certificates_paginated",
        )
    )
    def test_focus_html(self):
        res = self.testapp.get("/.well-known/admin/ca-certificate/1", status=200)
        res = self.testapp.get(
            "/.well-known/admin/ca-certificate/1/chain.cer", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/ca-certificate/1/chain.crt", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/ca-certificate/1/chain.der", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/ca-certificate/1/chain.pem", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/ca-certificate/1/chain.pem.txt", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/ca-certificate/1/server-certificates", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/ca-certificate/1/server-certificates/1", status=200
        )

    @tests_routes(
        ("admin:ca_certificate:focus|json", "admin:ca_certificate:focus:parse|json",)
    )
    def test_focus_json(self):
        res = self.testapp.get("/.well-known/admin/ca-certificate/1.json", status=200)
        res = self.testapp.get(
            "/.well-known/admin/ca-certificate/1/parse.json", status=200
        )

    @tests_routes(
        ("admin:ca_certificate:upload", "admin:ca_certificate:upload_bundle",)
    )
    def test_upload_html(self):
        """This should enter in item #3, but the CACertificates.order is 1; the other cert is a self-signed"""
        _ca_cert_id = TEST_FILES["CACertificates"]["order"][1]
        _ca_cert_filename = TEST_FILES["CACertificates"]["cert"][_ca_cert_id]
        _ca_cert_filepath = self._filepath_testfile(_ca_cert_filename)

        res = self.testapp.get("/.well-known/admin/ca-certificate/upload", status=200)
        form = res.form
        form["chain_file"] = Upload(_ca_cert_filepath)
        res2 = form.submit()
        assert res2.status_code == 303

        re_expected = re.compile(
            r"""^http://peter-sslers\.example\.com/\.well-known/admin/ca-certificate/(\d+)\?result=success&is_created=1$"""
        )
        matched = re_expected.match(res2.location)
        assert matched
        obj_id = matched.groups()[0]
        res3 = self.testapp.get(res2.location, status=200)

        # try a bundle
        res = self.testapp.get(
            "/.well-known/admin/ca-certificate/upload-bundle", status=200
        )
        form = res.form
        form["isrgrootx1_file"] = Upload(
            self._filepath_testfile(TEST_FILES["CACertificates"]["cert"]["isrgrootx1"])
        )
        form["le_x1_auth_file"] = Upload(
            self._filepath_testfile(TEST_FILES["CACertificates"]["cert"]["le_x1_auth"])
        )
        form["le_x2_auth_file"] = Upload(
            self._filepath_testfile(TEST_FILES["CACertificates"]["cert"]["le_x2_auth"])
        )
        form["le_x1_cross_signed_file"] = Upload(
            self._filepath_testfile(
                TEST_FILES["CACertificates"]["cert"]["le_x1_cross_signed"]
            )
        )
        form["le_x2_cross_signed_file"] = Upload(
            self._filepath_testfile(
                TEST_FILES["CACertificates"]["cert"]["le_x2_cross_signed"]
            )
        )
        form["le_x3_cross_signed_file"] = Upload(
            self._filepath_testfile(
                TEST_FILES["CACertificates"]["cert"]["le_x3_cross_signed"]
            )
        )
        form["le_x4_cross_signed_file"] = Upload(
            self._filepath_testfile(
                TEST_FILES["CACertificates"]["cert"]["le_x4_cross_signed"]
            )
        )
        res2 = form.submit()
        assert res2.status_code == 303
        assert (
            res2.location
            == """http://peter-sslers.example.com/.well-known/admin/ca-certificates?uploaded=1"""
        )
        res3 = self.testapp.get(res2.location, status=200)

        """This should enter in item #4"""
        _ca_cert_id = TEST_FILES["CACertificates"]["order"][2]
        _ca_cert_filename = TEST_FILES["CACertificates"]["cert"][_ca_cert_id]
        _ca_cert_filepath = self._filepath_testfile(_ca_cert_filename)

    @tests_routes(
        ("admin:ca_certificate:upload|json", "admin:ca_certificate:upload_bundle|json",)
    )
    def test_upload_json(self):
        _ca_cert_id = TEST_FILES["CACertificates"]["order"][1]
        _ca_cert_filename = TEST_FILES["CACertificates"]["cert"][_ca_cert_id]
        _ca_cert_filepath = self._filepath_testfile(_ca_cert_filename)

        res = self.testapp.get(
            "/.well-known/admin/ca-certificate/upload.json", status=200
        )
        _data = {"chain_file": Upload(_ca_cert_filepath)}
        res2 = self.testapp.post("/.well-known/admin/ca-certificate/upload.json", _data)
        assert res2.status_code == 200
        assert res2.json["result"] == "success"

        # we may not have created this
        assert res2.json["CACertificate"]["created"] in (True, False)
        assert (
            res2.json["CACertificate"]["id"] > 2
        )  # the database was set up with 2 items
        obj_id = res2.json["CACertificate"]["id"]

        res3 = self.testapp.get(
            "/.well-known/admin/ca-certificate/%s" % obj_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/ca-certificate/upload-bundle.json", status=200
        )
        chain_filepath = self._filepath_testfile("lets-encrypt-x1-cross-signed.pem.txt")
        form = {}
        form["isrgrootx1_file"] = Upload(
            self._filepath_testfile(TEST_FILES["CACertificates"]["cert"]["isrgrootx1"])
        )
        form["le_x1_auth_file"] = Upload(
            self._filepath_testfile(TEST_FILES["CACertificates"]["cert"]["le_x1_auth"])
        )
        form["le_x2_auth_file"] = Upload(
            self._filepath_testfile(TEST_FILES["CACertificates"]["cert"]["le_x2_auth"])
        )
        form["le_x1_cross_signed_file"] = Upload(
            self._filepath_testfile(
                TEST_FILES["CACertificates"]["cert"]["le_x1_cross_signed"]
            )
        )
        form["le_x2_cross_signed_file"] = Upload(
            self._filepath_testfile(
                TEST_FILES["CACertificates"]["cert"]["le_x2_cross_signed"]
            )
        )
        form["le_x3_cross_signed_file"] = Upload(
            self._filepath_testfile(
                TEST_FILES["CACertificates"]["cert"]["le_x3_cross_signed"]
            )
        )
        form["le_x4_cross_signed_file"] = Upload(
            self._filepath_testfile(
                TEST_FILES["CACertificates"]["cert"]["le_x4_cross_signed"]
            )
        )
        res2 = self.testapp.post(
            "/.well-known/admin/ca-certificate/upload-bundle.json", form
        )
        assert res2.status_code == 200
        assert res2.json["result"] == "success"
        # this is going to be too messy to check all the vars
        # {u'isrgrootx1_pem': {u'id': 5, u'created': False}, u'le_x2_auth_pem': {u'id': 3, u'created': False}, u'le_x4_cross_signed_pem': {u'id': 6, u'created': False}, u'le_x2_cross_signed_pem': {u'id': 7, u'created': False}, u'le_x3_cross_signed_pem': {u'id': 8, u'created': False}, u'result': u'success', u'le_x1_cross_signed_pem': {u'id': 4, u'created': False}, u'le_x1_auth_pem': {u'id': 1, u'created': False}}


class FunctionalTests_CertificateRequest(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_CertificateRequest
    """

    def _get_one(self):
        # grab a certificate
        focus_item = (
            self.ctx.dbSession.query(model_objects.CertificateRequest)
            .order_by(model_objects.CertificateRequest.id.asc())
            .first()
        )
        return focus_item

    @tests_routes(
        ("admin:certificate_requests", "admin:certificate_requests_paginated",)
    )
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/certificate-requests", status=200)

        # paginated
        res = self.testapp.get("/.well-known/admin/certificate-requests/1", status=200)

    @tests_routes(
        (
            "admin:certificate_requests|json",
            "admin:certificate_requests_paginated|json",
        )
    )
    def test_list_json(self):
        # root
        res = self.testapp.get(
            "/.well-known/admin/certificate-requests.json", status=200
        )
        assert "CertificateRequests" in res.json

        # paginated
        res = self.testapp.get(
            "/.well-known/admin/certificate-requests/1.json", status=200
        )
        assert "CertificateRequests" in res.json

    @tests_routes(
        (
            "admin:certificate_request:focus",
            "admin:certificate_request:focus:acme_orders",
            "admin:certificate_request:focus:acme_orders_paginated",
        )
    )
    def test_focus_html(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/certificate-request/%s" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/admin/certificate-request/%s/acme-orders" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/admin/certificate-request/%s/acme-orders/1" % focus_id,
            status=200,
        )

    @tests_routes(("admin:certificate_request:focus:raw",))
    def test_focus_raw(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/certificate-request/%s/csr.csr" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-request/%s/csr.pem" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-request/%s/csr.pem.txt" % focus_id,
            status=200,
        )

    @tests_routes(("admin:certificate_request:focus|json",))
    def test_focus_json(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/certificate-request/%s.json" % focus_id, status=200
        )
        assert "CertificateRequest" in res.json


class FunctionalTests_CoverageAssuranceEvent(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_CoverageAssuranceEvent
    """

    def _get_one(self):
        # grab a Domain
        focus_item = (
            self.ctx.dbSession.query(model_objects.CoverageAssuranceEvent)
            .order_by(model_objects.CoverageAssuranceEvent.id.asc())
            .first()
        )
        return focus_item

    @tests_routes(
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
            "/.well-known/admin/coverage-assurance-events", status=303
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/coverage-assurance-events/all"
        )

        # roots
        res = self.testapp.get(
            "/.well-known/admin/coverage-assurance-events/all", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/coverage-assurance-events/unresolved", status=200
        )

        # paginated
        res = self.testapp.get(
            "/.well-known/admin/coverage-assurance-events/all/1", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/coverage-assurance-events/unresolved/1", status=200
        )

    @tests_routes(("admin:coverage_assurance_event:focus",))
    def test_focus_html(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/coverage-assurance-event/%s" % focus_id, status=200
        )


class FunctionalTests_Domain(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_Domain
    """

    def _get_one(self):
        # grab a Domain
        focus_item = (
            self.ctx.dbSession.query(model_objects.Domain)
            .filter(model_objects.Domain.is_active.op("IS")(True))
            .order_by(model_objects.Domain.id.asc())
            .first()
        )
        return focus_item

    @tests_routes(
        (
            "admin:domains",
            "admin:domains_paginated",
            "admin:domains:challenged",
            "admin:domains:challenged_paginated",
            "admin:domains:expiring",
            "admin:domains:expiring_paginated",
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/domains", status=200)
        res = self.testapp.get("/.well-known/admin/domains/challenged", status=200)
        res = self.testapp.get("/.well-known/admin/domains/expiring", status=200)

        # paginated
        res = self.testapp.get("/.well-known/admin/domains/1", status=200)
        res = self.testapp.get("/.well-known/admin/domains/challenged/1", status=200)
        res = self.testapp.get("/.well-known/admin/domains/expiring/1", status=200)

    @tests_routes(
        (
            "admin:domains|json",
            "admin:domains_paginated|json",
            "admin:domains:challenged|json",
            "admin:domains:challenged_paginated|json",
            "admin:domains:expiring|json",
            "admin:domains:expiring_paginated|json",
        )
    )
    def test_list_json(self):
        # json root
        res = self.testapp.get("/.well-known/admin/domains.json", status=200)
        assert "Domains" in res.json

        res = self.testapp.get("/.well-known/admin/domains/challenged.json", status=200)
        assert "Domains" in res.json

        res = self.testapp.get("/.well-known/admin/domains/expiring.json", status=200)
        assert "Domains" in res.json

        # json paginated
        res = self.testapp.get("/.well-known/admin/domains/1.json", status=200)
        assert "Domains" in res.json

        res = self.testapp.get(
            "/.well-known/admin/domains/challenged/1.json", status=200
        )
        assert "Domains" in res.json

        res = self.testapp.get("/.well-known/admin/domains/expiring/1.json", status=200)
        assert "Domains" in res.json

    @tests_routes(("admin:domains:search",))
    def test_search_html(self):
        res = self.testapp.get("/.well-known/admin/domains/search", status=200)
        res2 = self.testapp.post(
            "/.well-known/admin/domains/search", {"domain": "example.com"}
        )

    @tests_routes(("admin:domains:search|json",))
    def test_search_json(self):
        res = self.testapp.get("/.well-known/admin/domains/search.json", status=200)
        res2 = self.testapp.post(
            "/.well-known/admin/domains/search.json", {"domain": "example.com"}
        )

    @tests_routes(
        (
            "admin:domain:focus",
            "admin:domain:focus:acme_authorizations",
            "admin:domain:focus:acme_authorizations_paginated",
            "admin:domain:focus:acme_challenges",
            "admin:domain:focus:acme_challenges_paginated",
            "admin:domain:focus:acme_orders",
            "admin:domain:focus:acme_orders_paginated",
            "admin:domain:focus:acme_orderlesss",
            "admin:domain:focus:acme_orderlesss_paginated",
            "admin:domain:focus:certificate_requests",
            "admin:domain:focus:certificate_requests_paginated",
            "admin:domain:focus:server_certificates",
            "admin:domain:focus:server_certificates_paginated",
            "admin:domain:focus:queue_certificates",
            "admin:domain:focus:queue_certificates_paginated",
            "admin:domain:focus:unique_fqdn_sets",
            "admin:domain:focus:unique_fqdn_sets_paginated",
        )
    )
    def test_focus_html(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id
        focus_name = focus_item.domain_name

        res = self.testapp.get("/.well-known/admin/domain/%s" % focus_id, status=200)
        res = self.testapp.get("/.well-known/admin/domain/%s" % focus_name, status=200)

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/acme-authorizations" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/acme-authorizations/1" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/acme-challenges" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/acme-challenges/1" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/acme-orders" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/acme-orders/1" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/acme-orderlesss" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/acme-orderlesss/1" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/certificate-requests" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/certificate-requests/1" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/server-certificates" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/server-certificates/1" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/queue-certificates" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/queue-certificates/1" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/unique-fqdn-sets" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/unique-fqdn-sets/1" % focus_id, status=200
        )

    @tests_routes(
        (
            "admin:domain:focus|json",
            "admin:domain:focus:config|json",
            "admin:domain:focus:calendar|json",
        )
    )
    def test_focus_json(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id
        focus_name = focus_item.domain_name

        res = self.testapp.get(
            "/.well-known/admin/domain/%s.json" % focus_id, status=200
        )
        assert "Domain" in res.json

        res = self.testapp.get(
            "/.well-known/admin/domain/%s.json" % focus_name, status=200
        )
        assert "Domain" in res.json

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/config.json" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/calendar.json" % focus_id, status=200
        )

    @tests_routes(("admin:domain:focus:mark",))
    def test_manipulate_html(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/mark" % focus_id, status=303,
        )
        assert res.location.endswith("?result=error&error=post+required&operation=mark")

        # the `focus_item` is active,
        if not focus_item.is_active:
            raise ValueError("NOT focus_item.is_active")

        # fail making this active
        res = self.testapp.post(
            "/.well-known/admin/domain/%s/mark" % focus_id, {"action": "active"},
        )
        assert res.status_code == 303
        assert res.location.endswith(
            "?result=error&error=Error_Main--There+was+an+error+with+your+form.+Already+active.&operation=mark&action=active"
        )

        # inactive ROUNDTRIP
        res = self.testapp.post(
            "/.well-known/admin/domain/%s/mark" % focus_id, {"action": "inactive"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=inactive")

        res = self.testapp.post(
            "/.well-known/admin/domain/%s/mark" % focus_id, {"action": "active"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=active")

    @tests_routes(("admin:domain:focus:mark|json",))
    def test_manipulate_json(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        # GET
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/mark.json" % focus_id,
            {"action": "active"},
            status=200,
        )
        assert "form_fields" in res.json
        assert "instructions" in res.json

        # the `focus_item` is active,
        if not focus_item.is_active:
            raise ValueError("NOT focus_item.is_active")

        # fail making this active
        res = self.testapp.post(
            "/.well-known/admin/domain/%s/mark.json" % focus_id, {"action": "active"},
        )
        assert res.status_code == 200
        assert res.json["result"] == "error"
        assert (
            res.json["form_errors"]["Error_Main"]
            == "There was an error with your form. Already active."
        )

        # inactive ROUNDTRIP
        res = self.testapp.post(
            "/.well-known/admin/domain/%s/mark.json" % focus_id, {"action": "inactive"},
        )
        assert res.status_code == 200
        assert "Domain" in res.json
        assert res.json["Domain"]["is_active"] is False

        res = self.testapp.post(
            "/.well-known/admin/domain/%s/mark.json" % focus_id, {"action": "active"},
        )
        assert res.status_code == 200
        assert "Domain" in res.json
        assert res.json["Domain"]["is_active"] is True

    @unittest.skipUnless(RUN_NGINX_TESTS, "not running against nginx")
    @tests_routes(("admin:domain:focus:nginx_cache_expire",))
    def test_nginx_html(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id
        focus_name = focus_item.domain_name

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/nginx-cache-expire" % focus_id, status=303
        )
        RE_success = re.compile(
            r"^http://peter-sslers\.example\.com/\.well-known/admin/domain/\d+\?result=success&operation=nginx\+cache\+expire&event\.id=\d+$"
            ""
        )
        assert RE_success.match(res.location)

    @unittest.skipUnless(RUN_NGINX_TESTS, "not running against nginx")
    @tests_routes(("admin:domain:focus:nginx_cache_expire|json",))
    def test_nginx_json(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id
        focus_name = focus_item.domain_name

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/nginx-cache-expire.json" % focus_id,
            status=200,
        )
        assert res.json["result"] == "success"


class FunctionalTests_DomainBlacklisted(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_DomainBlacklisted
    """

    @tests_routes(("admin:domains_blacklisted", "admin:domains_blacklisted_paginated",))
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/domains-blacklisted", status=200)

        # paginated
        res = self.testapp.get("/.well-known/admin/domains-blacklisted/1", status=200)

    @tests_routes(
        ("admin:domains_blacklisted|json", "admin:domains_blacklisted_paginated|json",)
    )
    def test_list_json(self):
        # json root
        res = self.testapp.get(
            "/.well-known/admin/domains-blacklisted.json", status=200
        )
        assert "DomainsBlacklisted" in res.json

        # json paginated
        res = self.testapp.get(
            "/.well-known/admin/domains-blacklisted/1.json", status=200
        )
        assert "DomainsBlacklisted" in res.json

    def test_AcmeOrder_new_fails(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_DomainBlacklisted.test_AcmeOrder_new_fails
        """
        _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]

        # "admin:acme_order:new:freeform",
        res = self.testapp.get("/.well-known/admin/acme-order/new/freeform", status=200)

        form = res.form
        _form_fields = form.fields.keys()
        assert "account_key_option" in _form_fields
        form["account_key_option"].force_value("account_key_file")
        form["acme_account_provider_id"].force_value("1")
        form["account_key_file_pem"] = Upload(
            self._filepath_testfile(
                _test_data["acme-order/new/freeform#1"]["account_key_file_pem"]
            )
        )
        form["account__contact"] = _test_data["acme-order/new/freeform#1"][
            "account__contact"
        ]
        form["account__private_key_cycle"].force_value("account_daily")
        form["private_key_cycle__renewal"].force_value("account_key_default")
        form["private_key_option"].force_value("private_key_for_account_key")
        form["domain_names"] = "always-fail.example.com, foo.example.com"
        form["processing_strategy"].force_value("create_order")
        res2 = form.submit()

        assert res2.status_code == 200
        assert "There was an error with your form." in res2.text
        assert (
            "The following Domains are blacklisted: always-fail.example.com"
            in res2.text
        )

    def test_AcmeOrderless_new_fails(self):

        res = self.testapp.get("/.well-known/admin/acme-orderless/new", status=200)
        form = res.form
        form["domain_names"] = "always-fail.example.com, foo.example.com"
        res2 = form.submit()

        assert res2.status_code == 200
        assert "There was an error with your form." in res2.text
        assert (
            "The following Domains are blacklisted: always-fail.example.com"
            in res2.text
        )

    def test_AcmeOrderless_add_fails(self):

        res = self.testapp.get("/.well-known/admin/acme-orderless/new", status=200)
        form = res.form
        form["domain_names"] = "example.com"
        res2 = form.submit()
        assert res2.status_code == 303
        matched = RE_AcmeOrderless.match(res2.location)
        assert matched
        obj_id = matched.groups()[0]

        # build a new form and submit edits
        res3 = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s" % obj_id, status=200,
        )
        form = res3.forms["acmeorderless-add_challenge"]
        add_fields = dict(form.submit_fields())
        assert "keyauthorization" in add_fields
        assert "domain" in add_fields
        assert "token" in add_fields
        form["keyauthorization"] = "keyauthorization_add"
        form["domain"] = "always-fail.example.com"
        form["token"] = "token_add"
        res4 = form.submit()
        assert res4.status_code == 200
        assert "There was an error with your form." in res4.text
        assert (
            """<span class="help-inline">This domain is blacklisted.</span>"""
            in res4.text
        )

    def test_QueueDomain_add_fails(self):
        res = self.testapp.get("/.well-known/admin/queue-domains/add", status=200)
        _domain_names = [
            "always-fail.example.com",
            "test-queuedomain-add-fails.example.com",
        ]
        form = res.form
        form["domain_names"] = ",".join(_domain_names)
        res2 = form.submit()
        assert res2.status_code == 303
        assert (
            res2.location
            == """http://peter-sslers.example.com/.well-known/admin/queue-domains?result=success&operation=add&results=%7B%22always-fail.example.com%22%3A+%22blacklisted%22%2C+%22test-queuedomain-add-fails.example.com%22%3A+%22queued%22%7D"""
        )


class FunctionalTests_Operations(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_Operations
    """

    @tests_routes(
        (
            "admin:operations",
            "admin:operations:ca_certificate_probes",
            "admin:operations:ca_certificate_probes_paginated",
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
        res = self.testapp.get("/.well-known/admin/operations", status=302)
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/operations/log"
        )

        res = self.testapp.get(
            "/.well-known/admin/operations/ca-certificate-probes", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/operations/ca-certificate-probes/1", status=200
        )

        res = self.testapp.get("/.well-known/admin/operations/log", status=200)
        res = self.testapp.get("/.well-known/admin/operations/log/1", status=200)
        res = self.testapp.get(
            "/.well-known/admin/operations/log/item/%s" % focus_item.id, status=200
        )

        res = self.testapp.get("/.well-known/admin/operations/object-log", status=200)
        res = self.testapp.get("/.well-known/admin/operations/object-log/1", status=200)
        res = self.testapp.get(
            "/.well-known/admin/operations/object-log/item/%s" % focus_item_event.id,
            status=200,
        )

        _nginx = (
            True
            if (
                ("enable_nginx" in self.testapp.app.registry.settings["app_settings"])
                and (
                    self.testapp.app.registry.settings["app_settings"]["enable_nginx"]
                    is True
                )
            )
            else False
        )
        if _nginx:
            res = self.testapp.get("/.well-known/admin/operations/nginx", status=200)
            res = self.testapp.get("/.well-known/admin/operations/nginx/1", status=200)
        else:
            res = self.testapp.get("/.well-known/admin/operations/nginx", status=302)
            assert (
                res.location
                == "http://peter-sslers.example.com/.well-known/admin?result=error&error=no+nginx"
            )

            res = self.testapp.get("/.well-known/admin/operations/nginx/1", status=302)
            assert (
                res.location
                == "http://peter-sslers.example.com/.well-known/admin?result=error&error=no+nginx"
            )

        res = self.testapp.get("/.well-known/admin/operations/redis", status=200)
        res = self.testapp.get("/.well-known/admin/operations/redis/1", status=200)


class FunctionalTests_PrivateKey(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_PrivateKey
    """

    def _get_one(self):
        # grab a Key
        # loop these in desc order, because latter items shouldn't have anything associated on them.
        focus_item = (
            self.ctx.dbSession.query(model_objects.PrivateKey)
            .filter(
                model_objects.PrivateKey.is_active.op("IS")(True),
                model_objects.PrivateKey.private_key_type_id
                != model_utils.PrivateKeyType.from_string("placeholder"),
            )
            .order_by(model_objects.PrivateKey.id.desc())
            .first()
        )
        return focus_item

    @tests_routes(("admin:private_keys", "admin:private_keys_paginated",))
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/private-keys", status=200)

        # paginated
        res = self.testapp.get("/.well-known/admin/private-keys/1", status=200)

    @tests_routes(("admin:private_keys|json", "admin:private_keys_paginated|json",))
    def test_list_json(self):
        # json
        res = self.testapp.get("/.well-known/admin/private-keys.json", status=200)
        assert "PrivateKeys" in res.json

        res = self.testapp.get("/.well-known/admin/private-keys/1.json", status=200)
        assert "PrivateKeys" in res.json

    @tests_routes(
        (
            "admin:private_key:focus",
            "admin:private_key:focus:certificate_requests",
            "admin:private_key:focus:certificate_requests_paginated",
            "admin:private_key:focus:server_certificates",
            "admin:private_key:focus:server_certificates_paginated",
            "admin:private_key:focus:queue_certificates",
            "admin:private_key:focus:queue_certificates_paginated",
        )
    )
    def test_focus_html(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/private-key/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/certificate-requests" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/certificate-requests/1" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/server-certificates" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/server-certificates/1" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/queue-certificates" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/queue-certificates/1" % focus_id,
            status=200,
        )

    @tests_routes(
        ("admin:private_key:focus|json", "admin:private_key:focus:parse|json",)
    )
    def test_focus_json(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/private-key/%s.json" % focus_id, status=200
        )
        assert "PrivateKey" in res.json

        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/parse.json" % focus_id, status=200
        )
        assert str(focus_id) in res.json

    @tests_routes(("admin:private_key:focus:raw",))
    def test_focus_raw(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/key.key" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/key.pem" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/key.pem.txt" % focus_id, status=200
        )

    @tests_routes(("admin:private_key:focus:mark",))
    def test_manipulate_html(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/mark" % focus_id, status=303,
        )
        assert res.location.endswith("?result=error&error=post+required&operation=mark")

        # the `focus_item` is active, so it can't be compromised or inactive
        if focus_item.is_compromised:
            raise ValueError("focus_item.is_compromised")

        if not focus_item.is_active:
            raise ValueError("NOT focus_item.is_active")

        # fail making this active
        res = self.testapp.post(
            "/.well-known/admin/private-key/%s/mark" % focus_id, {"action": "active"},
        )
        assert res.status_code == 303
        assert res.location.endswith(
            "?result=error&error=Error_Main--There+was+an+error+with+your+form.+Already+activated.&operation=mark&action=active"
        )

        # inactive ROUNDTRIP
        res = self.testapp.post(
            "/.well-known/admin/private-key/%s/mark" % focus_id, {"action": "inactive"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=inactive")

        res = self.testapp.post(
            "/.well-known/admin/private-key/%s/mark" % focus_id, {"action": "active"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=active")

        # then compromised
        res = self.testapp.post(
            "/.well-known/admin/private-key/%s/mark" % focus_id,
            {"action": "compromised"},
        )
        assert res.status_code == 303
        assert res.location.endswith(
            "?result=success&operation=mark&action=compromised"
        )

    @tests_routes(("admin:private_key:focus:mark|json",))
    def test_manipulate_json(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/mark.json" % focus_id, status=200,
        )
        assert "form_fields" in res.json
        assert "instructions" in res.json

        # the `focus_item` is active, so it can't be compromised or inactive
        if focus_item.is_compromised:
            raise ValueError("focus_item.is_compromised")

        if not focus_item.is_active:
            raise ValueError("NOT focus_item.is_active")

        # fail making this active
        res = self.testapp.post(
            "/.well-known/admin/private-key/%s/mark.json" % focus_id,
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
            "/.well-known/admin/private-key/%s/mark.json" % focus_id,
            {"action": "inactive"},
        )
        assert res.status_code == 200
        assert "PrivateKey" in res.json
        assert res.json["PrivateKey"]["is_active"] is False

        res = self.testapp.post(
            "/.well-known/admin/private-key/%s/mark.json" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 200
        assert "PrivateKey" in res.json
        assert res.json["PrivateKey"]["is_active"] is True

        # then compromised
        res = self.testapp.post(
            "/.well-known/admin/private-key/%s/mark.json" % focus_id,
            {"action": "compromised"},
        )
        assert res.status_code == 200
        assert "PrivateKey" in res.json
        assert res.json["PrivateKey"]["is_active"] is False
        assert res.json["PrivateKey"]["is_compromised"] is True

    @tests_routes(("admin:private_key:upload", "admin:private_key:new",))
    def test_new_html(self):
        # this should be creating a new key
        _key_filename = TEST_FILES["PrivateKey"]["2"]["file"]
        key_filepath = self._filepath_testfile(_key_filename)
        res = self.testapp.get("/.well-known/admin/private-key/upload", status=200)
        form = res.form
        form["private_key_file_pem"] = Upload(key_filepath)
        res2 = form.submit()
        assert res2.status_code == 303
        assert """/.well-known/admin/private-key/""" in res2.location
        # for some reason, we don't always "create" this.
        assert """?result=success""" in res2.location
        res3 = self.testapp.get(res2.location, status=200)

        # okay now new
        res = self.testapp.get("/.well-known/admin/private-key/new", status=200)
        form = res.form
        new_fields = dict(form.submit_fields())
        assert "bits" in new_fields
        assert new_fields["bits"] == "4096"

        res2 = form.submit()
        assert res2.status_code == 303
        # 'http://peter-sslers.example.com/.well-known/admin/private-key/3?result=success&is_created=1'
        assert res2.location.startswith(
            """http://peter-sslers.example.com/.well-known/admin/private-key/"""
        )
        # for some reason, we don't always "create" this.
        assert res2.location.endswith("""?result=success&is_created=1""")
        res3 = self.testapp.get(res2.location, status=200)

    @tests_routes(("admin:private_key:upload|json", "admin:private_key:new|json",))
    def test_new_json(self):
        _key_filename = TEST_FILES["PrivateKey"]["2"]["file"]
        key_filepath = self._filepath_testfile(_key_filename)

        res = self.testapp.get("/.well-known/admin/private-key/upload.json", status=200)
        assert "form_fields" in res.json

        form = {}
        form["private_key_file_pem"] = Upload(key_filepath)
        res2 = self.testapp.post("/.well-known/admin/private-key/upload.json", form)
        assert res2.status_code == 200
        assert "PrivateKey" in res2.json

        res = self.testapp.get("/.well-known/admin/private-key/new.json", status=200)
        assert "form_fields" in res.json

        form = {"bits": 4096}
        res2 = self.testapp.post("/.well-known/admin/private-key/new.json", form)
        assert res2.status_code == 200
        assert "PrivateKey" in res2.json


class FunctionalTests_ServerCertificate(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_ServerCertificate
    """

    def _get_one(self):
        # grab a certificate
        # iterate backwards
        focus_item = (
            self.ctx.dbSession.query(model_objects.ServerCertificate)
            .filter(model_objects.ServerCertificate.is_active.op("IS")(True))
            .order_by(model_objects.ServerCertificate.id.desc())
            .first()
        )
        return focus_item

    @tests_routes(
        (
            "admin:server_certificates",
            "admin:server_certificates_paginated",
            "admin:server_certificates:active",
            "admin:server_certificates:active_paginated",
            "admin:server_certificates:expiring",
            "admin:server_certificates:expiring_paginated",
            "admin:server_certificates:inactive",
            "admin:server_certificates:inactive_paginated",
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/server-certificates", status=200)

        # paginated
        res = self.testapp.get("/.well-known/admin/server-certificates/1", status=200)

        for _type in (
            "active",
            "expiring",
            "inactive",
        ):
            res = self.testapp.get(
                "/.well-known/admin/server-certificates/%s" % _type, status=200
            )
            res = self.testapp.get(
                "/.well-known/admin/server-certificates/%s/1" % _type, status=200
            )

    @tests_routes(
        (
            "admin:server_certificates|json",
            "admin:server_certificates_paginated|json",
            "admin:server_certificates:active|json",
            "admin:server_certificates:active_paginated|json",
            "admin:server_certificates:expiring|json",
            "admin:server_certificates:expiring_paginated|json",
            "admin:server_certificates:inactive|json",
            "admin:server_certificates:inactive_paginated|json",
        )
    )
    def test_list_json(self):
        # root
        res = self.testapp.get(
            "/.well-known/admin/server-certificates.json", status=200
        )
        assert "ServerCertificates" in res.json

        # paginated
        res = self.testapp.get(
            "/.well-known/admin/server-certificates/1.json", status=200
        )
        assert "ServerCertificates" in res.json

        for _type in (
            "active",
            "expiring",
            "inactive",
        ):
            res = self.testapp.get(
                "/.well-known/admin/server-certificates/%s.json" % _type, status=200
            )
            assert "ServerCertificates" in res.json

            res = self.testapp.get(
                "/.well-known/admin/server-certificates/%s/1.json" % _type, status=200
            )
            assert "ServerCertificates" in res.json

    @tests_routes(
        (
            "admin:server_certificate:focus",
            "admin:server_certificate:focus:queue_certificates",
            "admin:server_certificate:focus:queue_certificates_paginated",
        )
    )
    def test_focus_html(self):
        focus_item = self._get_one()
        if focus_item is None:
            raise ValueError(
                """This test currently fails when the ENTIRE SUITE is run """
                """because `FunctionalTests_API.tests_manipulate` will """
                """deactivate the certificate. Try running this test or """
                """this tests's class directly to ensure a pass."""
            )
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/queue-certificates" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/queue-certificates/1" % focus_id,
            status=200,
        )

    @tests_routes(
        (
            "admin:server_certificate:focus:chain:raw",
            "admin:server_certificate:focus:fullchain:raw",
            "admin:server_certificate:focus:privatekey:raw",
            "admin:server_certificate:focus:cert:raw",
        )
    )
    def test_focus_raw(self):
        focus_item = self._get_one()
        if focus_item is None:
            raise ValueError(
                """This test currently fails when the ENTIRE SUITE is run """
                """because `FunctionalTests_API.tests_manipulate` will """
                """deactivate the certificate. Try running this test or """
                """this tests's class directly to ensure a pass."""
            )
        focus_id = focus_item.id
        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/chain.cer" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/chain.crt" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/chain.der" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/chain.pem" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/chain.pem.txt" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/fullchain.pem" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/fullchain.pem.txt" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/privkey.key" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/privkey.pem" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/privkey.pem.txt" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/cert.crt" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/cert.pem" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/cert.pem.txt" % focus_id,
            status=200,
        )

    @tests_routes(
        (
            "admin:server_certificate:focus|json",
            "admin:server_certificate:focus:config|json",
            "admin:server_certificate:focus:parse|json",
        )
    )
    def test_focus_json(self):
        focus_item = self._get_one()
        if focus_item is None:
            raise ValueError(
                """This test currently fails when the ENTIRE SUITE is run """
                """because `FunctionalTests_API.tests_manipulate` will """
                """deactivate the certificate. Try running this test or """
                """this tests's class directly to ensure a pass."""
            )
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s.json" % focus_id, status=200
        )
        assert "ServerCertificate" in res.json

        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/config.json" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/parse.json" % focus_id, status=200
        )

    @tests_routes(("admin:server_certificate:focus:mark",))
    def test_manipulate_html(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/mark" % focus_id
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
            "/.well-known/admin/server-certificate/%s/mark" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 303
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/server-certificate/%s?&result=error&error=There+was+an+error+with+your+form.+Already+active.&operation=mark&action=active"
            % focus_id
        )

        # inactive ROUNDTRIP
        res = self.testapp.post(
            "/.well-known/admin/server-certificate/%s/mark" % focus_id,
            {"action": "inactive"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=inactive")

        res = self.testapp.post(
            "/.well-known/admin/server-certificate/%s/mark" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=active")

        # then compromised
        res = self.testapp.post(
            "/.well-known/admin/server-certificate/%s/mark" % focus_id,
            {"action": "revoked"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=revoked")

    @tests_routes(("admin:server_certificate:focus:mark|json",))
    def test_manipulate_json(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/mark.json" % focus_id, status=200,
        )
        assert "form_fields" in res.json
        assert "instructions" in res.json

        # the `focus_item` is active, so it can't be revoked or inactive
        if focus_item.is_revoked:
            raise ValueError("focus_item.is_revoked")

        if not focus_item.is_active:
            raise ValueError("NOT focus_item.is_active")

        # fail making this active
        res = self.testapp.post(
            "/.well-known/admin/server-certificate/%s/mark.json" % focus_id,
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
            "/.well-known/admin/server-certificate/%s/mark.json" % focus_id,
            {"action": "inactive"},
        )
        assert res.status_code == 200
        assert "ServerCertificate" in res.json
        assert res.json["ServerCertificate"]["is_active"] is False

        res = self.testapp.post(
            "/.well-known/admin/server-certificate/%s/mark.json" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 200
        assert "ServerCertificate" in res.json
        assert res.json["ServerCertificate"]["is_active"] is True

        # then compromised
        res = self.testapp.post(
            "/.well-known/admin/server-certificate/%s/mark.json" % focus_id,
            {"action": "revoked"},
        )
        assert res.status_code == 200
        assert "ServerCertificate" in res.json
        assert res.json["ServerCertificate"]["is_active"] is False
        assert res.json["ServerCertificate"]["is_revoked"] is True
        assert res.json["ServerCertificate"]["is_deactivated"] is True

    @tests_routes(("admin:server_certificate:upload",))
    def test_upload_html(self):
        #
        # upload a new cert
        #
        res = self.testapp.get(
            "/.well-known/admin/server-certificate/upload", status=200
        )
        _SelfSigned_id = "1"
        form = res.form
        form["certificate_file"] = Upload(
            self._filepath_testfile(
                TEST_FILES["ServerCertificates"]["SelfSigned"][_SelfSigned_id]["cert"]
            )
        )
        form["chain_file"] = Upload(
            self._filepath_testfile(
                TEST_FILES["ServerCertificates"]["SelfSigned"][_SelfSigned_id]["cert"]
            )
        )
        form["private_key_file_pem"] = Upload(
            self._filepath_testfile(
                TEST_FILES["ServerCertificates"]["SelfSigned"][_SelfSigned_id]["pkey"]
            )
        )
        res2 = form.submit()
        assert res2.status_code == 303
        assert res2.location.startswith(
            """http://peter-sslers.example.com/.well-known/admin/server-certificate/"""
        )

    @tests_routes(("admin:server_certificate:upload|json",))
    def test_upload_json(self):
        res = self.testapp.get(
            "/.well-known/admin/server-certificate/upload.json", status=200
        )
        chain_filepath = self._filepath_testfile("lets-encrypt-x1-cross-signed.pem.txt")
        _SelfSigned_id = "2"
        form = {}
        form["certificate_file"] = Upload(
            self._filepath_testfile(
                TEST_FILES["ServerCertificates"]["SelfSigned"][_SelfSigned_id]["cert"]
            )
        )
        form["chain_file"] = Upload(
            self._filepath_testfile(
                TEST_FILES["ServerCertificates"]["SelfSigned"][_SelfSigned_id]["cert"]
            )
        )
        form["private_key_file_pem"] = Upload(
            self._filepath_testfile(
                TEST_FILES["ServerCertificates"]["SelfSigned"][_SelfSigned_id]["pkey"]
            )
        )
        res2 = self.testapp.post(
            "/.well-known/admin/server-certificate/upload.json", form
        )
        assert res2.status_code == 200
        assert res2.json["result"] == "success"
        assert res2.json["ServerCertificate"]["created"] in (True, False)
        certificate_id = res2.json["ServerCertificate"]["id"]
        res3 = self.testapp.get(
            "/.well-known/admin/server-certificate/%s.json" % certificate_id, status=200
        )
        assert "ServerCertificate" in res3.json

    @unittest.skipUnless(RUN_NGINX_TESTS, "not running against nginx")
    @tests_routes(("admin:server_certificate:focus:nginx_cache_expire",))
    def test_nginx_html(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/nginx-cache-expire" % focus_id,
            status=303,
        )
        RE_success = re.compile(
            r"^http://peter-sslers\.example\.com/\.well-known/admin/server-certificate/\d+\?result=success&operation=nginx\+cache\+expire&event\.id=\d+$"
            ""
        )
        assert RE_success.match(res.location)

    @unittest.skipUnless(RUN_NGINX_TESTS, "not running against nginx")
    @tests_routes(("admin:server_certificate:focus:nginx_cache_expire|json",))
    def test_nginx_json(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/nginx-cache-expire.json"
            % focus_id,
            status=200,
        )
        assert res.json["result"] == "success"


class FunctionalTests_UniqueFQDNSet(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_UniqueFQDNSet
    """

    def _get_one(self):
        # grab a UniqueFQDNSet
        focus_item = (
            self.ctx.dbSession.query(model_objects.UniqueFQDNSet)
            .order_by(model_objects.UniqueFQDNSet.id.asc())
            .first()
        )
        return focus_item

    @tests_routes(("admin:unique_fqdn_sets", "admin:unique_fqdn_sets_paginated",))
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/unique-fqdn-sets", status=200)

        # paginated
        res = self.testapp.get("/.well-known/admin/unique-fqdn-sets/1", status=200)

    @tests_routes(
        ("admin:unique_fqdn_sets|json", "admin:unique_fqdn_sets_paginated|json",)
    )
    def test_list_json(self):
        # root
        res = self.testapp.get("/.well-known/admin/unique-fqdn-sets.json", status=200)
        assert "UniqueFQDNSets" in res.json

        # paginated
        res = self.testapp.get("/.well-known/admin/unique-fqdn-sets/1.json", status=200)
        assert "UniqueFQDNSets" in res.json

    @tests_routes(
        (
            "admin:unique_fqdn_set:focus",
            "admin:unique_fqdn_set:focus:acme_orders",
            "admin:unique_fqdn_set:focus:acme_orders_paginated",
            "admin:unique_fqdn_set:focus:certificate_requests",
            "admin:unique_fqdn_set:focus:certificate_requests_paginated",
            "admin:unique_fqdn_set:focus:server_certificates",
            "admin:unique_fqdn_set:focus:server_certificates_paginated",
            "admin:unique_fqdn_set:focus:queue_certificates",
            "admin:unique_fqdn_set:focus:queue_certificates_paginated",
        )
    )
    def test_focus_html(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s/acme-orders" % focus_id, status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s/acme-orders/1" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s/certificate-requests" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s/certificate-requests/1" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s/server-certificates" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s/server-certificates/1" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s/queue-certificates" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s/queue-certificates/1" % focus_id,
            status=200,
        )

    @tests_routes(
        (
            "admin:unique_fqdn_set:focus|json",
            "admin:unique_fqdn_set:focus:calendar|json",
        )
    )
    def test_focus_json(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s.json" % focus_id, status=200
        )
        assert "UniqueFQDNSet" in res.json

        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s/calendar.json" % focus_id, status=200
        )


class FunctionalTests_QueueCertificate(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_QueueCertificate
    """

    def _get_one(self):
        # grab an item
        focus_item = (
            self.ctx.dbSession.query(model_objects.QueueCertificate)
            .filter(model_objects.QueueCertificate.is_active.is_(True))
            .order_by(model_objects.QueueCertificate.id.asc())
            .first()
        )
        return focus_item

    @tests_routes(
        (
            "admin:queue_certificates",
            "admin:queue_certificates:all",
            "admin:queue_certificates:all_paginated",
            "admin:queue_certificates:failures",
            "admin:queue_certificates:failures_paginated",
            "admin:queue_certificates:successes",
            "admin:queue_certificates:successes_paginated",
            "admin:queue_certificates:unprocessed",
            "admin:queue_certificates:unprocessed_paginated",
        )
    )
    def test_list_html(self):
        # root redirects
        res = self.testapp.get("/.well-known/admin/queue-certificates", status=303)
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/queue-certificates/all"
        )

        # root
        res = self.testapp.get("/.well-known/admin/queue-certificates/all", status=200)
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/failures", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/successes", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/unprocessed", status=200
        )

        # paginated
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/all/1", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/failures/1", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/successes/1", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/unprocessed/1", status=200
        )

    @tests_routes(
        (
            "admin:queue_certificates|json",
            "admin:queue_certificates:all|json",
            "admin:queue_certificates:all_paginated|json",
            "admin:queue_certificates:failures|json",
            "admin:queue_certificates:failures_paginated|json",
            "admin:queue_certificates:successes|json",
            "admin:queue_certificates:successes_paginated|json",
            "admin:queue_certificates:unprocessed|json",
            "admin:queue_certificates:unprocessed_paginated|json",
        )
    )
    def test_list_json(self):
        # root|json redirects
        res = self.testapp.get("/.well-known/admin/queue-certificates.json", status=303)
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/queue-certificates/all.json"
        )

        # root
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/all.json", status=200
        )
        assert "pagination" in res.json
        assert "QueueCertificates" in res.json

        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/failures.json", status=200
        )
        assert "pagination" in res.json
        assert "QueueCertificates" in res.json

        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/successes.json", status=200
        )
        assert "pagination" in res.json
        assert "QueueCertificates" in res.json

        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/unprocessed.json", status=200
        )
        assert "pagination" in res.json
        assert "QueueCertificates" in res.json

        # paginated
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/all/1.json", status=200
        )
        assert "pagination" in res.json
        assert "QueueCertificates" in res.json

        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/failures/1.json", status=200
        )
        assert "pagination" in res.json
        assert "QueueCertificates" in res.json

        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/successes/1.json", status=200
        )
        assert "pagination" in res.json
        assert "QueueCertificates" in res.json

        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/unprocessed/1.json", status=200
        )
        assert "pagination" in res.json
        assert "QueueCertificates" in res.json

    @tests_routes(("admin:queue_certificate:focus",))
    def test_focus_html(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_QueueCertificate.test_focus_html
        """
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/%s" % focus_id, status=200
        )

    @tests_routes(("admin:queue_certificate:focus|json",))
    def test_focus_json(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_QueueCertificate.test_focus_json
        """
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/%s.json" % focus_id, status=200
        )
        assert res.json["result"] == "success"
        assert "QueueCertificate" in res.json
        assert res.json["QueueCertificate"]["id"] == focus_id

    @tests_routes(("admin:queue_certificate:focus:mark",))
    def test_manipulate_html(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_QueueCertificate.test_manipulate_html
        """
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/%s/mark" % focus_id,
            {"action": "cancel"},
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/queue-certificate/%s?&result=error&error=post+required&operation=mark"
            % focus_id
        )

        res2 = self.testapp.post(
            "/.well-known/admin/queue-certificate/%s/mark" % focus_id,
            {"action": "cancel"},
            status=303,
        )
        assert (
            res2.location
            == "http://peter-sslers.example.com/.well-known/admin/queue-certificate/%s?result=success&operation=mark"
            % focus_id
        )

        res3 = self.testapp.post(
            "/.well-known/admin/queue-certificate/%s/mark" % focus_id,
            {"action": "cancel"},
            status=303,
        )
        assert (
            res3.location
            == "http://peter-sslers.example.com/.well-known/admin/queue-certificate/%s?result=error&error=action--Already+cancelledError_Main--There+was+an+error+with+your+form.&operation=mark&action=cancel"
            % focus_id
        )

    @tests_routes(("admin:queue_certificate:focus:mark|json",))
    def test_manipulate_json(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_QueueCertificate.test_manipulate_json
        """
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/%s/mark.json" % focus_id,
            {"action": "cancel"},
            status=200,
        )
        assert "instructions" in res.json

        res2 = self.testapp.post(
            "/.well-known/admin/queue-certificate/%s/mark.json" % focus_id,
            {"action": "cancel"},
            status=200,
        )
        assert res2.json["result"] == "success"
        assert res2.json["QueueCertificate"]["is_active"] is False

        res3 = self.testapp.post(
            "/.well-known/admin/queue-certificate/%s/mark.json" % focus_id,
            {"action": "cancel"},
            status=200,
        )
        assert res3.json["result"] == "error"
        assert res3.json["form_errors"]["action"] == "Already cancelled"

    def _get_queueable_AcmeOrder(self):
        # see `AcmeOrder.is_renewable_queue`
        dbAcmeOrder = (
            self.ctx.dbSession.query(model_objects.AcmeOrder)
            .join(
                model_objects.AcmeAccount,
                model_objects.AcmeOrder.acme_account_id == model_objects.AcmeAccount.id,
            )
            .filter(model_objects.AcmeAccount.is_active.is_(True),)
            .order_by(model_objects.AcmeOrder.id.asc())
            .first()
        )
        assert dbAcmeOrder
        return dbAcmeOrder

    def _get_queueable_ServerCertificate(self):
        dbServerCertificate = (
            self.ctx.dbSession.query(model_objects.ServerCertificate)
            .order_by(model_objects.ServerCertificate.id.asc())
            .first()
        )
        assert dbServerCertificate
        return dbServerCertificate

    def _get_queueable_UniqueFQDNSet(self):
        dbUniqueFQDNSet = (
            self.ctx.dbSession.query(model_objects.UniqueFQDNSet)
            .order_by(model_objects.UniqueFQDNSet.id.asc())
            .first()
        )
        assert dbUniqueFQDNSet
        return dbUniqueFQDNSet

    @tests_routes(("admin:queue_certificate:new_structured",))
    def test_new_structured_html(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_QueueCertificate.test_new_structured_html
        """
        # TODO: test with objects that have issues
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/new/structured", status=303
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/queue-certificates?result=error&error=invalid+queue+source&operation=new-structured"
        )

        # try with an AcmeOrder
        dbAcmeOrder = self._get_queueable_AcmeOrder()
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/new/structured?queue_source=AcmeOrder&acme_order=%s"
            % dbAcmeOrder.id,
            status=200,
        )
        form = res.form
        res2 = form.submit()
        assert res2.status_code == 303
        matched = RE_QueueCertificate.match(res2.location)
        assert matched
        queue_id_1 = matched.groups()[0]

        # try with a ServerCertificate
        dbServerCertificate = self._get_queueable_ServerCertificate()
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/new/structured?queue_source=ServerCertificate&server_certificate=%s"
            % dbServerCertificate.id,
            status=200,
        )
        form = res.form
        res2 = form.submit()
        assert res2.status_code == 303
        matched = RE_QueueCertificate.match(res2.location)
        assert matched
        queue_id_2 = matched.groups()[0]

        # try with an UniqueFQDNSet
        dbUniqueFQDNSet = self._get_queueable_UniqueFQDNSet()
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/new/structured?queue_source=UniqueFQDNSet&unique_fqdn_set=%s"
            % dbUniqueFQDNSet.id,
            status=200,
        )
        form = res.form
        res2 = form.submit()
        assert res2.status_code == 303
        matched = RE_QueueCertificate.match(res2.location)
        assert matched
        queue_id_3 = matched.groups()[0]

    @tests_routes(("admin:queue_certificate:new_structured|json",))
    def test_new_structured_json(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_QueueCertificate.test_new_structured_json
        """
        # TODO: test with objects that have issues
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/new/structured.json", status=200
        )
        assert res.json["result"] == "error"
        assert res.json["error"] == "invalid queue source"

        # try with an AcmeOrder
        dbAcmeOrder = self._get_queueable_AcmeOrder()
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/new/structured.json?queue_source=AcmeOrder&acme_order=%s"
            % dbAcmeOrder.id,
            status=200,
        )
        assert "instructions" in res.json

        form = {
            "queue_source": "AcmeOrder",
            "acme_order": dbAcmeOrder.id,
            "account_key_option": "account_key_reuse",
            "account_key_reuse": dbAcmeOrder.acme_account.acme_account_key.key_pem_md5,
            "account__private_key_cycle": "single_certificate",
            "private_key_option": "private_key_for_account_key",
            "private_key_cycle__renewal": "account_key_default",
        }
        res = self.testapp.post(
            "/.well-known/admin/queue-certificate/new/structured.json",
            form,
            status=200,
        )
        assert res.json["result"] == "success"
        assert "QueueCertificate" in res.json
        queue_id_1 = res.json["QueueCertificate"]

        # try with a ServerCertificate
        dbServerCertificate = self._get_queueable_ServerCertificate()
        res_instructions = self.testapp.get(
            "/.well-known/admin/queue-certificate/new/structured.json?queue_source=ServerCertificate&server_certificate=%s"
            % dbServerCertificate.id,
            status=200,
        )
        account_key_global_default = res_instructions.json["valid_options"][
            "AcmeAccount_GlobalDefault"
        ]["AcmeAccountKey"]["key_pem_md5"]
        form = {
            "queue_source": "ServerCertificate",
            "server_certificate": dbServerCertificate.id,
            "account_key_option": "account_key_global_default",
            "account_key_global_default": account_key_global_default,
            "account__private_key_cycle": "single_certificate",
            "private_key_option": "private_key_for_account_key",
            "private_key_cycle__renewal": "account_key_default",
        }
        res = self.testapp.post(
            "/.well-known/admin/queue-certificate/new/structured.json",
            form,
            status=200,
        )
        assert res.json["result"] == "success"
        assert "QueueCertificate" in res.json
        queue_id_2 = res.json["QueueCertificate"]

        # try with an UniqueFQDNSet
        dbUniqueFQDNSet = self._get_queueable_UniqueFQDNSet()
        res_instructions = self.testapp.get(
            "/.well-known/admin/queue-certificate/new/structured.json?queue_source=UniqueFQDNSet&unique_fqdn_set=%s"
            % dbUniqueFQDNSet.id,
            status=200,
        )
        form = {
            "queue_source": "UniqueFQDNSet",
            "unique_fqdn_set": dbUniqueFQDNSet.id,
            "account_key_option": "account_key_global_default",
            "account_key_global_default": account_key_global_default,
            "account__private_key_cycle": "single_certificate",
            "private_key_option": "private_key_for_account_key",
            "private_key_cycle__renewal": "account_key_default",
        }
        res = self.testapp.post(
            "/.well-known/admin/queue-certificate/new/structured.json",
            form,
            status=200,
        )
        assert res.json["result"] == "success"
        assert "QueueCertificate" in res.json
        queue_id_3 = res.json["QueueCertificate"]

    @tests_routes(("admin:queue_certificate:new_freeform",))
    def test_new_freeform_html(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_QueueCertificate.test_new_freeform_html
        """
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/new/freeform", status=200
        )
        form = res.form
        form["domain_names"] = "test-new-freeform-html.example.com"
        res2 = form.submit()
        assert res2.status_code == 303
        matched = RE_QueueCertificate.match(res2.location)
        assert matched
        queue_id_1 = matched.groups()[0]

    @tests_routes(("admin:queue_certificate:new_freeform|json",))
    def test_new_freeform_json(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_QueueCertificate.test_new_freeform_json
        """
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/new/freeform.json", status=200
        )
        assert "instructions" in res.json

        res2 = self.testapp.post(
            "/.well-known/admin/queue-certificate/new/freeform.json", {}, status=200
        )
        assert res2.json["result"] == "error"
        assert "form_errors" in res2.json

        form = {}
        form["account_key_option"] = "account_key_global_default"
        account_key_global_default = res.json["valid_options"][
            "AcmeAccount_GlobalDefault"
        ]["AcmeAccountKey"]["key_pem_md5"]
        form["account_key_global_default"] = account_key_global_default
        form["account__private_key_cycle"] = "single_certificate"
        form["private_key_option"] = "private_key_for_account_key"
        form["private_key_cycle__renewal"] = "account_key_default"
        form["domain_names"] = "test-new-freeform-json.example.com"
        res3 = self.testapp.post(
            "/.well-known/admin/queue-certificate/new/freeform.json", form, status=200
        )
        assert res3.json["result"] == "success"
        assert "QueueCertificate" in res3.json
        queue_id_1 = res3.json["QueueCertificate"]


class FunctionalTests_QueueDomains(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_QueueDomains
    """

    def _get_one(self):
        # grab an item
        focus_item = (
            self.ctx.dbSession.query(model_objects.QueueDomain)
            .filter(model_objects.QueueDomain.is_active.op("IS")(True))
            .order_by(model_objects.QueueDomain.id.asc())
            .first()
        )
        return focus_item

    @tests_routes(
        (
            "admin:queue_domains",
            "admin:queue_domains_paginated",
            "admin:queue_domains:all",
            "admin:queue_domains:all_paginated",
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/queue-domains", status=200)
        res = self.testapp.get("/.well-known/admin/queue-domains/all", status=200)
        # paginated
        res = self.testapp.get("/.well-known/admin/queue-domains/1", status=200)
        res = self.testapp.get("/.well-known/admin/queue-domains/all/1", status=200)

    @tests_routes(
        (
            "admin:queue_domains|json",
            "admin:queue_domains_paginated|json",
            "admin:queue_domains:all|json",
            "admin:queue_domains:all_paginated|json",
        )
    )
    def test_list_json(self):
        # json root
        res = self.testapp.get("/.well-known/admin/queue-domains.json", status=200)
        res = self.testapp.get("/.well-known/admin/queue-domains/all.json", status=200)
        # json paginated
        res = self.testapp.get("/.well-known/admin/queue-domains/1.json", status=200)
        res = self.testapp.get(
            "/.well-known/admin/queue-domains/all/1.json", status=200
        )

    @tests_routes(("admin:queue_domains:add",))
    def test_add_html(self):
        res = self.testapp.get("/.well-known/admin/queue-domains/add", status=200)
        form = res.form
        form["domain_names"] = TEST_FILES["Domains"]["Queue"]["1"]["add"]
        res2 = form.submit()
        assert res2.status_code == 303
        assert (
            """http://peter-sslers.example.com/.well-known/admin/queue-domains?result=success"""
            in res2.location
        )

    @tests_routes(("admin:queue_domains:add|json",))
    def test_add_json(self):
        res = self.testapp.get("/.well-known/admin/queue-domains/add.json", status=200)
        _data = {"domain_names": TEST_FILES["Domains"]["Queue"]["1"]["add.json"]}
        res2 = self.testapp.post("/.well-known/admin/queue-domains/add.json", _data)
        assert res2.status_code == 200
        assert res2.json["result"] == "success"

    @tests_routes(("admin:queue_domain:focus",))
    def test_focus_html(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/queue-domain/%s" % focus_id, status=200
        )

    @tests_routes(("admin:queue_domain:focus|json",))
    def test_focus_json(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/queue-domain/%s.json" % focus_id, status=200
        )
        assert res.json["result"] == "success"
        assert "QueueDomain" in res.json

    @tests_routes(("admin:queue_domain:focus:mark",))
    def test_manipulate_html(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/queue-domain/%s/mark" % focus_id,
            {"action": "cancel"},
            status=303,
        )

        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/queue-domain/%s?result=error&error=post+required&operation=mark"
            % focus_id
        )

        res2 = self.testapp.post(
            "/.well-known/admin/queue-domain/%s/mark" % focus_id, {"action": "cancel"}
        )
        assert res2.status_code == 303
        assert (
            res2.location
            == "http://peter-sslers.example.com/.well-known/admin/queue-domain/%s?result=success&operation=mark&action=cancel"
            % focus_id
        )

        res3 = self.testapp.post(
            "/.well-known/admin/queue-domain/%s/mark" % focus_id, {"action": "cancel"}
        )
        assert res3.status_code == 303
        assert (
            res3.location
            == "http://peter-sslers.example.com/.well-known/admin/queue-domain/%s?result=error&error=action--Already+cancelledError_Main--There+was+an+error+with+your+form.&operation=mark&action=cancel"
            % focus_id
        )

    @tests_routes(("admin:queue_domain:focus:mark|json",))
    def test_manipulate_json(self):
        focus_item = self._get_one()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/queue-domain/%s/mark.json" % focus_id,
            {"action": "cancel"},
            status=200,
        )
        assert "form_fields" in res.json
        assert "instructions" in res.json

        # make this inactive
        res2 = self.testapp.post(
            "/.well-known/admin/queue-domain/%s/mark.json" % focus_id,
            {"action": "cancel"},
        )
        assert res2.status_code == 200
        assert res2.json["result"] == "success"
        assert "QueueDomain" in res2.json
        assert res2.json["QueueDomain"]["is_active"] is False

        # fail it inactive
        res3 = self.testapp.post(
            "/.well-known/admin/queue-domain/%s/mark.json" % focus_id,
            {"action": "cancel"},
        )
        assert res3.status_code == 200
        assert res3.json["result"] == "error"
        assert "form_errors" in res3.json
        assert res3.json["form_errors"]["action"] == "Already cancelled"


class FunctionalTests_AcmeServer(AppTest):
    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes("admin:acme_account:new")
    def test_AcmeAccount_new_html(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_AcmeAccount_new_html
        """

        res = self.testapp.get("/.well-known/admin/acme-account/new", status=200)
        form = res.form
        form["acme_account_provider_id"].force_value(
            str(1)
        )  # acme_account_provider_id(1) == pebble
        res2 = form.submit()
        assert res2.status_code == 200
        assert "There was an error with your form." in res2.text
        assert "Please enter an email address" in res2.text

        form = res2.form
        form["account__contact"].force_value("AcmeAccount.new.html@example.com")
        res2 = form.submit()
        assert res2.status_code == 303
        re_expected = re.compile(
            r"""^http://peter-sslers\.example\.com/\.well-known/admin/acme-account/(\d+)\?result=success&operation=new&is_created=1$"""
        )
        matched = re_expected.match(res2.location)
        assert matched
        obj_id = matched.groups()[0]

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes("admin:acme_account:new|json")
    def test_AcmeAccount_new_json(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_AcmeAccount_new_json
        """
        res = self.testapp.get("/.well-known/admin/acme-account/new.json", status=200)
        assert "form_fields" in res.json
        assert "instructions" in res.json

        form = {}
        res2 = self.testapp.post("/.well-known/admin/acme-account/new.json", form)
        assert res2.json["result"] == "error"
        assert "form_errors" in res2.json
        assert isinstance(res2.json["form_errors"], dict)
        assert len(res2.json["form_errors"]) == 1
        assert res2.json["form_errors"]["Error_Main"] == "Nothing submitted."

        form = {
            "acme_account_provider_id": 1,
            "account__contact": "AcmeAccount.new.json@example.com",
            "account__private_key_cycle": "single_certificate",
        }
        res3 = self.testapp.post("/.well-known/admin/acme-account/new.json", form)
        assert res3.json["result"] == "success"
        assert "AcmeAccount" in res3.json
        return True

    def _get_one_AcmeAccount(self):
        # grab an item
        focus_item = (
            self.ctx.dbSession.query(model_objects.AcmeAccount)
            .filter(model_objects.AcmeAccount.is_active.op("IS")(True))
            .filter(model_objects.AcmeAccount.acme_account_provider_id == 1)
            .order_by(model_objects.AcmeAccount.id.asc())
            .first()
        )
        return focus_item

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes("admin:acme_account:focus:acme_server:authenticate")
    def test_AcmeAccount_authenticate_html(self):
        """
        # this hits Pebble via http
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_AcmeAccount_authenticate_html
        """
        focus_item = self._get_one_AcmeAccount()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/acme-server/authenticate" % focus_id,
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/acme-account/%s?result=error&error=post+required&operation=acme-server--authenticate"
            % focus_id
        )

        res = self.testapp.post(
            "/.well-known/admin/acme-account/%s/acme-server/authenticate" % focus_id,
            {},
        )
        assert (
            res.location
            == """http://peter-sslers.example.com/.well-known/admin/acme-account/%s?result=success&operation=acme-server--authenticate&is_authenticated=True"""
            % focus_id
        )

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes("admin:acme_account:focus:acme_server:authenticate|json")
    def test_AcmeAccount_authenticate_json(self):
        """
        # this hits Pebble via http
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_AcmeAccount_authenticate_json
        """
        focus_item = self._get_one_AcmeAccount()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/acme-server/authenticate.json"
            % focus_id,
            status=200,
        )
        assert res.location is None  # no redirect
        assert "instructions" in res.json

        res = self.testapp.post(
            "/.well-known/admin/acme-account/%s/acme-server/authenticate.json"
            % focus_id,
            {},
        )
        assert res.status_code == 200
        assert res.location is None  # no redirect
        assert "AcmeAccount" in res.json

    @tests_routes(
        (
            "admin:acme_order:new:freeform",
            "admin:acme_order:focus|json",
            "admin:acme_account:focus",
            "admin:acme_account:focus:acme_authorizations",
            "admin:acme_account:focus:acme_authorizations|json",
        )
    )
    def _prep__AcmeAccount_deactivate_pending_authorizations(self):
        """
        shared routine
        this runs `@under_pebble`, but the invoking function should wrap it
        """
        _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]
        # we need two for this test
        assert len(_test_data["acme-order/new/freeform#1"]["domain_names"]) == 2

        # "admin:acme_order:new:freeform",
        res = self.testapp.get("/.well-known/admin/acme-order/new/freeform", status=200)
        form = res.form
        _form_fields = form.fields.keys()
        assert "account_key_option" in _form_fields
        form["account_key_option"].force_value("account_key_file")
        form["acme_account_provider_id"].force_value("1")
        form["account_key_file_pem"] = Upload(
            self._filepath_testfile(
                _test_data["acme-order/new/freeform#1"]["account_key_file_pem"]
            )
        )
        form["account__contact"] = _test_data["acme-order/new/freeform#1"][
            "account__contact"
        ]
        form["account__private_key_cycle"].force_value("account_daily")
        form["private_key_cycle__renewal"].force_value("account_key_default")
        form["private_key_option"].force_value("private_key_for_account_key")
        form["domain_names"] = ",".join(
            _test_data["acme-order/new/freeform#1"]["domain_names"]
        )
        form["processing_strategy"].force_value("create_order")
        res2 = form.submit()
        assert res2.status_code == 303

        matched = RE_AcmeOrder.match(res2.location)
        assert matched
        obj_id = matched.groups()[0]

        # "admin:acme_order:focus|json",
        res = self.testapp.get("%s.json" % res2.location, status=200)
        assert "AcmeOrder" in res.json
        acme_account_id = res.json["AcmeOrder"]["AcmeAccount"]["id"]
        assert acme_account_id

        # admin:acme_account:focus
        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s" % acme_account_id, status=200
        )

        return acme_account_id

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(
        (
            "admin:acme_account:focus:acme_server:deactivate_pending_authorizations",  # real test
        )
    )
    def test_AcmeAccount_deactivate_pending_authorizations_html(self):
        """
        # this hits Pebble via http
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_AcmeAccount_deactivate_pending_authorizations_html
        """
        acme_account_id = self._prep__AcmeAccount_deactivate_pending_authorizations()

        # get - fail!
        res_bad = self.testapp.get(
            "/.well-known/admin/acme-account/%s/acme-server/deactivate-pending-authorizations"
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
            "/.well-known/admin/acme-account/%s/acme-authorizations" % acme_account_id,
            status=200,
        )
        res2 = self.testapp.get(
            "/.well-known/admin/acme-account/%s/acme-authorizations.json"
            % acme_account_id,
            status=200,
        )
        acme_authorization_ids = [
            i["id"]
            for i in res2.json["AcmeAuthorizations"]
            if i["acme_status_authorization"]
            in model_utils.Acme_Status_Authorization.OPTIONS_DEACTIVATE
        ]
        assert len(acme_authorization_ids) == 2
        form = res.form
        form["acme_authorization_id"] = acme_authorization_ids
        res3 = form.submit()

        assert res3.status_code == 303
        matched = RE_AcmeAccount_deactivate_pending_success.match(res3.location)

        res4 = self.testapp.get(
            "/.well-known/admin/acme-account/%s/acme-authorizations.json"
            % acme_account_id,
            status=200,
        )
        acme_authorization_ids_2 = [
            i["id"]
            for i in res4.json["AcmeAuthorizations"]
            if i["acme_status_authorization"]
            in model_utils.Acme_Status_Authorization.OPTIONS_DEACTIVATE
        ]
        assert len(acme_authorization_ids_2) == 0

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(
        (
            "admin:acme_account:focus:acme_server:deactivate_pending_authorizations|json",  # real test
        )
    )
    def test_AcmeAccount_deactivate_pending_authorizations_json(self):
        """
        # this hits Pebble via http
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_AcmeAccount_deactivate_pending_authorizations_json
        """
        acme_account_id = self._prep__AcmeAccount_deactivate_pending_authorizations()

        # get - fail!
        res_bad = self.testapp.get(
            "/.well-known/admin/acme-account/%s/acme-server/deactivate-pending-authorizations.json"
            % acme_account_id,
            status=200,
        )
        assert "instructions" in res_bad.json

        # use the JSON route to grab authorization ids for our form
        # admin:acme_account:focus:acme_authorizations
        res2 = self.testapp.get(
            "/.well-known/admin/acme-account/%s/acme-authorizations.json"
            % acme_account_id,
            status=200,
        )
        acme_authorization_ids = [
            i["id"]
            for i in res2.json["AcmeAuthorizations"]
            if i["acme_status_authorization"]
            in model_utils.Acme_Status_Authorization.OPTIONS_DEACTIVATE
        ]
        assert len(acme_authorization_ids) == 2

        post_data = [
            ("acme_authorization_id", acme_authorization_id)
            for acme_authorization_id in acme_authorization_ids
        ]
        res3 = self.testapp.post(
            "/.well-known/admin/acme-account/%s/acme-server/deactivate-pending-authorizations.json"
            % acme_account_id,
            post_data,
        )
        assert res3.status_code == 200

        res4 = self.testapp.get(
            "/.well-known/admin/acme-account/%s/acme-authorizations.json"
            % acme_account_id,
            status=200,
        )
        acme_authorization_ids_2 = [
            i["id"]
            for i in res4.json["AcmeAuthorizations"]
            if i["acme_status_authorization"]
            in model_utils.Acme_Status_Authorization.OPTIONS_DEACTIVATE
        ]
        assert len(acme_authorization_ids_2) == 0

    @tests_routes(("admin:acme_order:new:freeform",))
    def _prep_AcmeOrder_html(self, processing_strategy=None):
        """
        this runs `@under_pebble`, but the invoking function should wrap it
        """
        _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]

        # we need two for this test
        assert len(_test_data["acme-order/new/freeform#1"]["domain_names"]) == 2

        # "admin:acme_order:new:freeform",
        res = self.testapp.get("/.well-known/admin/acme-order/new/freeform", status=200)

        form = res.form
        _form_fields = form.fields.keys()
        assert "account_key_option" in _form_fields
        form["account_key_option"].force_value("account_key_file")
        form["acme_account_provider_id"].force_value("1")
        form["account_key_file_pem"] = Upload(
            self._filepath_testfile(
                _test_data["acme-order/new/freeform#1"]["account_key_file_pem"]
            )
        )
        form["account__contact"] = _test_data["acme-order/new/freeform#1"][
            "account__contact"
        ]
        form["account__private_key_cycle"].force_value("account_daily")
        form["private_key_cycle__renewal"].force_value("account_key_default")
        form["private_key_option"].force_value("private_key_for_account_key")
        form["domain_names"] = ",".join(
            _test_data["acme-order/new/freeform#1"]["domain_names"]
        )
        if processing_strategy is None:
            processing_strategy = "create_order"
        form["processing_strategy"].force_value(processing_strategy)
        res2 = form.submit()
        assert res2.status_code == 303

        # "admin:acme_order:focus",
        matched = RE_AcmeOrder.match(res2.location)
        assert matched
        obj_id = matched.groups()[0]

        return (obj_id, res2.location)

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(
        (
            "admin:acme_order:new:freeform",
            "admin:acme_order:focus",
            "admin:acme_order:focus:acme_server:sync",
            "admin:acme_order:focus:acme_server:sync_authorizations",
            "admin:acme_authorization:focus",
            "admin:acme_authorization:focus:acme_server:sync",
            "admin:acme_authorization:focus:acme_server:trigger",
            "admin:acme_challenge:focus",
            "admin:acme_challenge:focus:acme_server:sync",
            "admin:acme_challenge:focus:acme_server:trigger",
            "admin:acme_order:focus:finalize",
            "admin:acme_order:focus:renew:custom",
            "admin:acme_order:focus:renew:quick",
            "admin:acme_order:focus:acme_server:deactivate_authorizations",
        )
    )
    def test_AcmeOrder_extended_html(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_AcmeOrder_extended_html

        NOTE: if domains are not randomized for the order, one needs to reset the pebble instance
        NOTE^^^ this now runs with it's own pebble instance
        """
        _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]

        (obj_id, obj_url) = self._prep_AcmeOrder_html()

        # /acme-order
        res = self.testapp.get(obj_url, status=200)

        # "admin:acme_order:focus:acme_server:sync",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-server/sync" % obj_id, status=303
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=success&operation=acme+server+sync"
            % obj_id
        )

        # "admin:acme_order:focus:acme_server:sync_authorizations",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-server/sync-authorizations" % obj_id,
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=success&operation=acme+server+sync+authorizations"
            % obj_id
        )

        _dbAcmeOrder = self.ctx.dbSession.query(model_objects.AcmeOrder).get(obj_id)
        assert len(_dbAcmeOrder.acme_authorizations) == len(
            _test_data["acme-order/new/freeform#1"]["domain_names"]
        )
        _authorization_pairs = [
            (i.id, i.acme_challenge_http01.id) for i in _dbAcmeOrder.acme_authorizations
        ]
        self.ctx.dbSession.rollback()

        assert len(_authorization_pairs) == 2

        # AuthPair 1
        (auth_id_1, challenge_id_1) = _authorization_pairs[0]

        # "admin:acme_authorization:focus",
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s" % auth_id_1, status=200
        )
        # "admin:acme_authorization:focus:sync"
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/sync" % auth_id_1,
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-authorization/%s?result=success&operation=acme+server+sync"
            % auth_id_1
        )

        # "admin:acme_authorization:focus:trigger"
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/trigger" % auth_id_1,
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-authorization/%s?result=success&operation=acme+server+trigger"
            % auth_id_1
        )

        # "admin:acme_authorization:focus:trigger" AGAIN
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/trigger" % auth_id_1,
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-authorization/%s?result=error&error=ACME+Server+Trigger+is+not+allowed+for+this+AcmeAuthorization&operation=acme+server+trigger"
            % auth_id_1
        )

        # AuthPair 2
        (auth_id_2, challenge_id_2) = _authorization_pairs[1]

        # "admin:acme_challenge:focus",
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge/%s" % challenge_id_2, status=200
        )

        # "admin:acme_challenge:focus:acme_server:sync",
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge/%s/acme-server/sync" % challenge_id_2,
            status=303,
        )
        # "admin:acme_challenge:focus:acme_server:trigger",
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge/%s/acme-server/trigger" % challenge_id_2,
            status=303,
        )

        # "admin:acme_authorization:focus:sync"
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/sync" % auth_id_2,
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-authorization/%s?result=success&operation=acme+server+sync"
            % auth_id_2
        )

        # now go back to the order
        res = self.testapp.get("/.well-known/admin/acme-order/%s" % obj_id, status=200,)
        assert (
            """<td><span class="label label-default">processing_started</span></td>"""
            in res.text
        )

        # "admin:acme_order:focus:acme_server:sync",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-server/sync" % obj_id, status=303
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=success&operation=acme+server+sync"
            % obj_id
        )

        # "admin:acme_order:focus:finalize",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/finalize" % obj_id, status=303
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=success&operation=finalize+order"
            % obj_id
        )

        # now go back to the order
        res = self.testapp.get("/.well-known/admin/acme-order/%s" % obj_id, status=200,)
        assert (
            """<td><span class="label label-default">certificate_downloaded</span></td>"""
            in res.text
        )

        # "admin:acme_order:focus:renew:quick",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/renew/quick" % obj_id, status=200
        )
        form = res.form
        form["processing_strategy"].force_value("process_multi")
        res2 = form.submit()
        assert res2.status_code == 303

        re_expected = re.compile(
            r"""^http://peter-sslers\.example\.com/\.well-known/admin/acme-order/(\d+)\?result=success&operation=renew\+quick$"""
        )
        matched = re_expected.match(res2.location)
        assert matched
        obj_id__quick = matched.groups()[0]

        # "admin:acme_order:focus",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s" % obj_id__quick, status=200
        )
        # "admin:acme_order:focus:acme_server:sync",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-server/sync" % obj_id__quick,
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=success&operation=acme+server+sync"
            % obj_id__quick
        )
        # "admin:acme_order:focus",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s" % obj_id__quick, status=200
        )

        # IMPORTANT
        # pebble re-uses the authorizations
        # so we can either "process" or "finalize" here

        # let's call finalize
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/finalize" % obj_id__quick, status=303
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=success&operation=finalize+order"
            % obj_id__quick
        )

        # "admin:acme_order:focus",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s" % obj_id__quick, status=200
        )

        # "admin:acme_order:focus:renew:custom"
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/renew/custom" % obj_id__quick, status=200
        )
        form = res.form
        # we can just change the `processing_strategy`
        form["processing_strategy"].force_value("process_multi")
        res2 = form.submit()
        assert res2.status_code == 303

        re_expected = re.compile(
            r"""^http://peter-sslers\.example\.com/\.well-known/admin/acme-order/(\d+)\?result=success&operation=renew\+custom$"""
        )
        matched = re_expected.match(res2.location)
        assert matched
        obj_id__custom = matched.groups()[0]

        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-server/sync" % obj_id__custom,
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=success&operation=acme+server+sync"
            % obj_id__custom
        )
        # "admin:acme_order:focus",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s" % obj_id__custom, status=200
        )

        #
        # to handle the next series, we must use a new order with different domains
        #

        # we need two for this test
        assert len(_test_data["acme-order/new/freeform#2"]["domain_names"]) == 2
        # "admin:acme_order:new:freeform",
        res = self.testapp.get("/.well-known/admin/acme-order/new/freeform", status=200)

        form = res.form
        _form_fields = form.fields.keys()
        assert "account_key_option" in _form_fields
        form["account_key_option"].force_value("account_key_file")
        form["acme_account_provider_id"].force_value("1")
        form["account_key_file_pem"] = Upload(
            self._filepath_testfile(
                _test_data["acme-order/new/freeform#2"]["account_key_file_pem"]
            )
        )
        form["account__contact"] = _test_data["acme-order/new/freeform#2"][
            "account__contact"
        ]
        form["account__private_key_cycle"].force_value("account_daily")
        form["private_key_cycle__renewal"].force_value("account_key_default")
        form["private_key_option"].force_value("private_key_for_account_key")
        form["domain_names"] = ",".join(
            _test_data["acme-order/new/freeform#2"]["domain_names"]
        )
        form["processing_strategy"].force_value("create_order")
        res2 = form.submit()
        assert res2.status_code == 303

        # "admin:acme_order:focus",
        matched = RE_AcmeOrder.match(res2.location)
        assert matched
        obj_id__2 = matched.groups()[0]

        # grab the order
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s" % obj_id__2, status=200
        )

        # sync_authorizations
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-server/sync-authorizations"
            % obj_id__2,
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=success&operation=acme+server+sync+authorizations"
            % obj_id__2
        )

        # grab the order
        # look for deactivate-authorizations
        # note the space after `btn-info ` and no `disabled` class
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s" % obj_id__2, status=200
        )
        re_expected = re.compile(
            r'''href="/\.well-known/admin/acme-order/%s/acme-server/deactivate-authorizations"[\n\s\ ]+class="btn btn-xs btn-info "'''
            % obj_id__2
        )
        assert re_expected.findall(res.text)

        # "admin:acme_order:focus:acme_server:deactivate_authorizations",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-server/deactivate-authorizations"
            % obj_id__2,
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=success&operation=acme+server+deactivate+authorizations"
            % obj_id__2
        )

        # grab the order
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s" % obj_id__2, status=200
        )
        # look for deactivate-authorizations
        # note the `disabled` class
        re_expected = re.compile(
            r'''href="/\.well-known/admin/acme-order/\d+/acme-server/deactivate-authorizations"[\n\s\ ]+class="btn btn-xs btn-info disabled"'''
        )
        assert re_expected.findall(res.text)

        # "admin:acme_order:focus:retry",
        assert "acme_order-retry" in res.forms
        form = res.forms["acme_order-retry"]
        res = form.submit()
        assert res.status_code == 303

        matched = RE_AcmeOrder_retry.match(res.location)
        assert matched
        obj_id__3 = matched.groups()[0]

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(
        (
            "admin:acme_order:new:freeform",
            "admin:acme_order:focus",
            "admin:acme_order:focus:retry",
            "admin:acme_order:focus:mark",
        )
    )
    def test_AcmeOrder_mark_html(self):
        (obj_id, obj_url) = self._prep_AcmeOrder_html()

        # grab the order
        res = self.testapp.get("/.well-known/admin/acme-order/%s" % obj_id, status=200)

        # "mark" deactivate
        assert (
            'href="/.well-known/admin/acme-order/%s/mark?action=deactivate"' % obj_id
            in res.text
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/mark?action=deactivate" % obj_id,
            status=303,
        )
        matched = RE_AcmeOrder_deactivated.match(res.location)
        assert matched

        # grab the order
        res = self.testapp.get("/.well-known/admin/acme-order/%s" % obj_id, status=200)

        # "mark" invalid
        assert (
            'href="/.well-known/admin/acme-order/%s/mark?action=invalid"' % obj_id
            in res.text
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/mark?action=invalid" % obj_id, status=303,
        )
        matched = RE_AcmeOrder_invalidated.match(res.location)
        assert matched

        # grab the order
        res = self.testapp.get("/.well-known/admin/acme-order/%s" % obj_id, status=200)

        # "admin:acme_order:focus:retry",
        assert "acme_order-retry" in res.forms
        form = res.forms["acme_order-retry"]
        res = form.submit()
        assert res.status_code == 303

        matched = RE_AcmeOrder_retry.match(res.location)
        assert matched
        obj_id__4 = matched.groups()[0]

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(("admin:acme_order:new:freeform", "admin:acme_order:focus",))
    def test_AcmeOrder_process_single_html(self):
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

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(
        (
            "admin:acme_order:new:freeform",
            "admin:acme_order:focus",
            "admin:acme_order:focus:acme_process",
        )
    )
    def test_AcmeOrder_process_multi_html(self):
        (obj_id, obj_url) = self._prep_AcmeOrder_html(
            processing_strategy="process_multi"
        )

        # /acme-order
        res = self.testapp.get(obj_url, status=200)
        assert RE_AcmeOrder_can_process.findall(res.text)

        process_url = "/.well-known/admin/acme-order/%s/acme-process" % obj_id

        # get the first process
        res = self.testapp.get(process_url, status=303)
        assert RE_AcmeOrder_processed.match(res.location)

        # get the order again, then the second process
        res = self.testapp.get(obj_url, status=200)
        assert RE_AcmeOrder_can_process.findall(res.text)
        res_p = self.testapp.get(process_url, status=303)
        assert RE_AcmeOrder_processed.match(res_p.location)

        # get the order again, then the third process
        res = self.testapp.get(obj_url, status=200)
        assert RE_AcmeOrder_can_process.findall(res.text)
        res_p = self.testapp.get(process_url, status=303)
        assert RE_AcmeOrder_processed.match(res_p.location)

        # get the order again, it should be done
        res = self.testapp.get(obj_url, status=200)
        assert not RE_AcmeOrder_can_process.findall(res.text)
        assert "<td><code>valid</code>" in res.text
        assert (
            """<td><span class="label label-default">certificate_downloaded</span></td>"""
            in res.text
        )

    @tests_routes(("admin:acme_order:new:freeform|json",))
    def _prep_AcmeOrder_json(self, processing_strategy=None):
        """
        this runs `@under_pebble`, but the invoking function should wrap it
        """
        _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]

        # we need two for this test
        assert len(_test_data["acme-order/new/freeform#1"]["domain_names"]) == 2

        # "admin:acme_order:new:freeform",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/new/freeform.json", status=200
        )
        assert "instructions" in res.json

        form = {}
        form["account_key_option"] = "account_key_file"
        form["acme_account_provider_id"] = "1"
        form["account_key_file_pem"] = Upload(
            self._filepath_testfile(
                _test_data["acme-order/new/freeform#1"]["account_key_file_pem"]
            )
        )
        form["account__contact"] = _test_data["acme-order/new/freeform#1"][
            "account__contact"
        ]
        form["account__private_key_cycle"] = "account_daily"
        form["private_key_cycle__renewal"] = "account_key_default"
        form["private_key_option"] = "private_key_for_account_key"
        form["domain_names"] = ",".join(
            _test_data["acme-order/new/freeform#1"]["domain_names"]
        )
        if processing_strategy is None:
            processing_strategy = "create_order"
        form["processing_strategy"] = processing_strategy

        res2 = self.testapp.post(
            "/.well-known/admin/acme-order/new/freeform.json", form
        )
        assert res2.status_code == 200
        assert "AcmeOrder" in res2.json
        obj_id = res2.json["AcmeOrder"]["id"]

        return obj_id

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(
        (
            "admin:acme_order:new:freeform|json",
            "admin:acme_order:focus|json",
            "admin:acme_order:focus:acme_server:sync|json",
            "admin:acme_order:focus:acme_server:sync_authorizations|json",
            "admin:acme_authorization:focus|json",
            "admin:acme_authorization:focus:acme_server:sync|json",
            "admin:acme_authorization:focus:acme_server:trigger|json",
            "admin:acme_challenge:focus|json",
            "admin:acme_challenge:focus:acme_server:sync|json",
            "admin:acme_challenge:focus:acme_server:trigger|json",
            "admin:acme_order:focus:finalize|json",
            "admin:acme_order:focus:renew:custom|json",
            "admin:acme_order:focus:renew:quick|json",
            "admin:acme_order:focus:acme_server:deactivate_authorizations|json",
        )
    )
    def test_AcmeOrder_extended_json(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_AcmeOrder_extended_json

        NOTE: if domains are not randomized for the order, one needs to reset the pebble instance
        NOTE^^^ this now runs with it's own pebble instance
        """
        _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]

        obj_id = self._prep_AcmeOrder_json()

        # "admin:acme_order:focus|json",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % obj_id, status=200
        )
        assert "AcmeOrder" in res.json

        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-server/sync.json" % obj_id,
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync"

        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-server/sync-authorizations.json"
            % obj_id,
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync-authorizations"

        _dbAcmeOrder = self.ctx.dbSession.query(model_objects.AcmeOrder).get(obj_id)
        assert len(_dbAcmeOrder.acme_authorizations) == len(
            _test_data["acme-order/new/freeform#1"]["domain_names"]
        )
        _authorization_pairs = [
            (i.id, i.acme_challenge_http01.id) for i in _dbAcmeOrder.acme_authorizations
        ]
        self.ctx.dbSession.rollback()
        assert len(_authorization_pairs) == 2

        # AuthPair 1
        (auth_id_1, challenge_id_1) = _authorization_pairs[0]

        # "admin:acme_authorization:focus|json",
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s.json" % auth_id_1, status=200
        )
        assert "AcmeAuthorization" in res.json

        # "admin:acme_authorization:focus:sync|json"
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/sync.json"
            % auth_id_1,
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync"

        # "admin:acme_authorization:focus:trigger|json"
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/trigger.json"
            % auth_id_1,
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/trigger"

        # "admin:acme_authorization:focus:trigger|json" AGAIN
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/trigger.json"
            % auth_id_1,
            status=200,
        )
        assert res.json["result"] == "error"
        assert res.json["operation"] == "acme-server/trigger"
        assert (
            res.json["error"]
            == "ACME Server Trigger is not allowed for this AcmeAuthorization"
        )

        # AuthPair 2
        (auth_id_2, challenge_id_2) = _authorization_pairs[1]

        # "admin:acme_challenge:focus|json"
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge/%s.json" % challenge_id_2, status=200
        )
        assert "AcmeChallenge" in res.json

        # "admin:acme_challenge:focus:acme_server:sync|json",
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge/%s/acme-server/sync.json"
            % challenge_id_2,
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync"

        # "admin:acme_challenge:focus:acme_server:trigger|json",
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge/%s/acme-server/trigger.json"
            % challenge_id_2,
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/trigger"

        # "admin:acme_authorization:focus:sync|json"
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/sync.json"
            % auth_id_2,
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync"

        # now go back to the order
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % obj_id, status=200,
        )
        assert "AcmeOrder" in res.json
        assert (
            res.json["AcmeOrder"]["acme_order_processing_status"]
            == "processing_started"
        )

        # "admin:acme_order:focus:acme_server:sync|json",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-server/sync.json" % obj_id,
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync"

        # "admin:acme_order:focus:finalize|json",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/finalize.json" % obj_id, status=200
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "finalize-order"

        # now go back to the order
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % obj_id, status=200,
        )
        assert "AcmeOrder" in res.json
        assert (
            res.json["AcmeOrder"]["acme_order_processing_status"]
            == "certificate_downloaded"
        )

        # "admin:acme_order:focus:renew:quick|json",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/renew/quick.json" % obj_id, status=200,
        )
        assert "instructions" in res.json

        form = {"processing_strategy": "process_multi"}
        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/renew/quick.json" % obj_id,
            form,
            status=200,
        )
        assert res.json["result"] == "success"
        assert "AcmeOrder" in res.json
        obj_id__quick = res.json["AcmeOrder"]["id"]

        # "admin:acme_order:focus|json",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % obj_id__quick, status=200
        )
        assert "AcmeOrder" in res.json

        # "admin:acme_order:focus:acme_server:sync|json",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-server/sync.json" % obj_id__quick,
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync"

        # "admin:acme_order:focus|json",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % obj_id__quick, status=200
        )
        assert "AcmeOrder" in res.json

        # IMPORTANT
        # pebble re-uses the authorizations
        # so we can either "process" or "finalize" here

        # let's call finalize
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/finalize.json" % obj_id__quick, status=200
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "finalize-order"

        # "admin:acme_order:focus|json",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % obj_id__quick, status=200
        )
        assert "AcmeOrder" in res.json
        account_key_reuse = res.json["AcmeOrder"]["AcmeAccount"]["key_pem_md5"]
        private_key_reuse = res.json["AcmeOrder"]["PrivateKey"]["key_pem_md5"]

        # "admin:acme_order:focus:renew:custom"
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/renew/custom.json" % obj_id__quick,
            status=200,
        )
        assert "instructions" in res.json

        form = {}
        form["processing_strategy"] = "process_multi"
        form["account_key_option"] = "account_key_reuse"
        form["account_key_reuse"] = account_key_reuse
        form["account__private_key_cycle"] = "single_certificate"
        form["private_key_option"] = "private_key_reuse"
        form["private_key_reuse"] = private_key_reuse
        form["private_key_cycle__renewal"] = "account_key_default"
        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/renew/custom.json" % obj_id__quick,
            form,
            status=200,
        )
        assert res.json["result"] == "success"
        assert "AcmeOrder" in res.json
        obj_id__custom = res.json["AcmeOrder"]["id"]

        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-server/sync.json" % obj_id__custom,
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync"

        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % obj_id__custom, status=200
        )
        assert "AcmeOrder" in res.json

        #
        # to handle the next series, we must use a new order with different domains
        #

        # we need two for this test
        assert len(_test_data["acme-order/new/freeform#2"]["domain_names"]) == 2

        # "admin:acme_order:new:freeform",
        form = {}
        form["account_key_option"] = "account_key_file"
        form["acme_account_provider_id"] = "1"
        form["account_key_file_pem"] = Upload(
            self._filepath_testfile(
                _test_data["acme-order/new/freeform#2"]["account_key_file_pem"]
            )
        )
        form["account__contact"] = _test_data["acme-order/new/freeform#2"][
            "account__contact"
        ]
        form["account__private_key_cycle"] = "account_daily"
        form["private_key_cycle__renewal"] = "account_key_default"
        form["private_key_option"] = "private_key_for_account_key"
        form["domain_names"] = ",".join(
            _test_data["acme-order/new/freeform#2"]["domain_names"]
        )
        form["processing_strategy"] = "create_order"

        res2 = self.testapp.post(
            "/.well-known/admin/acme-order/new/freeform.json", form
        )
        assert res2.status_code == 200
        assert "AcmeOrder" in res2.json
        obj_id__2 = res2.json["AcmeOrder"]["id"]

        # grab the order
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % obj_id__2, status=200
        )
        assert "AcmeOrder" in res.json

        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-server/sync-authorizations.json"
            % obj_id__2,
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync-authorizations"

        # grab the order
        # look for deactivate-authorizations, ENABLED
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % obj_id__2, status=200
        )
        assert "AcmeOrder" in res.json
        assert (
            res.json["AcmeOrder"]["is_can_acme_server_deactivate_authorizations"]
            is True
        )

        # "admin:acme_order:focus:acme_server:deactivate_authorizations",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-server/deactivate-authorizations.json"
            % obj_id__2,
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/deactivate-authorizations"

        # grab the order
        # look for deactivate-authorizations, DISABLED
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % obj_id__2, status=200
        )
        assert "AcmeOrder" in res.json
        assert (
            res.json["AcmeOrder"]["is_can_acme_server_deactivate_authorizations"]
            is False
        )

        # "admin:acme_order:focus:retry",
        assert res.json["AcmeOrder"]["is_can_retry"] is True
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/retry.json" % obj_id__2, status=200
        )
        assert res.json["result"] == "error"
        assert res.json["error"] == "This must be a POST request."

        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/retry.json" % obj_id__2, {}, status=200
        )
        assert res.json["result"] == "success"
        assert "AcmeOrder" in res.json
        obj_id__3 = res.json["AcmeOrder"]["id"]

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(
        (
            "admin:acme_order:new:freeform|json",
            "admin:acme_order:focus|json",
            "admin:acme_order:focus:retry|json",
            "admin:acme_order:focus:mark|json",
        )
    )
    def test_AcmeOrder_mark_json(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_AcmeOrder_mark_json
        """

        obj_id = self._prep_AcmeOrder_json()

        # grab the order
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % obj_id, status=200
        )
        assert "AcmeOrder" in res.json

        # "mark" deactivate
        assert res.json["AcmeOrder"]["is_processing"]
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/mark.json?action=deactivate" % obj_id,
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "mark"
        assert res.json["action"] == "deactivate"

        # grab the order
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % obj_id, status=200
        )
        assert "AcmeOrder" in res.json

        # "mark" invalid
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/mark.json?action=invalid" % obj_id,
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "mark"
        assert res.json["action"] == "invalid"

        # grab the order
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % obj_id, status=200
        )
        assert "AcmeOrder" in res.json

        # "admin:acme_order:focus:retry",
        assert "AcmeOrder" in res.json

        assert res.json["AcmeOrder"]["is_can_retry"] is True
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/retry.json" % obj_id, status=200
        )
        assert res.json["result"] == "error"
        assert res.json["error"] == "This must be a POST request."

        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/retry.json" % obj_id, {}, status=200
        )
        assert res.json["result"] == "success"
        assert "AcmeOrder" in res.json
        obj_id__4 = res.json["AcmeOrder"]["id"]

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(
        ("admin:acme_order:new:freeform|json", "admin:acme_order:focus|json",)
    )
    def test_AcmeOrder_process_single_json(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_AcmeOrder_process_single_json
        """
        obj_id = self._prep_AcmeOrder_json(processing_strategy="process_single")

        # /acme-order
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % obj_id, status=200
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

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(
        (
            "admin:acme_order:new:freeform|json",
            "admin:acme_order:focus|json",
            "admin:acme_order:focus:acme_process|json",
        )
    )
    def test_AcmeOrder_process_multi_json(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_AcmeOrder_process_multi_json
        """
        obj_id = self._prep_AcmeOrder_json(processing_strategy="process_multi")

        # /acme-order
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % obj_id, status=200
        )
        assert "AcmeOrder" in res.json
        assert (
            res.json["AcmeOrder"]["acme_order_processing_strategy"] == "process_multi"
        )
        assert res.json["AcmeOrder"]["is_can_acme_process"] is True

        process_url = "/.well-known/admin/acme-order/%s/acme-process.json" % obj_id

        # get the first process
        res = self.testapp.get(process_url, status=200)
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-process"
        assert "AcmeOrder" in res.json
        assert res.json["AcmeOrder"]["is_can_acme_process"] is True

        # get the second process
        res = self.testapp.get(process_url, status=200)
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-process"
        assert "AcmeOrder" in res.json
        assert res.json["AcmeOrder"]["is_can_acme_process"] is True

        # get the third process
        res = self.testapp.get(process_url, status=200)
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-process"
        assert "AcmeOrder" in res.json
        assert res.json["AcmeOrder"]["is_can_acme_process"] is False
        assert res.json["AcmeOrder"]["acme_status_order"] == "valid"
        assert (
            res.json["AcmeOrder"]["acme_order_processing_status"]
            == "certificate_downloaded"
        )

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(
        (
            # "admin:acme_order:focus|json",
            "admin:acme_authorization:focus",
            "admin:acme_authorization:focus:acme_server:deactivate",
            "admin:acme_authorization:focus:acme_server:sync",
            "admin:acme_authorization:focus:acme_server:trigger",
        )
    )
    def test_AcmeAuthorization_manipulate_html(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_AcmeAuthorization_manipulate_html
        """
        (order_id, order_url) = self._prep_AcmeOrder_html()

        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % order_id, status=200
        )
        assert "AcmeOrder" in res.json
        acme_authorization_ids = res.json["AcmeOrder"]["acme_authorization_ids"]
        assert len(acme_authorization_ids) == 2

        # for #1, we deactivate then sync
        id_ = acme_authorization_ids[0]
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s" % id_, status=200
        )
        matched = RE_AcmeAuthorization_deactivate_btn.search(res.text)
        assert matched

        res_deactivated = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/deactivate" % id_,
            status=303,
        )
        assert RE_AcmeAuthorization_deactivated.match(res_deactivated.location)

        # check the main record, ensure we don't have a match
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s" % id_, status=200
        )
        matched_btn = RE_AcmeAuthorization_deactivate_btn.search(res.text)
        assert not matched_btn
        matched_btn = RE_AcmeAuthorization_trigger_btn.search(res.text)
        assert not matched_btn
        matched_btn = RE_AcmeAuthorization_sync_btn.search(res.text)
        assert matched_btn

        # try again, and fail
        res_deactivated = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/deactivate" % id_,
            status=303,
        )
        assert RE_AcmeAuthorization_deactivate_fail.match(res_deactivated.location)

        # now sync
        res_synced = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/sync" % id_,
            status=303,
        )
        assert RE_AcmeAuthorization_synced.match(res_synced.location)

        # for #2, we: sync, then trigger, then deactivate
        id_ = acme_authorization_ids[1]
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s" % id_, status=200
        )
        matched_btn = RE_AcmeAuthorization_sync_btn.search(res.text)
        assert matched_btn

        # now sync
        res_synced = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/sync" % id_,
            status=303,
        )
        assert RE_AcmeAuthorization_synced.match(res_synced.location)

        # check the main record
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s" % id_, status=200
        )
        matched_btn = RE_AcmeAuthorization_deactivate_btn.search(res.text)
        assert matched_btn
        matched_btn = RE_AcmeAuthorization_trigger_btn.search(res.text)
        assert matched_btn
        matched_btn = RE_AcmeAuthorization_sync_btn.search(res.text)
        assert matched_btn

        # trigger
        res_triggered = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/trigger" % id_,
            status=303,
        )
        assert RE_AcmeAuthorization_triggered.match(res_triggered.location)

        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s" % id_, status=200
        )
        matched_btn = RE_AcmeAuthorization_trigger_btn.search(res.text)
        assert not matched_btn

        # deactivate; fails after a trigger
        res_deactivated = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/deactivate" % id_,
            status=303,
        )
        assert RE_AcmeAuthorization_deactivate_fail.match(res_deactivated.location)

        # check the main record
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s" % id_, status=200
        )
        matched_btn = RE_AcmeAuthorization_deactivate_btn.search(res.text)
        assert not matched_btn
        matched_btn = RE_AcmeAuthorization_trigger_btn.search(res.text)
        assert not matched_btn
        matched_btn = RE_AcmeAuthorization_sync_btn.search(res.text)
        assert matched_btn

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(("admin:acme_order:focus:acme_server:download_certificate",))
    def test_AcmeOrder_download_certificate_html(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_AcmeOrder_download_certificate_html
        """
        (obj_id, obj_url) = self._prep_AcmeOrder_html(
            processing_strategy="process_single"
        )
        dbAcmeOrder = lib_db_get.get__AcmeOrder__by_id(self.ctx, obj_id)
        assert dbAcmeOrder is not None
        assert dbAcmeOrder.server_certificate_id is not None

        # stash the `server_certificate_id` and delete it from the backend
        server_certificate_id__og = dbAcmeOrder.server_certificate_id
        dbAcmeOrder.server_certificate_id = None
        self.ctx.pyramid_transaction_commit()

        # grab the order
        res = self.testapp.get("/.well-known/admin/acme-order/%s" % obj_id, status=200)
        assert "acme_order-download_certificate" in res.forms
        form = res.forms["acme_order-download_certificate"]
        res2 = form.submit()
        assert res2.status_code == 303
        assert RE_AcmeOrder_downloaded_certificate.match(res2.location)

        # grab the order again!
        res3 = self.testapp.get("/.well-known/admin/acme-order/%s" % obj_id, status=200)
        assert "acme_order-download_certificate" not in res3.forms
        server_certificate_ids = RE_server_certificate_link.findall(res3.text)
        assert server_certificate_ids
        assert len(server_certificate_ids) >= 1
        server_certificate_id__downloaded = int(server_certificate_ids[0])
        assert server_certificate_id__og == server_certificate_id__downloaded

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(("admin:acme_order:focus:acme_server:download_certificate|json",))
    def test_AcmeOrder_download_certificate_json(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_AcmeOrder_download_certificate_json
        """
        obj_id = self._prep_AcmeOrder_json(processing_strategy="process_single")
        dbAcmeOrder = lib_db_get.get__AcmeOrder__by_id(self.ctx, obj_id)
        assert dbAcmeOrder is not None
        assert dbAcmeOrder.server_certificate_id is not None

        # stash the `server_certificate_id` and delete it from the backend
        server_certificate_id__og = dbAcmeOrder.server_certificate_id
        dbAcmeOrder.server_certificate_id = None
        self.ctx.pyramid_transaction_commit()

        # grab the order
        res2 = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % obj_id, status=200
        )
        assert "AcmeOrder" in res2.json
        assert res2.json["AcmeOrder"]["server_certificate_id"] is None
        url_acme_server_certificate_download = res2.json["AcmeOrder"][
            "url_acme_server_certificate_download"
        ]
        assert url_acme_server_certificate_download is not None

        # trigger a download
        res3 = self.testapp.post(url_acme_server_certificate_download, {}, status=200)
        assert res3.json["AcmeOrder"]["url_acme_server_certificate_download"] is None
        assert res3.json["AcmeOrder"]["server_certificate_id"] is not None
        server_certificate_id__downloaded = res3.json["AcmeOrder"][
            "server_certificate_id"
        ]
        assert server_certificate_id__downloaded is not None

        # compare the certs
        assert server_certificate_id__og == server_certificate_id__downloaded

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(
        (
            # "admin:acme_order:focus|json",
            "admin:acme_authorization:focus|json",
            "admin:acme_authorization:focus:acme_server:deactivate|json",
            "admin:acme_authorization:focus:acme_server:sync|json",
            "admin:acme_authorization:focus:acme_server:trigger|json",
        )
    )
    def test_AcmeAuthorization_manipulate_json(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_AcmeAuthorization_manipulate_json
        """
        order_id = self._prep_AcmeOrder_json(processing_strategy="create_order")

        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % order_id, status=200
        )
        assert "AcmeOrder" in res.json
        acme_authorization_ids = res.json["AcmeOrder"]["acme_authorization_ids"]
        assert len(acme_authorization_ids) == 2

        # for #1, we deactivate then sync
        id_ = acme_authorization_ids[0]
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s.json" % id_, status=200
        )
        assert "AcmeAuthorization" in res.json
        assert res.json["AcmeAuthorization"]["url_acme_server_deactivate"] is not None

        res_deactivated = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/deactivate.json"
            % id_,
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
            res_deactivated.json["AcmeAuthorization"]["url_acme_server_trigger"] is None
        )
        assert (
            res_deactivated.json["AcmeAuthorization"]["url_acme_server_sync"]
            is not None
        )

        # try again, and fail
        res_deactivated = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/deactivate.json"
            % id_,
            status=200,
        )
        assert res_deactivated.json["result"] == "error"
        assert res_deactivated.json["operation"] == "acme-server/deactivate"
        assert (
            res_deactivated.json["error"]
            == "ACME Server Sync is not allowed for this AcmeAuthorization"
        )

        # now sync
        res_synced = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/sync.json" % id_,
            status=200,
        )
        assert res_synced.json["result"] == "success"
        assert res_synced.json["operation"] == "acme-server/sync"

        # for #2, we: sync, then trigger, then deactivate
        id_ = acme_authorization_ids[1]
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s.json" % id_, status=200
        )
        assert "AcmeAuthorization" in res.json
        assert res.json["AcmeAuthorization"]["url_acme_server_sync"] is not None

        # now sync
        res_synced = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/sync.json" % id_,
            status=200,
        )
        assert res_synced.json["result"] == "success"
        assert res_synced.json["operation"] == "acme-server/sync"

        # check the main record
        assert "AcmeAuthorization" in res_synced.json
        assert (
            res_synced.json["AcmeAuthorization"]["url_acme_server_deactivate"]
            is not None
        )
        assert (
            res_synced.json["AcmeAuthorization"]["url_acme_server_trigger"] is not None
        )
        assert res_synced.json["AcmeAuthorization"]["url_acme_server_sync"] is not None

        # trigger
        res_triggered = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/trigger.json" % id_,
            status=200,
        )
        assert res_triggered.json["result"] == "success"
        assert res_triggered.json["operation"] == "acme-server/trigger"
        assert (
            res_triggered.json["AcmeAuthorization"]["url_acme_server_trigger"] is None
        )

        # deactivate
        res_deactivated = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/deactivate.json"
            % id_,
            status=200,
        )
        assert res_deactivated.json["result"] == "error"
        assert res_deactivated.json["operation"] == "acme-server/deactivate"
        assert (
            res_deactivated.json["error"]
            == "ACME Server Sync is not allowed for this AcmeAuthorization"
        )

        # check the main record
        # must fetch the main record, because `AcmeAuthorization` does not appear in error
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s.json" % id_, status=200
        )
        assert "AcmeAuthorization" in res.json
        assert res.json["AcmeAuthorization"]["url_acme_server_deactivate"] is None
        assert res.json["AcmeAuthorization"]["url_acme_server_trigger"] is None
        assert res.json["AcmeAuthorization"]["url_acme_server_sync"] is not None

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(
        (
            "admin:acme_challenge:focus",
            "admin:acme_challenge:focus:acme_server:sync",
            "admin:acme_challenge:focus:acme_server:trigger",
        )
    )
    def test_AcmeChallenge_manipulate_html(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_AcmeChallenge_manipulate_html
        """
        (order_id, order_url) = self._prep_AcmeOrder_html()

        res_order = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % order_id, status=200
        )
        acme_authorization_ids = res_order.json["AcmeOrder"]["acme_authorization_ids"]
        assert len(acme_authorization_ids) == 2

        # loop these as an enumeration
        for (idx, authorization_id) in enumerate(acme_authorization_ids):

            # Auth1
            res_auth = self.testapp.get(
                "/.well-known/admin/acme-authorization/%s.json" % authorization_id,
                status=200,
            )
            # sync it to load the challenge
            res_auth = self.testapp.get(
                "/.well-known/admin/acme-authorization/%s/acme-server/sync.json"
                % authorization_id,
                status=200,
            )
            assert res_auth.json["result"] == "success"
            assert res_auth.json["operation"] == "acme-server/sync"
            assert (
                res_auth.json["AcmeAuthorization"]["acme_status_authorization"]
                == "pending"
            )
            challenge_id = res_auth.json["AcmeAuthorization"][
                "acme_challenge_http01_id"
            ]
            assert challenge_id is not None

            if idx == 0:
                # iteration 1: sync then trigger

                # Get/Audit Main Record
                res_challenge = self.testapp.get(
                    "/.well-known/admin/acme-challenge/%s" % challenge_id, status=200
                )
                assert RE_AcmeChallenge_sync_btn.search(res_challenge.text)
                assert RE_AcmeChallenge_trigger_btn.search(res_challenge.text)

                # sync
                res_sync = self.testapp.get(
                    "/.well-known/admin/acme-challenge/%s/acme-server/sync"
                    % challenge_id,
                    status=303,
                )
                assert RE_AcmeChallenge_synced.match(res_sync.location)

                # Get/Audit Main Record
                res_challenge = self.testapp.get(
                    "/.well-known/admin/acme-challenge/%s" % challenge_id, status=200
                )
                assert RE_AcmeChallenge_sync_btn.search(res_challenge.text)
                assert RE_AcmeChallenge_trigger_btn.search(res_challenge.text)

                # trigger
                res_trigger = self.testapp.get(
                    "/.well-known/admin/acme-challenge/%s/acme-server/trigger"
                    % challenge_id,
                    status=303,
                )
                assert RE_AcmeChallenge_triggered.match(res_trigger.location)

                # Get/Audit Main Record
                res_challenge = self.testapp.get(
                    "/.well-known/admin/acme-challenge/%s" % challenge_id, status=200
                )
                assert RE_AcmeChallenge_sync_btn.search(res_challenge.text)
                assert not RE_AcmeChallenge_trigger_btn.search(res_challenge.text)

                # trigger fail
                res_trigger = self.testapp.get(
                    "/.well-known/admin/acme-challenge/%s/acme-server/trigger"
                    % challenge_id,
                    status=303,
                )
                assert RE_AcmeChallenge_trigger_fail.match(res_trigger.location)

            else:

                # iteration 2: trigger then sync

                # Get/Audit Main Record
                res_challenge = self.testapp.get(
                    "/.well-known/admin/acme-challenge/%s" % challenge_id, status=200
                )
                assert RE_AcmeChallenge_sync_btn.search(res_challenge.text)
                assert RE_AcmeChallenge_trigger_btn.search(res_challenge.text)

                # trigger
                res_trigger = self.testapp.get(
                    "/.well-known/admin/acme-challenge/%s/acme-server/trigger"
                    % challenge_id,
                    status=303,
                )
                assert RE_AcmeChallenge_triggered.match(res_trigger.location)

                # Get/Audit Main Record
                res_challenge = self.testapp.get(
                    "/.well-known/admin/acme-challenge/%s" % challenge_id, status=200
                )
                assert RE_AcmeChallenge_sync_btn.search(res_challenge.text)
                assert not RE_AcmeChallenge_trigger_btn.search(res_challenge.text)

                # sync
                res_sync = self.testapp.get(
                    "/.well-known/admin/acme-challenge/%s/acme-server/sync"
                    % challenge_id,
                    status=303,
                )
                assert RE_AcmeChallenge_synced.match(res_sync.location)

                # Get/Audit Main Record
                res_challenge = self.testapp.get(
                    "/.well-known/admin/acme-challenge/%s" % challenge_id, status=200
                )
                assert RE_AcmeChallenge_sync_btn.search(res_challenge.text)
                assert not RE_AcmeChallenge_trigger_btn.search(res_challenge.text)

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(
        (
            "admin:acme_challenge:focus|json",
            "admin:acme_challenge:focus:acme_server:sync|json",
            "admin:acme_challenge:focus:acme_server:trigger|json",
        )
    )
    def test_AcmeChallenge_manipulate_json(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_AcmeChallenge_manipulate_json
        """

        order_id = self._prep_AcmeOrder_json()

        res_order = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % order_id, status=200
        )
        acme_authorization_ids = res_order.json["AcmeOrder"]["acme_authorization_ids"]
        assert len(acme_authorization_ids) == 2

        # loop these as an enumeration
        for (idx, authorization_id) in enumerate(acme_authorization_ids):

            # Auth1
            res_auth = self.testapp.get(
                "/.well-known/admin/acme-authorization/%s.json" % authorization_id,
                status=200,
            )
            # sync it to load the challenge
            res_auth = self.testapp.get(
                "/.well-known/admin/acme-authorization/%s/acme-server/sync.json"
                % authorization_id,
                status=200,
            )
            assert res_auth.json["result"] == "success"
            assert res_auth.json["operation"] == "acme-server/sync"
            assert (
                res_auth.json["AcmeAuthorization"]["acme_status_authorization"]
                == "pending"
            )
            challenge_id = res_auth.json["AcmeAuthorization"][
                "acme_challenge_http01_id"
            ]
            assert challenge_id is not None

            if idx == 0:
                # iteration 1: sync then trigger

                # Get/Audit Main Record
                res_challenge = self.testapp.get(
                    "/.well-known/admin/acme-challenge/%s.json" % challenge_id,
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
                res_sync = self.testapp.get(
                    "/.well-known/admin/acme-challenge/%s/acme-server/sync.json"
                    % challenge_id,
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
                res_trigger = self.testapp.get(
                    "/.well-known/admin/acme-challenge/%s/acme-server/trigger.json"
                    % challenge_id,
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
                res_trigger = self.testapp.get(
                    "/.well-known/admin/acme-challenge/%s/acme-server/trigger.json"
                    % challenge_id,
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
                    "/.well-known/admin/acme-challenge/%s.json" % challenge_id,
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
                res_trigger = self.testapp.get(
                    "/.well-known/admin/acme-challenge/%s/acme-server/trigger.json"
                    % challenge_id,
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
                res_sync = self.testapp.get(
                    "/.well-known/admin/acme-challenge/%s/acme-server/sync.json"
                    % challenge_id,
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

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(("admin:queue_domains:add", "admin:queue_domains:process",))
    def test_QueueDomains_process_html__create_order(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_QueueDomains_process_html__create_order
        """
        _domain_names = [
            "test-QueueDomains-process-html-create-order--1.example.com",
            "test-QueueDomains-process-html-create-order--2.example.com",
        ]

        # start off with some domains in the queue!
        res = self.testapp.get("/.well-known/admin/queue-domains/add", status=200)
        form = res.form
        form["domain_names"] = ",".join(_domain_names)
        res2 = form.submit()
        assert res2.status_code == 303
        assert res2.location.startswith(
            """http://peter-sslers.example.com/.well-known/admin/queue-domains?result=success&operation=add&results="""
        )

        # try to process; a CREATE only
        _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]
        res3 = self.testapp.get("/.well-known/admin/queue-domains/process", status=200)
        form = res3.form
        form["account_key_option"].force_value("account_key_file")
        form["acme_account_provider_id"].force_value("1")
        form["account_key_file_pem"] = Upload(
            self._filepath_testfile(
                _test_data["acme-order/new/freeform#1"]["account_key_file_pem"]
            )
        )
        form["account__contact"] = _test_data["acme-order/new/freeform#1"][
            "account__contact"
        ]
        form["account__private_key_cycle"].force_value("account_daily")
        form["private_key_cycle__renewal"].force_value("account_key_default")
        form["private_key_option"].force_value("private_key_for_account_key")
        form["processing_strategy"].force_value("create_order")
        form["max_domains_per_certificate"].force_value(10)
        res4 = form.submit()
        assert res4.status_code == 303

        matched = RE_QueueDomain_process_success.match(res4.location)
        assert matched
        acme_order_id = matched.groups()[0]
        assert acme_order_id

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(("admin:queue_domains:add", "admin:queue_domains:process",))
    def test_QueueDomains_process_html__process_single(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_QueueDomains_process_html__process_single
        
        NOTE: it is not necessary to test `process_multi` as that just does "create_order" with processing done via the AcmeOrder endpoints
        """
        _domain_names = [
            "test-QueueDomains-process-html-process-single--1.example.com",
            "test-QueueDomains-process-html-process-single--2.example.com",
        ]

        # start off with some domains in the queue!
        res = self.testapp.get("/.well-known/admin/queue-domains/add", status=200)
        form = res.form
        form["domain_names"] = ",".join(_domain_names)
        res2 = form.submit()
        assert res2.status_code == 303
        assert res2.location.startswith(
            """http://peter-sslers.example.com/.well-known/admin/queue-domains?result=success&operation=add&results="""
        )

        # try to process; use process_single
        _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]
        res3 = self.testapp.get("/.well-known/admin/queue-domains/process", status=200)
        form = res3.form
        form["account_key_option"].force_value("account_key_file")
        form["acme_account_provider_id"].force_value("1")
        form["account_key_file_pem"] = Upload(
            self._filepath_testfile(
                _test_data["acme-order/new/freeform#1"]["account_key_file_pem"]
            )
        )
        form["account__contact"] = _test_data["acme-order/new/freeform#1"][
            "account__contact"
        ]
        form["account__private_key_cycle"].force_value("account_daily")
        form["private_key_cycle__renewal"].force_value("account_key_default")
        form["private_key_option"].force_value("private_key_for_account_key")
        form["processing_strategy"].force_value("process_single")
        form["max_domains_per_certificate"].force_value(10)
        res4 = form.submit()
        assert res4.status_code == 303

        matched = RE_QueueDomain_process_success.match(res4.location)
        assert matched
        acme_order_id = matched.groups()[0]
        assert acme_order_id

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(("admin:queue_domains:add|json", "admin:queue_domains:process|json",))
    def test_QueueDomains_process_json__create_order(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_QueueDomains_process_json__create_order
        """
        _domain_names = [
            "test-QueueDomains-process-json-create-order--1.example.com",
            "test-QueueDomains-process-json-create-order--2.example.com",
        ]

        # start off with some domains in the queue!
        res = self.testapp.get("/.well-known/admin/queue-domains/add.json", status=200)
        _data = {"domain_names": ",".join(_domain_names)}
        res2 = self.testapp.post("/.well-known/admin/queue-domains/add.json", _data)
        assert res2.status_code == 200
        assert res2.json["result"] == "success"
        assert "domains" in res2.json
        for _domain in _domain_names:
            _domain = _domain.lower()
            assert _domain in res2.json["domains"]
            assert res2.json["domains"][_domain] == "queued"

        # nothing on GET
        res = self.testapp.get(
            "/.well-known/admin/queue-domains/process.json", status=200
        )
        assert "instructions" in res.json

        # try to process; a CREATE only
        _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]
        form = {}
        form["account_key_option"] = "account_key_file"
        form["acme_account_provider_id"] = "1"
        form["account_key_file_pem"] = Upload(
            self._filepath_testfile(
                _test_data["acme-order/new/freeform#1"]["account_key_file_pem"]
            )
        )
        form["account__contact"] = _test_data["acme-order/new/freeform#1"][
            "account__contact"
        ]
        form["account__private_key_cycle"] = "account_daily"
        form["private_key_cycle__renewal"] = "account_key_default"
        form["private_key_option"] = "private_key_for_account_key"
        form["processing_strategy"] = "create_order"
        form["max_domains_per_certificate"] = 10

        res2 = self.testapp.post("/.well-known/admin/queue-domains/process.json", form)
        assert res2.status_code == 200
        assert res2.json["result"] == "success"
        assert "AcmeOrder" in res2.json
        acme_order_id = res2.json["AcmeOrder"]["id"]
        assert acme_order_id
        assert res2.json["AcmeOrder"]["acme_status_order"] == "pending"
        for _domain in _domain_names:
            _domain = _domain.lower()
            assert _domain in res2.json["AcmeOrder"]["domains_as_list"]

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(("admin:queue_domains:process|json",))
    def test_QueueDomains_process_json__process_single(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_QueueDomains_process_json__process_single
        """
        _domain_names = [
            "test-QueueDomains-process-json-process-single--1.example.com",
            "test-QueueDomains-process-json-process-single--2.example.com",
        ]

        # start off with some domains in the queue!
        res = self.testapp.get("/.well-known/admin/queue-domains/add.json", status=200)
        _data = {"domain_names": ",".join(_domain_names)}
        res2 = self.testapp.post("/.well-known/admin/queue-domains/add.json", _data)
        assert res2.status_code == 200
        assert res2.json["result"] == "success"
        assert "domains" in res2.json

        for _domain in _domain_names:
            _domain = _domain.lower()
            assert _domain in res2.json["domains"]
            assert res2.json["domains"][_domain] == "queued"

        # nothing on GET
        res = self.testapp.get(
            "/.well-known/admin/queue-domains/process.json", status=200
        )
        assert "instructions" in res.json

        # try to process; PROCESS_SINGLE
        _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]
        form = {}
        form["account_key_option"] = "account_key_file"
        form["acme_account_provider_id"] = "1"
        form["account_key_file_pem"] = Upload(
            self._filepath_testfile(
                _test_data["acme-order/new/freeform#1"]["account_key_file_pem"]
            )
        )
        form["account__contact"] = _test_data["acme-order/new/freeform#1"][
            "account__contact"
        ]
        form["account__private_key_cycle"] = "account_daily"
        form["private_key_cycle__renewal"] = "account_key_default"
        form["private_key_option"] = "private_key_for_account_key"
        form["processing_strategy"] = "process_single"
        form["max_domains_per_certificate"] = 10

        # post it
        res2 = self.testapp.post("/.well-known/admin/queue-domains/process.json", form)
        assert res2.status_code == 200
        assert res2.json["result"] == "success"
        assert "AcmeOrder" in res2.json
        acme_order_id = res2.json["AcmeOrder"]["id"]
        assert acme_order_id
        # `@under_pebble` WILL be valid
        # `@under_pebble_strict` WILL NOT be valid
        assert res2.json["AcmeOrder"]["acme_status_order"] == "valid"
        for _domain in _domain_names:
            _domain = _domain.lower()
            assert _domain in res2.json["AcmeOrder"]["domains_as_list"]

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(("admin:api:queue_certificates:update",))
    def test_QueueCertificates_api_update_html(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_QueueCertificates_api_update_html
        """
        res = self.testapp.get(
            "/.well-known/admin/api/queue-certificates/update", status=303
        )
        assert (
            res.location
            == """http://peter-sslers.example.com/.well-known/admin/queue-certificates?result=success&operation=update&results=true"""
        )
        # TODO - populate the database so it will actually update the queue, retest

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(("admin:api:queue_certificates:update|json",))
    def test_QueueCertificates_api_update_json(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_QueueCertificates_api_update_json
        """
        res = self.testapp.get(
            "/.well-known/admin/api/queue-certificates/update.json", status=200
        )
        assert "instructions" in res.json
        assert res.json["instructions"] == "POST required"

        res = self.testapp.post(
            "/.well-known/admin/api/queue-certificates/update.json", status=200
        )
        assert res.json["result"] == "success"
        assert res.json["results"] is True
        # TODO - populate the database so it will actually update the queue, retest

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(("admin:api:queue_certificates:process",))
    def test_QueueCertificates_api_process_html(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_QueueCertificates_api_process_html
        """
        res = self.testapp.get(
            "/.well-known/admin/api/queue-certificates/process.json", status=200
        )
        # pdb.set_trace()

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble
    @tests_routes(("admin:api:queue_certificates:process|json",))
    def test_QueueCertificates_api_process_json(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeServer.test_QueueCertificates_api_process_json
        """
        res = self.testapp.get(
            "/.well-known/admin/api/queue-certificates/process", status=200
        )
        # pdb.set_trace()


class FunctionalTests_API(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_API
    """

    @tests_routes(("admin:api",))
    def test_passive(self):
        res = self.testapp.get("/.well-known/admin/api", status=200)

    @tests_routes(("admin:api:domain:enable", "admin:api:domain:disable",))
    def test_domains(self):
        # enable
        _data = {"domain_names": "example.com,foo.example.com, bar.example.com"}
        res = self.testapp.post("/.well-known/admin/api/domain/enable", _data)
        assert res.status_code == 200
        assert res.json["result"] == "success"

        # disable
        _data = {"domain_names": "example.com,biz.example.com"}
        res = self.testapp.post("/.well-known/admin/api/domain/disable", _data)
        assert res.status_code == 200
        assert res.json["result"] == "success"

    @tests_routes(
        (
            "admin:api:deactivate_expired",
            "admin:api:deactivate_expired|json",
            "admin:api:update_recents",
            "admin:api:update_recents|json",
        )
    )
    def test_manipulate(self):
        # deactivate-expired
        res = self.testapp.get("/.well-known/admin/api/deactivate-expired", status=303)
        assert (
            "/.well-known/admin/operations/log?result=success&event.id=" in res.location
        )

        res = self.testapp.get(
            "/.well-known/admin/api/deactivate-expired.json", status=200
        )
        assert "instructions" in res.json
        assert (
            res.json["instructions"] == "JSON endpoint requires a submission via `POST`"
        )
        res = self.testapp.post(
            "/.well-known/admin/api/deactivate-expired.json", {}, status=200
        )
        assert res.json["result"] == "success"

        # update-recents
        res = self.testapp.get("/.well-known/admin/api/update-recents", status=303)
        assert (
            "/.well-known/admin/operations/log?result=success&event.id=" in res.location
        )
        res = self.testapp.get("/.well-known/admin/api/update-recents.json", status=200)
        assert "instructions" in res.json
        assert (
            res.json["instructions"] == "JSON endpoint requires a submission via `POST`"
        )
        res = self.testapp.post(
            "/.well-known/admin/api/update-recents.json", {}, status=200
        )
        assert res.json["result"] == "success"

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @tests_routes(
        (
            "admin:api:ca_certificate_probes:probe",
            "admin:api:ca_certificate_probes:probe|json",
        )
    )
    def test_api__pebble(self):
        res = self.testapp.get(
            "/.well-known/admin/api/ca-certificate-probes/probe", status=303
        )
        assert (
            "/admin/operations/ca-certificate-probes?result=success&event.id="
            in res.location
        )

        res = self.testapp.get(
            "/.well-known/admin/api/ca-certificate-probes/probe.json", status=200
        )
        assert "instructions" in res.json
        assert (
            res.json["instructions"] == "JSON endpoint requires a submission via `POST`"
        )
        res = self.testapp.post(
            "/.well-known/admin/api/ca-certificate-probes/probe.json", {}, status=200,
        )
        assert res.json["result"] == "success"

    @unittest.skipUnless(RUN_REDIS_TESTS, "not running against redis")
    @under_redis
    @tests_routes(("admin:api:redis:prime", "admin:api:redis:prime|json",))
    def test_redis(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_API.test_redis
        """
        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        # NOTE: prep work, ensure we updated recents
        res = self.testapp.post(
            "/.well-known/admin/api/update-recents.json", {}, status=200
        )
        assert res.json["result"] == "success"

        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

        res = self.testapp.get("/.well-known/admin/api/redis/prime", status=303)
        assert (
            "/.well-known/admin/operations/redis?result=success&operation=redis_prime&event.id="
            in res.location
        )

        res = self.testapp.get("/.well-known/admin/api/redis/prime.json", status=200)
        assert "instructions" in res.json
        assert (
            res.json["instructions"] == "JSON endpoint requires a submission via `POST`"
        )

        res = self.testapp.post(
            "/.well-known/admin/api/redis/prime.json", {}, status=200
        )
        assert res.json["result"] == "success"

    @unittest.skipUnless(RUN_NGINX_TESTS, "not running against nginx")
    @tests_routes(
        (
            "admin:api:nginx:cache_flush",
            "admin:api:nginx:cache_flush|json",
            "admin:api:nginx:status|json",
        )
    )
    def test_nginx(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_API.test_nginx
        """
        # TODO: this doesn't actually test nginx
        # this will test the nginx routes work, but they will catch exceptions when trying to talk upstream
        res = self.testapp.get("/.well-known/admin/api/nginx/cache-flush", status=303)
        assert (
            "/.well-known/admin/operations/nginx?result=success&operation=nginx_cache_flush&event.id="
            in res.location
        )

        res = self.testapp.get(
            "/.well-known/admin/api/nginx/cache-flush.json", status=200
        )
        assert res.json["result"] == "success"

        res = self.testapp.get("/.well-known/admin/api/nginx/status.json", status=200)
        assert res.json["result"] == "success"


class IntegratedTests_AcmeServer(AppTestWSGI):
    """
    This test suite runs against a Pebble instance, which will try to validate the domains.
    This tests serving and responding to validations.

    python -m unittest peter_sslers.tests.pyramid_app_tests.IntegratedTests_AcmeServer
    """

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
            "http://peter-sslers.example.com:5002/.well-known/admin/acme-order/new/freeform.json"
        )
        assert resp.status_code == 200
        assert "instructions" in resp.json()

        form = {}
        files = {}
        form["account_key_option"] = "account_key_file"
        form["acme_account_provider_id"] = "1"
        files["account_key_file_pem"] = open(
            self._filepath_testfile(account_key_file_pem), "rb",
        )
        form["account__contact"] = account__contact
        form["account__private_key_cycle"] = "account_daily"
        form["private_key_cycle__renewal"] = "account_key_default"
        form["private_key_option"] = "private_key_for_account_key"
        form["domain_names"] = ",".join(domain_names)
        form["processing_strategy"] = "process_single"
        resp = requests.post(
            "http://peter-sslers.example.com:5002/.well-known/admin/acme-order/new/freeform.json",
            data=form,
            files=files,
        )
        return resp

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble_strict
    def test_AcmeOrder_multiple_domains(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.IntegratedTests_AcmeServer.test_AcmeOrder_multiple_domains

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

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble_strict
    def test_AcmeOrder_cleanup(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.IntegratedTests_AcmeServer.test_AcmeOrder_cleanup

        this test is not focused on routes, but cleaning up an order
        """
        # Functional Tests: self.testapp.app.registry.settings
        # Integrated Tests: self.testapp_wsgi.test_app.registry.settings
        # by default, this should be True
        assert (
            self.testapp_wsgi.test_app.registry.settings["app_settings"][
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
        assert resp.json()["error"] == "`pending` AcmeOrder failed an AcmeAuthorization"
        assert "AcmeOrder" in resp.json()
        obj_id = resp.json()["AcmeOrder"]["id"]

        # # test for resync bug
        # url = "http://peter-sslers.example.com:5002/.well-known/admin/acme-order/%s/acme-server/sync.json" % obj_id
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

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @under_pebble_strict
    def test_AcmeOrder_nocleanup(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.IntegratedTests_AcmeServer.test_AcmeOrder_nocleanup

        this test is not focused on routes, but cleaning up an order
        """
        try:
            # Functional Tests: self.testapp.app.registry.settings
            # Integrated Tests: self.testapp_wsgi.test_app.registry.settings
            # by default, this should be True
            assert (
                self.testapp_wsgi.test_app.registry.settings["app_settings"][
                    "cleanup_pending_authorizations"
                ]
                is True
            )
            # now set this as False
            self.testapp_wsgi.test_app.registry.settings["app_settings"][
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
            assert stats_b["count-Domain"] == stats_og["count-Domain"] + 20
            assert stats_b["count-UniqueFQDNSet"] == stats_og["count-UniqueFQDNSet"] + 1
            assert stats_b["count-AcmeOrder"] == stats_og["count-AcmeOrder"] + 1
            assert (
                stats_b["count-AcmeAuthorization"]
                == stats_og["count-AcmeAuthorization"] + 20
            )
            # this one is hard to figure out
            # start with 20 auths
            _expected = stats_og["count-AcmeAuthorization-pending"] + 20
            # then figure out the difference in challenges
            _expected = _expected - (
                stats_b["count-AcmeChallenge"] - stats_og["count-AcmeChallenge"]
            )
            # no need to subtract one for the failed auth, because it's part of the `count-AcmeChallenge`
            # _expected = _expected - 1

            assert stats_b["count-AcmeAuthorization-pending"] == _expected

        finally:
            # reset
            self.testapp_wsgi.test_app.registry.settings["app_settings"][
                "cleanup_pending_authorizations"
            ] = True

    @under_pebble_strict
    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against Pebble API")
    @tests_routes(("admin:api:domain:certificate-if-needed",))
    def test_domain_certificate_if_needed(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.IntegratedTests_AcmeServer.test_domain_certificate_if_needed
        """
        res = self.testapp.get(
            "/.well-known/admin/api/domain/certificate-if-needed", status=200
        )
        assert "instructions" in res.json
        assert "AcmeAccount_GlobalDefault" in res.json["valid_options"]
        key_pem_md5 = res.json["valid_options"]["AcmeAccount_GlobalDefault"][
            "AcmeAccountKey"
        ]["key_pem_md5"]

        res2 = self.testapp.post(
            "/.well-known/admin/api/domain/certificate-if-needed", {}, status=200
        )
        assert "instructions" not in res2.json
        assert res2.json["result"] == "error"

        # prep the form
        form = {}
        form["account_key_option"] = "account_key_global_default"
        form["account_key_global_default"] = key_pem_md5
        form["account__private_key_cycle"] = "account_daily"
        form["private_key_cycle__renewal"] = "account_key_default"
        form["private_key_option"] = "private_key_for_account_key"
        form["processing_strategy"] = "process_single"

        # Pass 1 - Generate a single domain
        _domain_name = "test-domain-certificate-if-needed-1.example.com"
        form["domain_names"] = _domain_name
        res3 = self.testapp.post(
            "/.well-known/admin/api/domain/certificate-if-needed", form
        )
        assert res3.status_code == 200
        assert res3.json["result"] == "success"
        assert "domain_results" in res3.json
        assert _domain_name in res3.json["domain_results"]
        try:
            assert (
                res3.json["domain_results"][_domain_name]["server_certificate.status"]
                == "new"
            )
            assert res3.json["domain_results"][_domain_name]["domain.status"] == "new"
        except:
            pprint.pprint(res3.json)
            raise
        assert res3.json["domain_results"][_domain_name]["acme_order.id"] is not None

        # Pass 2 - Try multiple domains
        _domain_names = (
            "test-domain-certificate-if-needed-1.example.com",
            "test-domain-certificate-if-needed-2.example.com",
        )
        form["domain_names"] = ",".join(_domain_names)
        res4 = self.testapp.post(
            "/.well-known/admin/api/domain/certificate-if-needed", form
        )
        assert res4.status_code == 200
        assert res4.json["result"] == "error"
        assert (
            res4.json["form_errors"]["domain_names"]
            == "This endpoint currently supports only 1 domain name"
        )

        # Pass 3 - Try a failure domain
        _domain_name = "fail-a-1.example.com"
        form["domain_names"] = _domain_name
        res5 = self.testapp.post(
            "/.well-known/admin/api/domain/certificate-if-needed", form
        )
        assert res5.status_code == 200
        assert res5.json["result"] == "success"
        assert (
            res5.json["domain_results"][_domain_name]["server_certificate.status"]
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
        form["domain_names"] = _domain_name
        res6 = self.testapp.post(
            "/.well-known/admin/api/domain/certificate-if-needed", form
        )
        assert res6.status_code == 200
        assert res6.json["result"] == "success"
        assert "domain_results" in res6.json
        assert _domain_name in res6.json["domain_results"]
        assert (
            res6.json["domain_results"][_domain_name]["server_certificate.status"]
            == "exists"
        )
        assert (
            res6.json["domain_results"][_domain_name]["domain.status"]
            == "existing.active"
        )
        assert res6.json["domain_results"][_domain_name]["acme_order.id"] is None

        # Pass 5 - make the existing domain inactive, then submit
        _domain_name = "test-domain-certificate-if-needed-1.example.com"
        form_disable = {"domain_names": _domain_name}
        res_disable = self.testapp.post(
            "/.well-known/admin/api/domain/disable", form_disable
        )
        assert res_disable.status_code == 200
        assert res_disable.json["result"] == "success"

        _domain_name = "test-domain-certificate-if-needed-1.example.com"
        form["domain_names"] = _domain_name
        res7 = self.testapp.post(
            "/.well-known/admin/api/domain/certificate-if-needed", form
        )
        assert res7.status_code == 200
        assert res7.json["result"] == "success"
        assert "domain_results" in res7.json
        assert _domain_name in res7.json["domain_results"]
        assert (
            res7.json["domain_results"][_domain_name]["server_certificate.status"]
            == "exists"
        )
        assert (
            res7.json["domain_results"][_domain_name]["domain.status"]
            == "existing.activated"
        )
        assert res7.json["domain_results"][_domain_name]["acme_order.id"] is None

    @unittest.skipUnless(RUN_REDIS_TESTS, "not running against redis")
    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "not running against pebble")
    @under_pebble
    @under_redis
    @tests_routes(("admin:api:redis:prime", "admin:api:redis:prime|json",))
    def test_redis(self):
        """
        python -m unittest peter_sslers.tests.pyramid_app_tests.IntegratedTests_AcmeServer.test_redis
        """

        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        # NOTE: prep work, ensure we have a cert
        # prep the form
        res = self.testapp.get(
            "/.well-known/admin/api/domain/certificate-if-needed", status=200
        )
        assert "instructions" in res.json
        assert "AcmeAccount_GlobalDefault" in res.json["valid_options"]
        key_pem_md5 = res.json["valid_options"]["AcmeAccount_GlobalDefault"][
            "AcmeAccountKey"
        ]["key_pem_md5"]

        form = {}
        form["account_key_option"] = "account_key_global_default"
        form["account_key_global_default"] = key_pem_md5
        form["account__private_key_cycle"] = "account_daily"
        form["private_key_cycle__renewal"] = "account_key_default"
        form["private_key_option"] = "private_key_for_account_key"
        form["processing_strategy"] = "process_single"
        # Pass 1 - Generate a single domain
        _domain_name = "test-redis-1.example.com"
        form["domain_names"] = _domain_name
        res = self.testapp.post(
            "/.well-known/admin/api/domain/certificate-if-needed", form
        )
        assert res.status_code == 200
        assert res.json["result"] == "success"
        assert "domain_results" in res.json
        assert _domain_name in res.json["domain_results"]
        assert (
            res.json["domain_results"][_domain_name]["server_certificate.status"]
            == "new"
        )
        assert res.json["domain_results"][_domain_name]["domain.status"] == "new"
        assert res.json["domain_results"][_domain_name]["acme_order.id"] is not None

        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        # NOTE: prep work, ensure we updated recents
        res = self.testapp.post(
            "/.well-known/admin/api/update-recents.json", {}, status=200
        )
        assert res.json["result"] == "success"

        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

        # okay, loop the prime styles
        _prime_styles = ("1", "2")
        _existing_prime_style = self.testapp.app.registry.settings["app_settings"][
            "redis.prime_style"
        ]
        try:
            for _prime_style in _prime_styles:
                if _prime_style == _existing_prime_style:
                    continue
                self.testapp.app.registry.settings["app_settings"][
                    "redis.prime_style"
                ] = _prime_style

                res = self.testapp.post(
                    "/.well-known/admin/api/redis/prime.json", {}, status=200
                )
                assert res.json["result"] == "success"

        finally:
            # reset
            self.testapp.app.registry.settings["app_settings"][
                "redis.prime_style"
            ] = _existing_prime_style


class CoverageAssurance_AuditTests(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.CoverageAssurance_AuditTests
    """

    def test_audit_route_coverage(self):
        """
        This test is used to audit the pyramid app's registered routes for coverage
        against tests that are registered with the `@tests_routes` decorator
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
