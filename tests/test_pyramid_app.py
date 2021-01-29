from __future__ import print_function

# stdlib
import datetime
import json
import os
import packaging.version
import pdb
import pprint
import re
import unittest
import zipfile
from functools import wraps
import sys
from io import open  # overwrite `open` in Python2
import six

if six.PY3:
    from io import StringIO
    from io import BytesIO
else:
    from StringIO import StringIO

# pypi
from webtest import Upload
from webtest.http import StopableWSGIServer
import requests
import sqlalchemy

# local
from peter_sslers.lib import letsencrypt_info
from peter_sslers.lib.db import get as lib_db_get
from peter_sslers.model import objects as model_objects
from peter_sslers.model import utils as model_utils

from ._utils import FakeRequest
from ._utils import TEST_FILES
from ._utils import AppTest
from ._utils import AppTestWSGI
from ._utils import under_pebble
from ._utils import under_pebble_strict
from ._utils import under_redis

# local, flags
from .regex_library import *
from ._utils import LETSENCRYPT_API_VALIDATES
from ._utils import RUN_API_TESTS__PEBBLE
from ._utils import RUN_API_TESTS__ACME_DNS_API
from ._utils import RUN_NGINX_TESTS
from ._utils import RUN_REDIS_TESTS
from ._utils import SSL_TEST_PORT
from ._utils import OPENRESTY_PLUGIN_MINIMUM


# ==============================================================================
#
# essentially disable logging for tests
#
import logging

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


# =====


class FunctionalTests_Passes(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_Passes
    this is only used to test setup
    """

    def test_passes(self):
        return True


class FunctionalTests_Main(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_Main
    """

    @routes_tested("admin")
    def test_custom_headers(self):
        res = self.testapp.get("/.well-known/admin", status=200)
        assert res.headers["X-Peter-SSLers"] == "production"

    @routes_tested("admin")
    def test_root(self):
        res = self.testapp.get("/.well-known/admin", status=200)

    @routes_tested("admin:whoami")
    def test_admin_whoami(self):
        res = self.testapp.get("/.well-known/admin/whoami", status=200)

    @routes_tested("admin:help")
    def test_help(self):
        res = self.testapp.get("/.well-known/admin/help", status=200)

    @routes_tested("admin:settings")
    def test_settings(self):
        res = self.testapp.get("/.well-known/admin/settings", status=200)

    @routes_tested("admin:api")
    def test_api_docs(self):
        res = self.testapp.get("/.well-known/admin/api", status=200)

    @routes_tested("admin:search")
    def test_search(self):
        res = self.testapp.get("/.well-known/admin/search", status=200)

    @routes_tested("public_whoami")
    def test_public_whoami(self):
        res = self.testapp.get("/.well-known/public/whoami", status=200)


class FunctionalTests_AcmeAccount(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeAccount
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
        assert focus_item is not None
        return focus_item, focus_item.id

    @routes_tested("admin:acme_account:upload")
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

    @routes_tested("admin:acme_account:upload|json")
    def test_upload_json(self):
        _key_filename = TEST_FILES["AcmeAccount"]["2"]["key"]
        _private_key_cycle = TEST_FILES["AcmeAccount"]["2"]["private_key_cycle"]
        key_filepath = self._filepath_testfile(_key_filename)

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

    @routes_tested(("admin:acme_accounts", "admin:acme_accounts_paginated"))
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/acme-accounts", status=200)
        # paginated
        res = self.testapp.get("/.well-known/admin/acme-accounts/1", status=200)

    @routes_tested(("admin:acme_accounts|json", "admin:acme_accounts_paginated|json"))
    def test_list_json(self):
        # json root
        res = self.testapp.get("/.well-known/admin/acme-accounts.json", status=200)
        assert "AcmeAccounts" in res.json

        # json paginated
        res = self.testapp.get("/.well-known/admin/acme-accounts/1.json", status=200)
        assert "AcmeAccounts" in res.json

    @routes_tested(
        (
            "admin:acme_account:focus",
            "admin:acme_account:focus:acme_authorizations",
            "admin:acme_account:focus:acme_authorizations_paginated",
            "admin:acme_account:focus:acme_orders",
            "admin:acme_account:focus:acme_orders_paginated",
            "admin:acme_account:focus:private_keys",
            "admin:acme_account:focus:private_keys_paginated",
            "admin:acme_account:focus:certificate_signeds",
            "admin:acme_account:focus:certificate_signeds_paginated",
            "admin:acme_account:focus:queue_certificates",
            "admin:acme_account:focus:queue_certificates_paginated",
        )
    )
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()

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
            "/.well-known/admin/acme-account/%s/acme-orders" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/acme-orders/1" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/private-keys" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/private-keys/1" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/certificate-signeds" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/certificate-signeds/1" % focus_id,
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

    @routes_tested(
        (
            "admin:acme_account:focus|json",
            "admin:acme_account:focus:config|json",
            "admin:acme_account:focus:parse|json",
            "admin:acme_account:focus:acme_authorizations|json",
            "admin:acme_account:focus:acme_authorizations_paginated|json",
        )
    )
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s.json" % focus_id, status=200
        )
        assert "AcmeAccount" in res.json
        assert res.json["AcmeAccount"]["id"] == focus_id

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/config.json" % focus_id, status=200
        )
        assert "AcmeAccount" in res.json
        assert res.json["AcmeAccount"]["id"] == focus_id
        assert "is_active" in res.json["AcmeAccount"]
        assert "private_key_cycle" in res.json["AcmeAccount"]
        assert "id" in res.json["AcmeAccount"]
        assert "is_global_default" in res.json["AcmeAccount"]

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/parse.json" % focus_id, status=200
        )
        assert "AcmeAccount" in res.json
        assert res.json["AcmeAccount"]["id"] == focus_id
        assert "AcmeAccountKey" in res.json["AcmeAccount"]
        assert "id" in res.json["AcmeAccount"]["AcmeAccountKey"]
        assert "parsed" in res.json["AcmeAccount"]["AcmeAccountKey"]

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/acme-authorizations.json" % focus_id,
            status=200,
        )
        assert "AcmeAuthorizations" in res.json
        assert "pagination" in res.json

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/acme-authorizations/1.json" % focus_id,
            status=200,
        )
        assert "AcmeAuthorizations" in res.json
        assert "pagination" in res.json

    @routes_tested("admin:acme_account:focus:raw")
    def test_focus_raw(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/key.key" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/key.pem" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/key.pem.txt" % focus_id, status=200
        )

    @routes_tested(("admin:acme_account:focus:edit", "admin:acme_account:focus:mark"))
    def test_manipulate_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/mark" % focus_id,
            status=303,
        )
        assert res.location.endswith("?result=error&error=post+required&operation=mark")

        if focus_item.is_global_default:
            raise ValueError("this should not be the global default")

        if not focus_item.is_active:
            raise ValueError("this should be active")

        # fail making this active
        res = self.testapp.post(
            "/.well-known/admin/acme-account/%s/mark" % focus_id,
            {"action": "active"},
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
            "/.well-known/admin/acme-account/%s/mark" % focus_id,
            {"action": "active"},
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

    @routes_tested(
        (
            "admin:acme_account:focus:edit|json",
            "admin:acme_account:focus:mark|json",
        )
    )
    def test_manipulate_json(self):
        (focus_item, focus_id) = self._get_one()

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
        assert res.json["AcmeAccount"]["id"] == focus_id
        assert res.json["AcmeAccount"]["is_active"] is False

        res = self.testapp.post(
            "/.well-known/admin/acme-account/%s/mark.json" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 200
        assert "AcmeAccount" in res.json
        assert res.json["AcmeAccount"]["id"] == focus_id
        assert res.json["AcmeAccount"]["is_active"] is True

        # then global_default
        res = self.testapp.post(
            "/.well-known/admin/acme-account/%s/mark.json" % focus_id,
            {"action": "global_default"},
        )
        assert res.status_code == 200
        assert "AcmeAccount" in res.json
        assert res.json["AcmeAccount"]["id"] == focus_id
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

        form["account__private_key_technology"] = "RSA"
        res4 = self.testapp.post(
            "/.well-known/admin/acme-account/%s/edit.json" % focus_id, form
        )
        assert res4.json["result"] == "success"
        assert "AcmeAccount" in res4.json

    def test_post_required_json(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `acme-account/new.json`
        res = self.testapp.get("/.well-known/admin/acme-account/new.json", status=200)
        assert "form_fields" in res.json
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-account/upload.json`
        res = self.testapp.get(
            "/.well-known/admin/acme-account/upload.json", status=200
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-account/%s/mark.json`
        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/mark.json" % focus_id,
            status=200,
        )
        assert "form_fields" in res.json
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-account/%s/acme-server/authenticate.json`
        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s/acme-server/authenticate.json"
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
        res = self.testapp.get("/.well-known/admin/acme-authorizations", status=200)
        # paginated
        res = self.testapp.get("/.well-known/admin/acme-authorizations/1", status=200)

    @routes_tested(
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

    @routes_tested("admin:acme_authorization:focus|json")
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s.json" % focus_id, status=200
        )
        assert "AcmeAuthorization" in res.json
        assert res.json["AcmeAuthorization"]["id"] == focus_id

    def test_post_required_html(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `acme-authorization/%s/acme-server/sync`
        # "admin:acme_authorization:focus:sync"
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/sync" % focus_id,
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-authorization/%s?result=error&operation=acme+server+sync&message=HTTP+POST+required"
            % focus_id
        )

        # note: removed `acme-authorization/%s/acme-server/trigger`

        # !!!: test `POST required` `acme-authorization/%s/acme-server/deactivate`
        # "admin:acme_authorization:focus:deactivate"
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/deactivate"
            % focus_id,
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/acme-authorization/%s?result=error&operation=acme+server+deactivate&message=HTTP+POST+required"
            % focus_id
        )

    def test_post_required_json(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `acme-authorization/%s/acme-server/sync.json`
        # "admin:acme_authorization:focus:sync|json"
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/sync.json" % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # note: removed `acme-authorization/%s/acme-server/trigger.json`

        # !!!: test `POST required` `acme-authorization/%s/acme-server/deactivate.json`
        # "admin:acme_authorization:focus:deactivate|json"
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s/acme-server/deactivate.json"
            % focus_id,
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

    @routes_tested(
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

    @routes_tested(("admin:acme_challenge:focus"))
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/acme-challenge/%s" % focus_id, status=200
        )

    @routes_tested(("admin:acme_challenge:focus|json"))
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/acme-challenge/%s.json" % focus_id, status=200
        )
        assert "AcmeChallenge" in res.json
        assert res.json["AcmeChallenge"]["id"] == focus_id

    def test_post_required_html(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `acme-challenge/%s/acme-server/sync`
        # "admin:acme_challenge:focus:acme_server:sync",
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge/%s/acme-server/sync" % focus_id,
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/acme-challenge/%s?result=error&operation=acme+server+sync&message=HTTP+POST+required"
            % focus_id
        )

        # !!!: test `POST required` `acme-challenge/%s/acme-server/trigger`
        # "admin:acme_challenge:focus:acme_server:trigger",
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge/%s/acme-server/trigger" % focus_id,
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/acme-challenge/%s?result=error&operation=acme+server+trigger&message=HTTP+POST+required"
            % focus_id
        )

    def test_post_required_json(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `acme-challenge/%s/acme-server/sync.json`
        # "admin:acme_challenge:focus:acme_server:sync|json",
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge/%s/acme-server/sync.json" % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-challenge/%s/acme-server/trigger.json`
        # "admin:acme_challenge:focus:acme_server:trigger|json",
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge/%s/acme-server/trigger.json" % focus_id,
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
        res = self.testapp.get("/.well-known/admin/acme-challenge-polls", status=200)
        # paginated
        res = self.testapp.get("/.well-known/admin/acme-challenge-polls/1", status=200)

    @routes_tested(
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
            "/.well-known/admin/acme-challenge-unknown-polls", status=200
        )
        # paginated
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge-unknown-polls/1", status=200
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


class FunctionalTests_AcmeDnsServer(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeDnsServer
    """

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
        res = self.testapp.get("/.well-known/admin/acme-dns-servers", status=200)
        # paginated
        res = self.testapp.get("/.well-known/admin/acme-dns-servers/1", status=200)

    @routes_tested(
        ("admin:acme_dns_servers|json", "admin:acme_dns_servers_paginated|json")
    )
    def test_list_json(self):
        # json root
        res = self.testapp.get("/.well-known/admin/acme-dns-servers.json", status=200)
        assert "AcmeDnsServers" in res.json
        # json paginated
        res = self.testapp.get("/.well-known/admin/acme-dns-servers/1.json", status=200)
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
            "/.well-known/admin/acme-dns-server/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-dns-server/%s/acme-dns-server-accounts" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-dns-server/%s/acme-dns-server-accounts/1"
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
            "/.well-known/admin/acme-dns-server/%s.json" % focus_id, status=200
        )
        assert "AcmeDnsServer" in res.json
        assert res.json["AcmeDnsServer"]["id"] == focus_id

        res = self.testapp.get(
            "/.well-known/admin/acme-dns-server/%s/acme-dns-server-accounts.json"
            % focus_id,
            status=200,
        )
        assert "AcmeDnsServer" in res.json
        assert res.json["AcmeDnsServer"]["id"] == focus_id
        assert "AcmeDnsServerAccounts" in res.json

        res = self.testapp.get(
            "/.well-known/admin/acme-dns-server/%s/acme-dns-server-accounts/1.json"
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
                "/.well-known/admin/acme-dns-server/%s" % _item_id, status=200
            )
            assert "set Global Default" in res.text
            assert "form-mark-global_default" in res.forms
            form = res.forms["form-mark-global_default"]
            res2 = form.submit()
            assert res2.status_code == 303
            assert RE_AcmeDnsServer_marked_global_default.match(res2.location)

        def _make_inactive(_item_id):
            res = self.testapp.get(
                "/.well-known/admin/acme-dns-server/%s" % _item_id, status=200
            )
            assert "Deactivate" in res.text
            assert "form-mark-inactive" in res.forms
            form = res.forms["form-mark-inactive"]
            res2 = form.submit()
            assert res2.status_code == 303
            assert RE_AcmeDnsServer_marked_inactive.match(res2.location)

        def _make_active(_item_id):
            res = self.testapp.get(
                "/.well-known/admin/acme-dns-server/%s" % _item_id, status=200
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
                "/.well-known/admin/acme-dns-server/%s" % _item_id, status=200
            )
            assert ("/acme-dns-server/%s/edit" % _item_id) in res.text
            res = self.testapp.get(
                "/.well-known/admin/acme-dns-server/%s/edit" % _item_id, status=200
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

        # ok our tests!

        # obj 1
        (focus_item, focus_id) = self._get_one()

        # obj 2
        (alt_item, alt_id) = self._get_one(id_not=focus_id)

        # test mark: global_default
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
        url_og = alt_item.root_url

        # fail editing the url
        _edit_url(alt_id, url_og, expect_failure_nochange=True)

        # make the url silly, then make it real
        _edit_url(alt_id, url_og + "123")
        _edit_url(alt_id, url_og)

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
                "/.well-known/admin/acme-dns-server/%s.json" % _item_id, status=200
            )
            assert "AcmeDnsServer" in res.json
            assert res.json["AcmeDnsServer"]["id"] == _item_id
            assert res.json["AcmeDnsServer"]["is_global_default"] is False

            res2 = self.testapp.get(
                "/.well-known/admin/acme-dns-server/%s/mark.json" % _item_id, status=200
            )
            assert "instructions" in res2.json

            res3 = self.testapp.post(
                "/.well-known/admin/acme-dns-server/%s/mark.json" % _item_id,
                {},
                status=200,
            )
            assert res3.json["result"] == "error"
            assert "form_errors" in res3.json
            assert res3.json["form_errors"]["Error_Main"] == "Nothing submitted."

            res4 = self.testapp.post(
                "/.well-known/admin/acme-dns-server/%s/mark.json" % _item_id,
                {"action": "global_default"},
                status=200,
            )
            assert res4.json["result"] == "success"
            assert "AcmeDnsServer" in res4.json
            assert res4.json["AcmeDnsServer"]["is_global_default"] is True

        def _make_inactive(_item_id):
            res = self.testapp.get(
                "/.well-known/admin/acme-dns-server/%s.json" % _item_id, status=200
            )
            assert "AcmeDnsServer" in res.json
            assert res.json["AcmeDnsServer"]["id"] == _item_id
            assert res.json["AcmeDnsServer"]["is_active"] is True

            res2 = self.testapp.get(
                "/.well-known/admin/acme-dns-server/%s/mark.json" % _item_id, status=200
            )
            assert "instructions" in res2.json

            res3 = self.testapp.post(
                "/.well-known/admin/acme-dns-server/%s/mark.json" % _item_id,
                {},
                status=200,
            )
            assert res3.json["result"] == "error"
            assert "form_errors" in res3.json
            assert res3.json["form_errors"]["Error_Main"] == "Nothing submitted."

            res4 = self.testapp.post(
                "/.well-known/admin/acme-dns-server/%s/mark.json" % _item_id,
                {"action": "inactive"},
                status=200,
            )
            assert res4.json["result"] == "success"
            assert "AcmeDnsServer" in res4.json
            assert res4.json["AcmeDnsServer"]["is_active"] is False

        def _make_active(_item_id):
            res = self.testapp.get(
                "/.well-known/admin/acme-dns-server/%s.json" % _item_id, status=200
            )
            assert "AcmeDnsServer" in res.json
            assert res.json["AcmeDnsServer"]["id"] == _item_id
            assert res.json["AcmeDnsServer"]["is_active"] is False

            res2 = self.testapp.get(
                "/.well-known/admin/acme-dns-server/%s/mark.json" % _item_id, status=200
            )
            assert "instructions" in res2.json

            res3 = self.testapp.post(
                "/.well-known/admin/acme-dns-server/%s/mark.json" % _item_id,
                {},
                status=200,
            )
            assert res3.json["result"] == "error"
            assert "form_errors" in res3.json
            assert res3.json["form_errors"]["Error_Main"] == "Nothing submitted."

            res4 = self.testapp.post(
                "/.well-known/admin/acme-dns-server/%s/mark.json" % _item_id,
                {"action": "active"},
                status=200,
            )
            assert res4.json["result"] == "success"
            assert "AcmeDnsServer" in res4.json
            assert res4.json["AcmeDnsServer"]["is_active"] is True

        def _edit_url(_item_id, _root_url, expect_failure_nochange=False):
            res = self.testapp.get(
                "/.well-known/admin/acme-dns-server/%s.json" % _item_id, status=200
            )
            assert res.json["AcmeDnsServer"]["id"] == _item_id
            assert "AcmeDnsServer" in res.json

            res2 = self.testapp.get(
                "/.well-known/admin/acme-dns-server/%s/edit.json" % _item_id, status=200
            )
            assert "instructions" in res2.json

            res3 = self.testapp.post(
                "/.well-known/admin/acme-dns-server/%s/edit.json" % _item_id,
                {},
                status=200,
            )
            assert res3.json["result"] == "error"
            assert "form_errors" in res3.json
            assert res3.json["form_errors"]["Error_Main"] == "Nothing submitted."

            if not expect_failure_nochange:
                res4 = self.testapp.post(
                    "/.well-known/admin/acme-dns-server/%s/edit.json" % _item_id,
                    {"root_url": _root_url},
                    status=200,
                )
                assert res4.json["result"] == "success"
                assert "AcmeDnsServer" in res4.json
                assert res4.json["AcmeDnsServer"]["root_url"] == _root_url
            else:
                res4 = self.testapp.post(
                    "/.well-known/admin/acme-dns-server/%s/edit.json" % _item_id,
                    {"root_url": _root_url},
                    status=200,
                )
                assert res4.json["result"] == "error"
                assert "form_errors" in res4.json
                assert (
                    res4.json["form_errors"]["Error_Main"]
                    == "There was an error with your form. No change"
                )

        # ok our tests!

        # obj 1
        (focus_item, focus_id) = self._get_one()

        # obj 2
        (alt_item, alt_id) = self._get_one(id_not=focus_id)

        # test mark: global_default
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
        url_og = alt_item.root_url

        # fail editing the url
        _edit_url(alt_id, url_og, expect_failure_nochange=True)

        # make the url silly, then make it real
        _edit_url(alt_id, url_og + "123")
        _edit_url(alt_id, url_og)

    @unittest.skipUnless(RUN_API_TESTS__ACME_DNS_API, "Not Running Against: acme-dns")
    @routes_tested(("admin:acme_dns_server:focus:check",))
    def test_against_acme_dns__html(self):
        (focus_item, focus_id) = self._get_one()
        res = self.testapp.get(
            "/.well-known/admin/acme-dns-server/%s" % focus_id, status=200
        )
        assert "form-check" in res.forms
        form = res.forms["form-check"]
        res = form.submit()
        assert res.status_code == 303
        assert RE_AcmeDnsServer_checked.match(res.location)

    @unittest.skipUnless(RUN_API_TESTS__ACME_DNS_API, "Not Running Against: acme-dns")
    @routes_tested(("admin:acme_dns_server:focus:check|json",))
    def test_against_acme_dns__json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.post(
            "/.well-known/admin/acme-dns-server/%s/check.json" % focus_id,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["health"] == True

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
        res = self.testapp.get("/.well-known/admin/acme-dns-server/new", status=200)
        form = res.form
        form["root_url"] = TEST_FILES["AcmeDnsServer"]["3"]["root_url"]
        res2 = form.submit()

        matched = RE_AcmeDnsServer_created.match(res2.location)
        assert matched
        obj_id = matched.groups()[0]

        res = self.testapp.get(
            "/.well-known/admin/acme-dns-server/%s" % obj_id, status=200
        )

        # ensure-domains
        # use ._get_one() so the real server is used
        (focus_item, focus_id) = self._get_one()
        res = self.testapp.get(
            "/.well-known/admin/acme-dns-server/%s/ensure-domains" % focus_id,
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
        assert RE_AcmeDnsServer_ensure_domains_results.match(res2.location)

        # import_domain
        # use ._get_one() so the real server is used
        res = self.testapp.get(
            "/.well-known/admin/acme-dns-server/%s/import-domain" % focus_id,
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

        res = self.testapp.post(
            "/.well-known/admin/acme-dns-server/new.json", {}, status=200
        )
        assert res.json["result"] == "error"
        assert "form_errors" in res.json
        assert res.json["form_errors"]["Error_Main"] == "Nothing submitted."

        _payload = {"root_url": TEST_FILES["AcmeDnsServer"]["4"]["root_url"]}
        res = self.testapp.post(
            "/.well-known/admin/acme-dns-server/new.json", _payload, status=200
        )
        assert res.json["result"] == "success"
        assert res.json["is_created"] is True
        assert "AcmeDnsServer" in res.json

        obj_id = res.json["AcmeDnsServer"]["id"]

        # ensure-domains
        # use ._get_one() so the real server is used
        (focus_item, focus_id) = self._get_one()
        res = self.testapp.get(
            "/.well-known/admin/acme-dns-server/%s/ensure-domains.json" % focus_id,
            status=200,
        )
        assert "domain_names" in res.json["form_fields"]

        res = self.testapp.post(
            "/.well-known/admin/acme-dns-server/%s/ensure-domains.json" % focus_id,
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
            "/.well-known/admin/acme-dns-server/%s/ensure-domains.json" % focus_id,
            _payload,
            status=200,
        )
        assert res.json["result"] == "success"
        assert "result_matrix" in res.json

        _account_ids = [
            "%s" % res.json["result_matrix"][_domain]["AcmeDnsServerAccount"]["id"]
            for _domain in res.json["result_matrix"].keys()
        ]
        res = self.testapp.get(
            "/.well-known/admin/acme-dns-server/%s/ensure-domains-results.json?acme-dns-server-accounts=%s"
            % (focus_id, ",".join(_account_ids))
        )

        # import-domain
        # use ._get_one() so the real server is used
        res = self.testapp.get(
            "/.well-known/admin/acme-dns-server/%s/import-domain.json" % focus_id,
            status=200,
        )
        _intended_payload = TEST_FILES["Domains"]["AcmeDnsServer"]["1"][
            "import-domain.json"
        ]["payload"]
        for k in _intended_payload.keys():
            assert k in res.json["form_fields"]

        res = self.testapp.post(
            "/.well-known/admin/acme-dns-server/%s/import-domain.json" % focus_id,
            status=200,
        )
        assert res.json["result"] == "error"
        assert "form_errors" in res.json
        assert res.json["form_errors"]["Error_Main"] == "Nothing submitted."

        res = self.testapp.post(
            "/.well-known/admin/acme-dns-server/%s/import-domain.json" % focus_id,
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
            "/.well-known/admin/acme-dns-server/%s/import-domain.json" % focus_id,
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

    def test_post_required_json(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `acme-dns-server/%s/check.json`
        res = self.testapp.get(
            "/.well-known/admin/acme-dns-server/%s/check.json" % focus_id, status=200
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-dns-server/new.json`
        res = self.testapp.get(
            "/.well-known/admin/acme-dns-server/new.json", status=200
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
            "/.well-known/admin/acme-dns-server-accounts", status=200
        )
        # paginated
        res = self.testapp.get(
            "/.well-known/admin/acme-dns-server-accounts/1", status=200
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
            "/.well-known/admin/acme-dns-server-accounts.json", status=200
        )
        assert "AcmeDnsServerAccounts" in res.json
        # json paginated
        res = self.testapp.get(
            "/.well-known/admin/acme-dns-server-accounts/1.json", status=200
        )
        assert "AcmeDnsServerAccounts" in res.json

    @routes_tested(("admin:acme_dns_server_account:focus",))
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/acme-dns-server-account/%s" % focus_id, status=200
        )

    @routes_tested(("admin:acme_dns_server_account:focus|json",))
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/acme-dns-server-account/%s.json" % focus_id, status=200
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
        res = self.testapp.get("/.well-known/admin/acme-event-logs", status=200)
        # paginated
        res = self.testapp.get("/.well-known/admin/acme-event-logs/1", status=200)

    @routes_tested(("admin:acme_event_log|json", "admin:acme_event_log_paginated|json"))
    def test_list_json(self):
        # json root
        res = self.testapp.get("/.well-known/admin/acme-event-logs.json", status=200)
        assert "AcmeEventLogs" in res.json
        # json paginated
        res = self.testapp.get("/.well-known/admin/acme-event-logs/1.json", status=200)
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
            "/.well-known/admin/acme-event-log/%s" % focus_id, status=200
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
            "/.well-known/admin/acme-event-log/%s.json" % focus_id, status=200
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
        res = self.testapp.get("/.well-known/admin/acme-orders", status=303)
        assert (
            res.location
            == """http://peter-sslers.example.com/.well-known/admin/acme-orders/active"""
        )

        for _type in (
            "all",
            "active",
            "finished",
        ):
            res = self.testapp.get(
                "/.well-known/admin/acme-orders/%s" % _type, status=200
            )
            res = self.testapp.get(
                "/.well-known/admin/acme-orders/%s/1" % _type, status=200
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
        res = self.testapp.get("/.well-known/admin/acme-orders.json", status=303)
        assert (
            res.location
            == """http://peter-sslers.example.com/.well-known/admin/acme-orders/active.json"""
        )

        for _type in (
            "all",
            "active",
            "finished",
        ):
            res = self.testapp.get(
                "/.well-known/admin/acme-orders/%s.json" % _type, status=200
            )
            assert "AcmeOrders" in res.json
            res = self.testapp.get(
                "/.well-known/admin/acme-orders/%s/1.json" % _type, status=200
            )
            assert "AcmeOrders" in res.json

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(("admin:acme_orders:active:acme_server:sync",))
    def test_active_acme_server_sync_html(self):
        res = self.testapp.get(
            "/.well-known/admin/acme-orders/active/acme-server/sync", status=303
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-orders/active?result=error&operation=acme+server+sync&message=HTTP+POST+required"
        )
        res = self.testapp.post(
            "/.well-known/admin/acme-orders/active/acme-server/sync", {}, status=303
        )
        assert res.location.startswith(
            "http://peter-sslers.example.com/.well-known/admin/acme-orders/active?result=success&operation=acme+server+sync&acme_order_ids.success="
        )

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(("admin:acme_orders:active:acme_server:sync|json",))
    def test_active_acme_server_sync_json(self):
        res = self.testapp.get(
            "/.well-known/admin/acme-orders/active/acme-server/sync.json", status=200
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        res = self.testapp.post(
            "/.well-known/admin/acme-orders/active/acme-server/sync.json",
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
            "/.well-known/admin/acme-order/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-event-logs" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-event-logs/1" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/audit" % focus_id, status=200
        )

    @routes_tested(("admin:acme_order:focus|json", "admin:acme_order:focus:audit|json"))
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % focus_id, status=200
        )
        assert "AcmeOrder" in res.json
        assert res.json["AcmeOrder"]["id"] == focus_id

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

    def test_post_required_html(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `acme-order/%s/acme-server/sync`
        # "admin:acme_order:focus:acme_server:sync",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-server/sync" % focus_id, status=303
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=error&operation=acme+server+sync&message=HTTP+POST+required"
            % focus_id
        )

        # !!!: test `POST required` `acme-order/%s/acme-server/sync-authorizations`
        # "admin:acme_order:focus:acme_server:sync_authorizations",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-server/sync-authorizations"
            % focus_id,
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=error&operation=acme+server+sync+authorizations&message=HTTP+POST+required"
            % focus_id
        )

        # !!!: test `POST required` `acme-order/%s/acme-finalize`
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-finalize" % focus_id, status=303
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=error&operation=acme+finalize&message=HTTP+POST+required"
            % focus_id
        )

        # !!!: test `POST required` `acme-order/%s/acme-server/deactivate-authorizations`
        # "admin:acme_order:focus:acme_server:deactivate_authorizations",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-server/deactivate-authorizations"
            % focus_id,
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=error&operation=acme+server+deactivate+authorizations&message=HTTP+POST+required"
            % focus_id
        )

        # !!!: test `POST required` `acme-order/%s/mark`
        # "admin:acme_order:focus:mark",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/mark?action=deactivate" % focus_id,
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=error&operation=mark&message=HTTP+POST+required"
            % focus_id
        )

        # !!!: test `POST required` `acme-order/%s/acme-process`
        # "admin:acme_order:focus:acme-process",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-process" % focus_id,
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=error&operation=acme+process&message=HTTP+POST+required"
            % focus_id
        )

    def test_post_required_json(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `acme-order/%s/acme-server/sync.json`
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-server/sync.json" % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-order/%s/acme-server/sync-authorizations.json`
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-server/sync-authorizations.json"
            % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-order/%s/acme-finalize.json`
        # "admin:acme_order:focus:acme_finalize|json",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-finalize.json" % focus_id, status=200
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-order/%s/acme-server/deactivate-authorizations.json`
        # "admin:acme_order:focus:acme_server:deactivate_authorizations",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-server/deactivate-authorizations.json"
            % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-order/%s/mark.json`
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/mark.json?action=deactivate" % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-order/%s/acme-process.json`
        # "admin:acme_order:focus:acme-process",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-process.json" % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-order/new/freeform.json`
        res = self.testapp.get(
            "/.well-known/admin/acme-order/new/freeform.json", status=200
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-order/%s/renew/quick.json`
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/renew/quick.json" % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `acme-order/%s/renew/custom.json`
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/renew/custom.json" % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]


class FunctionalTests_AcmeOrderless(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeOrderless
    """

    def _get_one(self):
        # grab an order
        focus_item = (
            self.ctx.dbSession.query(model_objects.AcmeOrderless)
            .order_by(model_objects.AcmeOrderless.id.asc())
            .first()
        )
        assert focus_item is not None
        return focus_item, focus_item.id

    @routes_tested(
        (
            "admin:acme_orderlesss",
            "admin:acme_orderlesss_paginated",
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/acme-orderlesss", status=200)
        res = self.testapp.get("/.well-known/admin/acme-orderlesss/1", status=200)

    @routes_tested(
        (
            "admin:acme_orderlesss|json",
            "admin:acme_orderlesss_paginated|json",
        )
    )
    def test_list_json(self):
        # json root
        res = self.testapp.get("/.well-known/admin/acme-orderlesss.json", status=200)
        assert "AcmeOrderless" in res.json
        res = self.testapp.get("/.well-known/admin/acme-orderlesss/1.json", status=200)
        assert "AcmeOrderless" in res.json

    @routes_tested(("admin:acme_orderless:focus",))
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()
        challenge_id = focus_item.acme_challenges[0].id

        res = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s/acme-challenge/%s"
            % (focus_id, challenge_id),
            status=200,
        )

    @routes_tested(("admin:acme_orderless:focus|json",))
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()
        challenge_id = focus_item.acme_challenges[0].id

        res = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s.json" % focus_id, status=200
        )
        assert "AcmeOrderless" in res.json
        assert res.json["AcmeOrderless"]["id"] == focus_id

        res = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s/acme-challenge/%s.json"
            % (focus_id, challenge_id),
            status=200,
        )
        assert "AcmeOrderless" in res.json
        assert "AcmeChallenge" in res.json

    @routes_tested(
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
        form["domain_names_http01"] = ",".join(
            TEST_FILES["AcmeOrderless"]["new-1"]["domain_names_http01"]
        )
        res2 = form.submit()
        assert res2.status_code == 303

        matched = RE_AcmeOrderless.match(res2.location)
        assert matched
        obj_id = matched.groups()[0]

        # build a new form and submit edits
        res3 = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s" % obj_id,
            status=200,
        )
        form = res3.forms["acmeorderless-update"]
        update_fields = dict(form.submit_fields())
        _challenge_ids = update_fields["_challenges"].split(",")
        assert len(_challenge_ids) == len(
            TEST_FILES["AcmeOrderless"]["new-1"]["domain_names_http01"]
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
            "/.well-known/admin/acme-orderless/%s?result=success" % obj_id,
            status=200,
        )

        # build a new form to assert the previous edits worked
        form = res5.forms["acmeorderless-update"]
        update_fields = dict(form.submit_fields())
        _challenge_ids = update_fields["_challenges"].split(",")
        assert len(_challenge_ids) == len(
            TEST_FILES["AcmeOrderless"]["new-1"]["domain_names_http01"]
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
        assert "acme_challenge_type" in add_fields
        form["keyauthorization"] = "keyauthorization_add"
        form["domain"] = "domain_add.example.com"
        form["token"] = "token_add"
        form["acme_challenge_type"] = "http-01"

        res6 = form.submit()
        assert res6.status_code == 303
        assert (
            res6.location
            == "http://peter-sslers.example.com/.well-known/admin/acme-orderless/%s?result=success"
            % obj_id
        )
        res7 = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s?status=success" % obj_id,
            status=200,
        )

        form = res7.forms["acmeorderless-update"]
        update_fields = dict(form.submit_fields())
        _challenge_ids = update_fields["_challenges"].split(",")
        # we just added 1
        assert len(_challenge_ids) == (
            len(TEST_FILES["AcmeOrderless"]["new-1"]["domain_names_http01"]) + 1
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
            "/.well-known/admin/acme-orderless/%s?result=success" % obj_id,
            status=200,
        )
        assert not res9.forms

        res10 = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s/acme-challenge/%s"
            % (obj_id, _challenge_ids[0]),
            status=200,
        )

    @routes_tested(
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
        form["domain_names_http01"] = ",".join(
            TEST_FILES["AcmeOrderless"]["new-1"]["domain_names_http01"]
        )
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
            "/.well-known/admin/acme-orderless/%s.json" % obj_id,
            status=200,
        )
        assert "AcmeOrderless" in res3.json
        assert "forms" in res3.json
        assert "acmeorderless-update" in res3.json["forms"]

        # build a new form and submit edits
        form = res3.json["forms"]["acmeorderless-update"]
        update_fields = dict(form.items())
        _challenge_ids = update_fields["_challenges"].split(",")
        assert len(_challenge_ids) == len(
            TEST_FILES["AcmeOrderless"]["new-1"]["domain_names_http01"]
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
            "/.well-known/admin/acme-orderless/%s.json" % obj_id,
            status=200,
        )
        assert "AcmeOrderless" in res3.json
        assert "forms" in res3.json
        assert "acmeorderless-update" in res3.json["forms"]
        form = res3.json["forms"]["acmeorderless-update"]
        update_fields = dict(form.items())
        _challenge_ids = update_fields["_challenges"].split(",")
        assert len(_challenge_ids) == len(
            TEST_FILES["AcmeOrderless"]["new-1"]["domain_names_http01"]
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
        assert "acme_challenge_type" in add_fields
        add_fields["keyauthorization"] = "keyauthorization_add"
        add_fields["domain"] = "domain_add.example.com"
        add_fields["token"] = "token_add"
        add_fields["acme_challenge_type"] = "http-01"

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
    python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeAccountProvider
    """

    @routes_tested("admin:acme_account_providers")
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/acme-account-providers", status=200)

    @routes_tested("admin:acme_account_providers|json")
    def test_list_json(self):
        # json root
        res = self.testapp.get(
            "/.well-known/admin/acme-account-providers.json", status=200
        )
        assert "AcmeAccountProviders" in res.json


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
        res = self.testapp.get("/.well-known/admin/certificate-cas", status=200)
        # paginated
        res = self.testapp.get("/.well-known/admin/certificate-cas/1", status=200)

    @routes_tested(
        (
            "admin:certificate_cas|json",
            "admin:certificate_cas_paginated|json",
        )
    )
    def test_list_json(self):
        # JSON root
        res = self.testapp.get("/.well-known/admin/certificate-cas.json", status=200)
        assert "CertificateCAs" in res.json

        # JSON paginated
        res = self.testapp.get("/.well-known/admin/certificate-cas/1.json", status=200)
        assert "CertificateCAs" in res.json

    @routes_tested(
        (
            "admin:certificate_ca:focus",
            "admin:certificate_ca:focus:raw",
            "admin:certificate_ca:focus:certificate_signeds",
            "admin:certificate_ca:focus:certificate_signeds_paginated",
        )
    )
    def test_focus_html(self):
        res = self.testapp.get("/.well-known/admin/certificate-ca/1", status=200)
        res = self.testapp.get(
            "/.well-known/admin/certificate-ca/1/chain.cer", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-ca/1/chain.crt", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-ca/1/chain.der", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-ca/1/chain.pem", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-ca/1/chain.pem.txt", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-ca/1/certificate-signeds", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-ca/1/certificate-signeds/1", status=200
        )

    @routes_tested(
        (
            "admin:certificate_ca:focus|json",
            "admin:certificate_ca:focus:parse|json",
        )
    )
    def test_focus_json(self):
        res = self.testapp.get("/.well-known/admin/certificate-ca/1.json", status=200)
        res = self.testapp.get(
            "/.well-known/admin/certificate-ca/1/parse.json", status=200
        )
        assert "CertificateCA" in res.json
        assert "id" in res.json["CertificateCA"]
        assert "parsed" in res.json["CertificateCA"]

    @routes_tested(
        (
            "admin:certificate_ca:upload",
            "admin:certificate_ca:upload_bundle",
        )
    )
    def test_upload_html(self):
        """This should enter in item #8, but the CertificateCAs.order is 0. At this point, the only CA Cert that is not self-signed should be `ISRG Root X1`"""
        _cert_ca_id = TEST_FILES["CertificateCAs"]["order"][0]
        self.assertEqual(_cert_ca_id, "trustid_root_x3")
        _cert_ca_filename = TEST_FILES["CertificateCAs"]["cert"][_cert_ca_id]
        _cert_ca_filepath = self._filepath_testfile(_cert_ca_filename)

        res = self.testapp.get("/.well-known/admin/certificate-ca/upload", status=200)
        form = res.form
        form["chain_file"] = Upload(_cert_ca_filepath)
        res2 = form.submit()
        assert res2.status_code == 303

        matched = RE_CertificateCA_uploaded.match(res2.location)

        # this querystring ends: ?result=success&is_created=0'
        _is_created = bool(int(res2.location[-1]))

        # focus_items = self.ctx.dbSession.query(model_objects.CertificateCA).all()
        # pdb.set_trace()

        assert matched
        obj_id = matched.groups()[0]
        res3 = self.testapp.get(res2.location, status=200)

        # try a bundle
        res = self.testapp.get(
            "/.well-known/admin/certificate-ca/upload-bundle", status=200
        )
        form = res.form
        _fields = [i[0] for i in form.submit_fields()]
        for _cert_id in letsencrypt_info.CA_LE_BUNDLE_SUPPORTED:
            _field_base = letsencrypt_info.CERT_CAS_DATA[_cert_id]["formfield_base"]
            _field = "%s_file" % _field_base
            self.assertIn(_field, _fields)
            form[_field] = Upload(
                self._filepath_testfile(TEST_FILES["CertificateCAs"]["cert"][_cert_id])
            )

        res2 = form.submit()
        assert res2.status_code == 303
        assert (
            res2.location
            == """http://peter-sslers.example.com/.well-known/admin/certificate-cas?uploaded=1"""
        )
        res3 = self.testapp.get(res2.location, status=200)

        """This should enter in item #4"""
        _cert_ca_id = TEST_FILES["CertificateCAs"]["order"][2]
        _cert_ca_filename = TEST_FILES["CertificateCAs"]["cert"][_cert_ca_id]
        _cert_ca_filepath = self._filepath_testfile(_cert_ca_filename)

    @routes_tested(
        (
            "admin:certificate_ca:upload|json",
            "admin:certificate_ca:upload_bundle|json",
        )
    )
    def test_upload_json(self):
        """This should enter in item #9, but the CertificateCAs.order is 0. At this point, the only CA Cert that is not self-signed should be `ISRG Root X1` and the trustid from `test_upload_html`"""
        _cert_ca_id = TEST_FILES["CertificateCAs"]["order"][2]
        self.assertEqual(_cert_ca_id, "isrg_root_x2")
        _cert_ca_filename = TEST_FILES["CertificateCAs"]["cert"][_cert_ca_id]
        _cert_ca_filepath = self._filepath_testfile(_cert_ca_filename)

        res = self.testapp.get(
            "/.well-known/admin/certificate-ca/upload.json", status=200
        )
        _data = {"chain_file": Upload(_cert_ca_filepath)}
        res2 = self.testapp.post("/.well-known/admin/certificate-ca/upload.json", _data)
        assert res2.status_code == 200
        assert res2.json["result"] == "success"

        # we may not have created this
        assert res2.json["CertificateCA"]["created"] in (True, False)
        assert (
            res2.json["CertificateCA"]["id"] > 2
        )  # the database was set up with 2 items
        obj_id = res2.json["CertificateCA"]["id"]

        res3 = self.testapp.get(
            "/.well-known/admin/certificate-ca/%s" % obj_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-ca/upload-bundle.json", status=200
        )
        chain_filepath = self._filepath_testfile("lets-encrypt-x1-cross-signed.pem.txt")
        form = {}

        for _cert_id in letsencrypt_info.CA_LE_BUNDLE_SUPPORTED:
            _field_base = letsencrypt_info.CERT_CAS_DATA[_cert_id]["formfield_base"]
            _field = "%s_file" % _field_base
            form[_field] = Upload(
                self._filepath_testfile(TEST_FILES["CertificateCAs"]["cert"][_cert_id])
            )

        res2 = self.testapp.post(
            "/.well-known/admin/certificate-ca/upload-bundle.json", form
        )
        assert res2.status_code == 200
        assert res2.json["result"] == "success"
        # this is going to be too messy to check all the vars
        # {u'isrgrootx1_pem': {u'id': 5, u'created': False}, u'le_int_x2_pem': {u'id': 3, u'created': False}, u'letsencrypt_intermediate_x4_cross_pem': {u'id': 6, u'created': False}, u'letsencrypt_intermediate_x2_cross_pem': {u'id': 7, u'created': False}, u'letsencrypt_intermediate_x3_cross_pem': {u'id': 8, u'created': False}, u'result': u'success', u'letsencrypt_intermediate_x1_cross_pem': {u'id': 4, u'created': False}, u'le_int_x1_pem': {u'id': 1, u'created': False}}

    def _expected_preferences(self):
        """this is shared by html and json"""
        # when we initialize the application, the setup routine inserts some
        # default CertificateCA preferences
        expected_preferences_initial = (
            ("1", "DA:C9:02"),  # trustid_root_x3
            ("2", "BD:B1:B9"),  # isrg_root_x2
            ("3", "CA:BD:2A"),  # isrg_root_x1
        )
        # calculate the expected matrix after an alteration
        # in this alteration, we swap the first and second items
        expected_preferences_altered = [i[1] for i in expected_preferences_initial]
        expected_preferences_altered.insert(0, expected_preferences_altered.pop(1))
        expected_preferences_altered = [
            (str(idx + 1), i) for (idx, i) in enumerate(expected_preferences_altered)
        ]

        return (expected_preferences_initial, expected_preferences_altered)

    def _load__CertificateCAPreferences(self):
        _dbCertificateCAPreferences = (
            self.ctx.dbSession.query(model_objects.CertificateCAPreference)
            .options(sqlalchemy.orm.joinedload("certificate_ca"))
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
            .filter(model_objects.CertificateCAPreference.id.op("IS")(None))
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
            "/.well-known/admin/certificate-cas/preferred", status=200
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
            == "http://peter-sslers.example.com/.well-known/admin/certificate-cas/preferred?result=success&operation=prioritize"
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
            == "http://peter-sslers.example.com/.well-known/admin/certificate-cas/preferred?result=success&operation=prioritize"
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
            "/.well-known/admin/certificate-cas/preferred", status=200
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
            == "http://peter-sslers.example.com/.well-known/admin/certificate-cas/preferred?result=success&operation=add"
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
            == "http://peter-sslers.example.com/.well-known/admin/certificate-cas/preferred?result=success&operation=delete"
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
            "/.well-known/admin/certificate-cas/preferred", status=200
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
            "/.well-known/admin/certificate-cas/preferred.json", status=200
        )
        _ensure_compliance_payload(res, expected_preferences_initial)

        # ensure GET/POST core functionality

        # GET/POST prioritize
        res = self.testapp.get(
            "/.well-known/admin/certificate-cas/preferred/prioritize.json", status=200
        )
        assert "form_fields" in res.json
        _expected_fields = ("slot", "fingerprint_sha1", "priority")
        assert len(res.json["form_fields"]) == len(_expected_fields)
        for _field in _expected_fields:
            assert _field in res.json["form_fields"]
        res = self.testapp.post(
            "/.well-known/admin/certificate-cas/preferred/prioritize.json"
        )
        assert res.json["result"] == "error"
        assert "Error_Main" in res.json["form_errors"]
        assert res.json["form_errors"]["Error_Main"] == "Nothing submitted."

        # GET/POST add
        res = self.testapp.get(
            "/.well-known/admin/certificate-cas/preferred/add.json", status=200
        )
        assert "form_fields" in res.json
        _expected_fields = ("fingerprint_sha1",)
        assert len(res.json["form_fields"]) == len(_expected_fields)
        for _field in _expected_fields:
            assert _field in res.json["form_fields"]
        res = self.testapp.post("/.well-known/admin/certificate-cas/preferred/add.json")
        assert res.json["result"] == "error"
        assert "Error_Main" in res.json["form_errors"]
        assert res.json["form_errors"]["Error_Main"] == "Nothing submitted."

        # GET/POST delete
        res = self.testapp.get(
            "/.well-known/admin/certificate-cas/preferred/delete.json", status=200
        )
        assert "form_fields" in res.json
        _expected_fields = ("fingerprint_sha1", "slot")
        assert len(res.json["form_fields"]) == len(_expected_fields)
        for _field in _expected_fields:
            assert _field in res.json["form_fields"]
        res = self.testapp.post(
            "/.well-known/admin/certificate-cas/preferred/delete.json"
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
            "/.well-known/admin/certificate-cas/preferred/prioritize.json", _payload
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
            "/.well-known/admin/certificate-cas/preferred/prioritize.json", _payload
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
            "/.well-known/admin/certificate-cas/preferred/prioritize.json", _payload
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
            "/.well-known/admin/certificate-cas/preferred/prioritize.json", _payload
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
            "/.well-known/admin/certificate-cas/preferred/prioritize.json", _payload
        )
        assert res.status_code == 200
        assert res.json["result"] == "success"
        assert res.json["operation"] == "prioritize"

        # now, do this again.
        # we should FAIL because it is stale
        res = self.testapp.post(
            "/.well-known/admin/certificate-cas/preferred/prioritize.json", _payload
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
            "/.well-known/admin/certificate-cas/preferred/prioritize.json", _payload
        )
        assert res.status_code == 200
        assert res.json["result"] == "success"
        assert res.json["operation"] == "prioritize"

        # now, do this again.
        # we should FAIL because it is stale
        res = self.testapp.post(
            "/.well-known/admin/certificate-cas/preferred/prioritize.json", _payload
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
            "/.well-known/admin/certificate-cas/preferred/add.json", _payload
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
            "/.well-known/admin/certificate-cas/preferred.json", status=200
        )
        _ensure_compliance_payload(res, expected_preferences_added)

        # delete
        _payload = {"slot": 4, "fingerprint_sha1": dbCertificateCA_add.fingerprint_sha1}
        res = self.testapp.post(
            "/.well-known/admin/certificate-cas/preferred/delete.json", _payload
        )
        assert res.status_code == 200
        assert res.json["result"] == "success"
        assert res.json["operation"] == "delete"

        # delete again, we should fail!
        res = self.testapp.post(
            "/.well-known/admin/certificate-cas/preferred/delete.json", _payload
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
            "/.well-known/admin/certificate-cas/preferred.json", status=200
        )
        _ensure_compliance_payload(res, expected_preferences_initial)

        # TODO: test adding more than 10 items


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
        res = self.testapp.get("/.well-known/admin/certificate-requests", status=200)

        # paginated
        res = self.testapp.get("/.well-known/admin/certificate-requests/1", status=200)

    @routes_tested(
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

    @routes_tested(("admin:certificate_request:focus:raw",))
    def test_focus_raw(self):
        (focus_item, focus_id) = self._get_one()

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

    @routes_tested(("admin:certificate_request:focus|json",))
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/certificate-request/%s.json" % focus_id, status=200
        )
        assert "CertificateRequest" in res.json
        assert res.json["CertificateRequest"]["id"] == focus_id


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
            "/.well-known/admin/coverage-assurance-events/all.json", status=200
        )
        assert "CoverageAssuranceEvents" in res.json
        res = self.testapp.get(
            "/.well-known/admin/coverage-assurance-events/unresolved.json", status=200
        )
        assert "CoverageAssuranceEvents" in res.json

        # paginated
        res = self.testapp.get(
            "/.well-known/admin/coverage-assurance-events/all/1.json", status=200
        )
        assert "CoverageAssuranceEvents" in res.json
        res = self.testapp.get(
            "/.well-known/admin/coverage-assurance-events/unresolved/1.json", status=200
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
            "/.well-known/admin/coverage-assurance-event/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/coverage-assurance-event/%s/children" % focus_id,
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
            "/.well-known/admin/coverage-assurance-event/%s.json" % focus_id, status=200
        )
        assert "CoverageAssuranceEvent" in res.json
        assert res.json["CoverageAssuranceEvent"]["id"] == focus_id

        res = self.testapp.get(
            "/.well-known/admin/coverage-assurance-event/%s/children.json" % focus_id,
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
            "/.well-known/admin/coverage-assurance-event/%s" % focus_id, status=200
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
            "/.well-known/admin/coverage-assurance-event/%s" % focus_id, status=200
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
            "/.well-known/admin/coverage-assurance-event/%s.json" % focus_id, status=200
        )
        assert "CoverageAssuranceEvent" in res.json
        assert res.json["CoverageAssuranceEvent"]["id"] == focus_id

        res2 = self.testapp.get(
            "/.well-known/admin/coverage-assurance-event/%s/mark.json" % focus_id,
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
            "/.well-known/admin/coverage-assurance-event/%s/mark.json" % focus_id,
            {},
            status=200,
        )
        assert res3.json["result"] == "error"
        assert "form_errors" in res3.json
        assert res3.json["form_errors"]["Error_Main"] == "Nothing submitted."

        _payload = {"action": "resolution", "resolution": resolution}
        res4 = self.testapp.post(
            "/.well-known/admin/coverage-assurance-event/%s/mark.json" % focus_id,
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
            "/.well-known/admin/coverage-assurance-event/%s/mark.json" % focus_id,
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
            .filter(model_objects.Domain.is_active.op("IS")(True))
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

    @routes_tested(
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

    @routes_tested(("admin:domains:search",))
    def test_search_html(self):
        res = self.testapp.get("/.well-known/admin/domains/search", status=200)
        res2 = self.testapp.post(
            "/.well-known/admin/domains/search", {"domain": "example.com"}
        )

    @routes_tested(("admin:domains:search|json",))
    def test_search_json(self):
        res = self.testapp.get("/.well-known/admin/domains/search.json", status=200)
        res2 = self.testapp.post(
            "/.well-known/admin/domains/search.json", {"domain": "example.com"}
        )

    @routes_tested(
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
            "admin:domain:focus:domain_autocerts",
            "admin:domain:focus:domain_autocerts_paginated",
            "admin:domain:focus:certificate_signeds",
            "admin:domain:focus:certificate_signeds_paginated",
            "admin:domain:focus:queue_certificates",
            "admin:domain:focus:queue_certificates_paginated",
            "admin:domain:focus:unique_fqdn_sets",
            "admin:domain:focus:unique_fqdn_sets_paginated",
        )
    )
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()
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
            "/.well-known/admin/domain/%s/domain-autocerts" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/domain-autocerts/1" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/certificate-requests" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/certificate-requests/1" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/certificate-signeds" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/certificate-signeds/1" % focus_id, status=200
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
            "/.well-known/admin/domain/%s.json" % focus_id, status=200
        )
        assert "Domain" in res.json
        assert res.json["Domain"]["id"] == focus_id
        assert res.json["Domain"]["domain_name"].lower() == focus_name.lower()

        res = self.testapp.get(
            "/.well-known/admin/domain/%s.json" % focus_name, status=200
        )
        assert "Domain" in res.json
        assert res.json["Domain"]["id"] == focus_id
        assert res.json["Domain"]["domain_name"].lower() == focus_name.lower()

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/config.json" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/calendar.json" % focus_id, status=200
        )

    @routes_tested(("admin:domain:focus:mark", "admin:domain:focus:update_recents"))
    def test_manipulate_html(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_Domain.test_manipulate_html
        """
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/mark" % focus_id,
            status=303,
        )
        assert res.location.endswith("?result=error&error=post+required&operation=mark")

        # the `focus_item` is active,
        if not focus_item.is_active:
            raise ValueError("NOT focus_item.is_active")

        # fail making this active
        res = self.testapp.post(
            "/.well-known/admin/domain/%s/mark" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 303
        assert res.location.endswith(
            "?result=error&error=Error_Main--There+was+an+error+with+your+form.+Already+active.&operation=mark&action=active"
        )

        # inactive ROUNDTRIP
        res = self.testapp.post(
            "/.well-known/admin/domain/%s/mark" % focus_id,
            {"action": "inactive"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=inactive")

        res = self.testapp.post(
            "/.well-known/admin/domain/%s/mark" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=active")

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/update-recents" % focus_id, status=303
        )
        assert (
            res.location
            == """http://peter-sslers.example.com/.well-known/admin/domain/%s?result=error&operation=update-recents&message=POST+required"""
            % focus_id
        )

        res = self.testapp.post(
            "/.well-known/admin/domain/%s/update-recents" % focus_id, status=303
        )
        assert (
            res.location
            == """http://peter-sslers.example.com/.well-known/admin/domain/%s?result=success&operation=update-recents"""
            % focus_id
        )

    @routes_tested(
        ("admin:domain:focus:mark|json", "admin:domain:focus:update_recents|json")
    )
    def test_manipulate_json(self):
        (focus_item, focus_id) = self._get_one()

        # the `focus_item` is active,
        if not focus_item.is_active:
            raise ValueError("NOT focus_item.is_active")

        # fail making this active
        res = self.testapp.post(
            "/.well-known/admin/domain/%s/mark.json" % focus_id,
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
            "/.well-known/admin/domain/%s/mark.json" % focus_id,
            {"action": "inactive"},
        )
        assert res.status_code == 200
        assert "Domain" in res.json
        assert res.json["Domain"]["id"] == focus_id
        assert res.json["Domain"]["is_active"] is False

        res = self.testapp.post(
            "/.well-known/admin/domain/%s/mark.json" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 200
        assert "Domain" in res.json
        assert res.json["Domain"]["id"] == focus_id
        assert res.json["Domain"]["is_active"] is True

        res = self.testapp.post(
            "/.well-known/admin/domain/%s/update-recents.json" % focus_id, status=200
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
        res = self.testapp.get("/.well-known/admin/domain/new", status=200)
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
        res = self.testapp.get("/.well-known/admin/domain/%s" % focus_id, status=200)
        assert """<th>AcmeDnsConfiguration</th>""" in res.text
        assert (
            """/.well-known/admin/domain/%s/acme-dns-server/new""" % focus_id
        ) in res.text

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/acme-dns-server/new" % focus_id, status=200
        )
        assert "form-acme_dns_server-new" in res.forms
        form = res.forms["form-acme_dns_server-new"]
        form.submit_fields()
        _options = [int(opt[0]) for opt in form["acme_dns_server_id"].options]
        if 1 not in _options:
            raise ValueError("we should have a `1` in _options")
        form["acme_dns_server_id"] = "1"
        res2 = form.submit()
        assert res2.status_code == 303
        assert RE_Domain_new_AcmeDnsServerAccount.match(res2.location)

        res = self.testapp.get("/.well-known/admin/domain/%s" % focus_id, status=200)
        assert """AcmeDnsServerAccounts - Existing""" in res.text
        assert (
            """href="/.well-known/admin/domain/%s/acme-dns-server-accounts""" % focus_id
        ) in res.text

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/acme-dns-server-accounts" % focus_id,
            status=200,
        )
        assert "/.well-known/admin/acme-dns-server/" in res.text
        assert "/.well-known/admin/acme-dns-server-account/" in res.text

        # force a new AcmeDnsServerAccount, and it should fail
        # originally this had a 200 return with errors
        # now we do a 303 redirect
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/acme-dns-server/new" % focus_id, status=303
        )
        assert (
            res.location
            == """http://peter-sslers.example.com/.well-known/admin/domain/%s/acme-dns-server-accounts?result=error&error=accounts-exist&operation=new"""
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
        res = self.testapp.post("/.well-known/admin/domain/new.json", {}, status=200)
        assert res.json["result"] == "error"
        assert "form_errors" in res.json
        assert res.json["form_errors"]["Error_Main"] == "Nothing submitted."

        _payload = {
            "domain_name": TEST_FILES["AcmeDnsServerAccount"]["test-new-via-Domain"][
                "json"
            ]["Domain"],
        }
        res = self.testapp.post(
            "/.well-known/admin/domain/new.json", _payload, status=200
        )
        assert res.status_code == 200
        assert res.json["result"] == "success"
        assert "Domain" in res.json
        focus_id = res.json["Domain"]["id"]

        # get the record
        res = self.testapp.get(
            "/.well-known/admin/domain/%s.json" % focus_id, status=200
        )
        assert "Domain" in res.json
        assert res.json["Domain"]["id"] == focus_id
        # note: there is no signifier to add a new acme-dns server account

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/acme-dns-server/new.json" % focus_id,
            status=200,
        )
        assert "instructions" in res.json  # already covered
        assert "HTTP POST required" in res.json["instructions"]  # already covered
        assert "valid_options" in res.json
        assert "acme_dns_server_id" in res.json["valid_options"]
        assert 1 in res.json["valid_options"]["acme_dns_server_id"]

        res = self.testapp.post(
            "/.well-known/admin/domain/%s/acme-dns-server/new.json" % focus_id,
            {},
            status=200,
        )
        assert res.json["result"] == "error"
        assert "form_errors" in res.json
        assert res.json["form_errors"]["Error_Main"] == "Nothing submitted."

        _payload = {
            "acme_dns_server_id": 1,
        }

        res = self.testapp.post(
            "/.well-known/admin/domain/%s/acme-dns-server/new.json" % focus_id,
            _payload,
            status=200,
        )
        assert res.status_code == 200
        assert res.json["result"] == "success"
        assert "AcmeDnsServer" in res.json["AcmeDnsServerAccount"]
        assert res.json["AcmeDnsServerAccount"]["AcmeDnsServer"]["id"] == 1
        acme_dns_server_account_id = res.json["AcmeDnsServerAccount"]["id"]

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/acme-dns-server-accounts.json" % focus_id,
            status=200,
        )
        assert "Domain" in res.json
        assert res.json["Domain"]["id"] == focus_id
        assert "AcmeDnsServerAccounts" in res.json
        account_ids = [_acct["id"] for _acct in res.json["AcmeDnsServerAccounts"]]
        assert acme_dns_server_account_id in account_ids

        # force a new AcmeDnsServerAccount, and it should fail
        res = self.testapp.post(
            "/.well-known/admin/domain/%s/acme-dns-server/new.json" % focus_id,
            _payload,
            # status=200,
        )
        assert res.json["result"] == "error"
        assert "form_errors" in res.json
        assert (
            res.json["form_errors"]["Error_Main"]
            == "There was an error with your form."
        )
        assert (
            res.json["form_errors"]["acme_dns_server_id"]
            == "Existing record for this AcmeDnsServer."
        )

    @unittest.skipUnless(RUN_NGINX_TESTS, "Not Running Against: nginx")
    @routes_tested(("admin:domain:focus:nginx_cache_expire",))
    def test_nginx_html(self):
        (focus_item, focus_id) = self._get_one()
        focus_name = focus_item.domain_name

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/nginx-cache-expire" % focus_id, status=303
        )
        assert RE_Domain_operation_nginx_expire.match(res.location)

    @unittest.skipUnless(RUN_NGINX_TESTS, "Not Running Against: nginx")
    @routes_tested(("admin:domain:focus:nginx_cache_expire|json",))
    def test_nginx_json(self):
        (focus_item, focus_id) = self._get_one()
        focus_name = focus_item.domain_name

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/nginx-cache-expire.json" % focus_id,
            status=200,
        )
        assert res.json["result"] == "success"

    def test_post_required_json(self):
        (focus_item, focus_id) = self._get_one()
        # the `focus_item` is active,
        if not focus_item.is_active:
            raise ValueError("NOT focus_item.is_active")

        # !!!: test `POST required` `domain/%s/mark.json`
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/mark.json" % focus_id,
            {"action": "active"},
            status=200,
        )
        assert "form_fields" in res.json
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `domain/%s/update-recents.json`
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/update-recents.json" % focus_id, status=200
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `domain/%s/new.json`
        res = self.testapp.get("/.well-known/admin/domain/new.json", status=200)
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `domain/%s/acme-dns-server/new.json`
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/acme-dns-server/new.json" % focus_id,
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
        res = self.testapp.get("/.well-known/admin/domain-autocerts", status=200)

        # paginated
        res = self.testapp.get("/.well-known/admin/domain-autocerts/1", status=200)

    @routes_tested(
        (
            "admin:domain_autocerts|json",
            "admin:domain_autocerts_paginated|json",
        )
    )
    def test_list_json(self):
        # json root
        res = self.testapp.get("/.well-known/admin/domain-autocerts.json", status=200)
        assert "DomainAutocerts" in res.json

        # json paginated
        res = self.testapp.get("/.well-known/admin/domain-autocerts/1.json", status=200)
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
        res = self.testapp.get("/.well-known/admin/domains-blocklisted", status=200)

        # paginated
        res = self.testapp.get("/.well-known/admin/domains-blocklisted/1", status=200)

    @routes_tested(
        (
            "admin:domains_blocklisted|json",
            "admin:domains_blocklisted_paginated|json",
        )
    )
    def test_list_json(self):
        # json root
        res = self.testapp.get(
            "/.well-known/admin/domains-blocklisted.json", status=200
        )
        assert "DomainsBlocklisted" in res.json

        # json paginated
        res = self.testapp.get(
            "/.well-known/admin/domains-blocklisted/1.json", status=200
        )
        assert "DomainsBlocklisted" in res.json

    def test_AcmeOrder_new_fails(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_DomainBlocklisted.test_AcmeOrder_new_fails
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
        form["domain_names_http01"] = "always-fail.example.com, foo.example.com"
        form["processing_strategy"].force_value("create_order")
        res2 = form.submit()

        assert res2.status_code == 200
        assert "There was an error with your form." in res2.text
        assert (
            "The following Domains are blocklisted: always-fail.example.com"
            in res2.text
        )

    def test_AcmeOrderless_new_fails(self):

        res = self.testapp.get("/.well-known/admin/acme-orderless/new", status=200)
        form = res.form
        form["domain_names_http01"] = "always-fail.example.com, foo.example.com"
        res2 = form.submit()

        assert res2.status_code == 200
        assert "There was an error with your form." in res2.text
        assert (
            "The following Domains are blocklisted: always-fail.example.com"
            in res2.text
        )

    def test_AcmeOrderless_add_fails(self):

        res = self.testapp.get("/.well-known/admin/acme-orderless/new", status=200)
        form = res.form
        form["domain_names_http01"] = "example.com"
        res2 = form.submit()
        assert res2.status_code == 303
        matched = RE_AcmeOrderless.match(res2.location)
        assert matched
        obj_id = matched.groups()[0]

        # build a new form and submit edits
        res3 = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s" % obj_id,
            status=200,
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
            """<span class="help-inline">This domain is blocklisted.</span>"""
            in res4.text
        )

    def test_QueueDomain_add_fails(self):
        res = self.testapp.get("/.well-known/admin/queue-domains/add", status=200)
        _domain_names = [
            "always-fail.example.com",
            "test-queuedomain-add-fails.example.com",
        ]
        form = res.form
        form["domain_names_http01"] = ",".join(_domain_names)
        res2 = form.submit()
        assert res2.status_code == 303
        assert (
            res2.location
            == """http://peter-sslers.example.com/.well-known/admin/queue-domains?result=success&operation=add&results=%7B%22always-fail.example.com%22%3A+%22blocklisted%22%2C+%22test-queuedomain-add-fails.example.com%22%3A+%22queued%22%7D"""
        )


class FunctionalTests_Operations(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_Operations
    """

    @routes_tested(
        (
            "admin:operations",
            "admin:operations:certificate_ca_downloads",
            "admin:operations:certificate_ca_downloads_paginated",
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
            "/.well-known/admin/operations/certificate-ca-downloads", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/operations/certificate-ca-downloads/1", status=200
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
    python -m unittest tests.test_pyramid_app.FunctionalTests_PrivateKey
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
        res = self.testapp.get("/.well-known/admin/private-keys", status=200)

        # paginated
        res = self.testapp.get("/.well-known/admin/private-keys/1", status=200)

    @routes_tested(
        (
            "admin:private_keys|json",
            "admin:private_keys_paginated|json",
        )
    )
    def test_list_json(self):
        # json
        res = self.testapp.get("/.well-known/admin/private-keys.json", status=200)
        assert "PrivateKeys" in res.json

        res = self.testapp.get("/.well-known/admin/private-keys/1.json", status=200)
        assert "PrivateKeys" in res.json

    @routes_tested(
        (
            "admin:private_key:focus",
            "admin:private_key:focus:certificate_requests",
            "admin:private_key:focus:certificate_requests_paginated",
            "admin:private_key:focus:certificate_signeds",
            "admin:private_key:focus:certificate_signeds_paginated",
            "admin:private_key:focus:queue_certificates",
            "admin:private_key:focus:queue_certificates_paginated",
        )
    )
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()

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
            "/.well-known/admin/private-key/%s/certificate-signeds" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/certificate-signeds/1" % focus_id,
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

    @routes_tested(
        (
            "admin:private_key:focus|json",
            "admin:private_key:focus:parse|json",
        )
    )
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/private-key/%s.json" % focus_id, status=200
        )
        assert "PrivateKey" in res.json
        assert res.json["PrivateKey"]["id"] == focus_id

        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/parse.json" % focus_id, status=200
        )
        assert str(focus_id) in res.json

    @routes_tested(("admin:private_key:focus:raw",))
    def test_focus_raw(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/key.key" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/key.pem" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/key.pem.txt" % focus_id, status=200
        )

    @routes_tested(("admin:private_key:focus:mark",))
    def test_manipulate_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/mark" % focus_id,
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
            "/.well-known/admin/private-key/%s/mark" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 303
        assert res.location.endswith(
            "?result=error&error=Error_Main--There+was+an+error+with+your+form.+Already+activated.&operation=mark&action=active"
        )

        # inactive ROUNDTRIP
        res = self.testapp.post(
            "/.well-known/admin/private-key/%s/mark" % focus_id,
            {"action": "inactive"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=inactive")

        res = self.testapp.post(
            "/.well-known/admin/private-key/%s/mark" % focus_id,
            {"action": "active"},
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
        assert res.json["PrivateKey"]["id"] == focus_id
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

    @routes_tested(
        (
            "admin:private_key:upload|json",
            "admin:private_key:new|json",
        )
    )
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

    def test_post_required_json(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `private-key/%s/mark.json`
        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/mark.json" % focus_id,
            status=200,
        )
        assert "form_fields" in res.json
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]


class FunctionalTests_CertificateSigned(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_CertificateSigned
    """

    def _get_one(self):
        # grab a certificate
        # iterate backwards
        focus_item = (
            self.ctx.dbSession.query(model_objects.CertificateSigned)
            .filter(model_objects.CertificateSigned.is_active.op("IS")(True))
            .order_by(model_objects.CertificateSigned.id.desc())
            .first()
        )
        assert focus_item is not None
        return focus_item, focus_item.id

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
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/certificate-signeds", status=303)
        assert (
            res.location
            == """http://peter-sslers.example.com/.well-known/admin/certificate-signeds/active"""
        )

        for _type in (
            "all",
            "active",
            "expiring",
            "inactive",
        ):
            res = self.testapp.get(
                "/.well-known/admin/certificate-signeds/%s" % _type, status=200
            )
            res = self.testapp.get(
                "/.well-known/admin/certificate-signeds/%s/1" % _type, status=200
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
        )
    )
    def test_list_json(self):
        # root
        res = self.testapp.get(
            "/.well-known/admin/certificate-signeds.json", status=303
        )
        assert (
            res.location
            == """http://peter-sslers.example.com/.well-known/admin/certificate-signeds/active.json"""
        )

        for _type in (
            "all",
            "active",
            "expiring",
            "inactive",
        ):
            res = self.testapp.get(
                "/.well-known/admin/certificate-signeds/%s.json" % _type, status=200
            )
            assert "CertificateSigneds" in res.json

            res = self.testapp.get(
                "/.well-known/admin/certificate-signeds/%s/1.json" % _type, status=200
            )
            assert "CertificateSigneds" in res.json

    @routes_tested(
        (
            "admin:certificate_signed:focus",
            "admin:certificate_signed:focus:queue_certificates",
            "admin:certificate_signed:focus:queue_certificates_paginated",
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
            "/.well-known/admin/certificate-signed/%s" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/queue-certificates" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/queue-certificates/1" % focus_id,
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

        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/chain.cer" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/chain.crt" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/chain.der" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/chain.pem" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/chain.pem.txt" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/fullchain.pem" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/fullchain.pem.txt" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/privkey.key" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/privkey.pem" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/privkey.pem.txt" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/cert.crt" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/cert.pem" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/cert.pem.txt" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/config.zip" % focus_id,
            status=200,
        )
        assert res.headers["Content-Type"] == "application/zip"
        assert (
            res.headers["Content-Disposition"]
            == "attachment; filename= cert%s.zip" % focus_id
        )
        if six.PY2:
            z = zipfile.ZipFile(StringIO(res.body))
        else:
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
            "/.well-known/admin/certificate-signed/%s.json" % focus_id, status=200
        )
        assert "CertificateSigned" in res.json
        assert res.json["CertificateSigned"]["id"] == focus_id

        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/config.json" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/parse.json" % focus_id, status=200
        )

    @routes_tested(("admin:certificate_signed:focus:mark",))
    def test_manipulate_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/mark" % focus_id
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
            "/.well-known/admin/certificate-signed/%s/mark" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 303
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/certificate-signed/%s?&result=error&error=There+was+an+error+with+your+form.+Already+active.&operation=mark&action=active"
            % focus_id
        )

        # inactive ROUNDTRIP
        res = self.testapp.post(
            "/.well-known/admin/certificate-signed/%s/mark" % focus_id,
            {"action": "inactive"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=inactive")

        res = self.testapp.post(
            "/.well-known/admin/certificate-signed/%s/mark" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=active")

        # then compromised
        res = self.testapp.post(
            "/.well-known/admin/certificate-signed/%s/mark" % focus_id,
            {"action": "revoked"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=revoked")

    @routes_tested(("admin:certificate_signed:focus:mark|json",))
    def test_manipulate_json(self):
        (focus_item, focus_id) = self._get_one()

        # the `focus_item` is active, so it can't be revoked or inactive
        if focus_item.is_revoked:
            raise ValueError("focus_item.is_revoked")

        if not focus_item.is_active:
            raise ValueError("NOT focus_item.is_active")

        # fail making this active
        res = self.testapp.post(
            "/.well-known/admin/certificate-signed/%s/mark.json" % focus_id,
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
            "/.well-known/admin/certificate-signed/%s/mark.json" % focus_id,
            {"action": "inactive"},
        )
        assert res.status_code == 200
        assert "CertificateSigned" in res.json
        assert res.json["CertificateSigned"]["id"] == focus_id
        assert res.json["CertificateSigned"]["is_active"] is False

        res = self.testapp.post(
            "/.well-known/admin/certificate-signed/%s/mark.json" % focus_id,
            {"action": "active"},
        )
        assert res.status_code == 200
        assert "CertificateSigned" in res.json
        assert res.json["CertificateSigned"]["id"] == focus_id
        assert res.json["CertificateSigned"]["is_active"] is True

        # then compromised
        res = self.testapp.post(
            "/.well-known/admin/certificate-signed/%s/mark.json" % focus_id,
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
            "/.well-known/admin/certificate-signed/upload", status=200
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
            """http://peter-sslers.example.com/.well-known/admin/certificate-signed/"""
        )

    @routes_tested(("admin:certificate_signed:upload|json",))
    def test_upload_json(self):
        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/upload.json", status=200
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
            "/.well-known/admin/certificate-signed/upload.json", form
        )
        assert res2.status_code == 200
        assert res2.json["result"] == "success"
        assert res2.json["CertificateSigned"]["created"] in (True, False)
        certificate_id = res2.json["CertificateSigned"]["id"]
        res3 = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s.json" % certificate_id, status=200
        )
        assert "CertificateSigned" in res3.json

    @unittest.skipUnless(RUN_NGINX_TESTS, "Not Running Against: nginx")
    @routes_tested(("admin:certificate_signed:focus:nginx_cache_expire",))
    def test_nginx_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/nginx-cache-expire" % focus_id,
            status=303,
        )
        assert RE_CertificateSigned_operation_nginx_expire.match(res.location)

    @unittest.skipUnless(RUN_NGINX_TESTS, "Not Running Against: nginx")
    @routes_tested(("admin:certificate_signed:focus:nginx_cache_expire|json",))
    def test_nginx_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/nginx-cache-expire.json"
            % focus_id,
            status=200,
        )
        assert res.json["result"] == "success"

    def test_post_required_json(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `certificate-signed/%s/mark.json`
        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s/mark.json" % focus_id,
            status=200,
        )
        assert "form_fields" in res.json
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]


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
        res = self.testapp.get("/.well-known/admin/unique-fqdn-sets", status=200)

        # paginated
        res = self.testapp.get("/.well-known/admin/unique-fqdn-sets/1", status=200)

    @routes_tested(
        (
            "admin:unique_fqdn_sets|json",
            "admin:unique_fqdn_sets_paginated|json",
        )
    )
    def test_list_json(self):
        # root
        res = self.testapp.get("/.well-known/admin/unique-fqdn-sets.json", status=200)
        assert "UniqueFQDNSets" in res.json

        # paginated
        res = self.testapp.get("/.well-known/admin/unique-fqdn-sets/1.json", status=200)
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
            "admin:unique_fqdn_set:focus:queue_certificates",
            "admin:unique_fqdn_set:focus:queue_certificates_paginated",
        )
    )
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s/acme-orders" % focus_id,
            status=200,
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
            "/.well-known/admin/unique-fqdn-set/%s/certificate-signeds" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s/certificate-signeds/1" % focus_id,
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

    @routes_tested(
        (
            "admin:unique_fqdn_set:focus|json",
            "admin:unique_fqdn_set:focus:calendar|json",
        )
    )
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s.json" % focus_id, status=200
        )
        assert "UniqueFQDNSet" in res.json
        assert res.json["UniqueFQDNSet"]["id"] == focus_id

        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s/calendar.json" % focus_id, status=200
        )

    @routes_tested(("admin:unique_fqdn_set:focus:update_recents",))
    def test_manipulate_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s/update-recents" % focus_id,
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/unique-fqdn-set/%s?result=error&operation=update-recents&message=POST+required"
            % focus_id
        )

        res = self.testapp.post(
            "/.well-known/admin/unique-fqdn-set/%s/update-recents" % focus_id,
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/unique-fqdn-set/%s?result=success&operation=update-recents"
            % focus_id
        )

    @routes_tested(("admin:unique_fqdn_set:focus:update_recents|json",))
    def test_manipulate_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.post(
            "/.well-known/admin/unique-fqdn-set/%s/update-recents.json" % focus_id,
            status=200,
        )
        assert res.status_code == 200
        assert res.json["result"] == "success"
        assert "UniqueFQDNSet" in res.json

    def test_post_required_json(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `unique-fqdn-set/%s/update-recents.json`
        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s/update-recents.json" % focus_id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]


class FunctionalTests_QueueCertificate(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_QueueCertificate
    """

    def _get_one(self):
        # grab an item
        focus_item = (
            self.ctx.dbSession.query(model_objects.QueueCertificate)
            .filter(model_objects.QueueCertificate.is_active.is_(True))
            .order_by(model_objects.QueueCertificate.id.asc())
            .first()
        )
        assert focus_item is not None
        return focus_item, focus_item.id

    @routes_tested(
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
            == "http://peter-sslers.example.com/.well-known/admin/queue-certificates/unprocessed"
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

    @routes_tested(
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
            == "http://peter-sslers.example.com/.well-known/admin/queue-certificates/unprocessed.json"
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

    @routes_tested(("admin:queue_certificate:focus",))
    def test_focus_html(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_QueueCertificate.test_focus_html
        """
        (focus_item, focus_id) = self._get_one()
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/%s" % focus_id, status=200
        )

    @routes_tested(("admin:queue_certificate:focus|json",))
    def test_focus_json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_QueueCertificate.test_focus_json
        """
        (focus_item, focus_id) = self._get_one()
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/%s.json" % focus_id, status=200
        )
        assert res.json["result"] == "success"
        assert "QueueCertificate" in res.json
        assert res.json["QueueCertificate"]["id"] == focus_id

    @routes_tested(("admin:queue_certificate:focus:mark",))
    def test_manipulate_html(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_QueueCertificate.test_manipulate_html
        """
        (focus_item, focus_id) = self._get_one()
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
            == "http://peter-sslers.example.com/.well-known/admin/queue-certificate/%s?result=error&error=Error_Main--There+was+an+error+with+your+form.---action--Already+processed&operation=mark&action=cancel"
            % focus_id
        )

    @routes_tested(("admin:queue_certificate:focus:mark|json",))
    def test_manipulate_json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_QueueCertificate.test_manipulate_json
        """
        (focus_item, focus_id) = self._get_one()

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
        assert res3.json["form_errors"]["action"] == "Already processed"

    def _get_queueable_AcmeOrder(self):
        # see `AcmeOrder.is_renewable_queue`
        dbAcmeOrder = (
            self.ctx.dbSession.query(model_objects.AcmeOrder)
            .join(
                model_objects.AcmeAccount,
                model_objects.AcmeOrder.acme_account_id == model_objects.AcmeAccount.id,
            )
            .filter(
                model_objects.AcmeAccount.is_active.is_(True),
            )
            .order_by(model_objects.AcmeOrder.id.asc())
            .first()
        )
        assert dbAcmeOrder
        return dbAcmeOrder

    def _get_queueable_CertificateSigned(self):
        dbCertificateSigned = (
            self.ctx.dbSession.query(model_objects.CertificateSigned)
            .order_by(model_objects.CertificateSigned.id.asc())
            .first()
        )
        assert dbCertificateSigned
        return dbCertificateSigned

    def _get_queueable_UniqueFQDNSet(self):
        dbUniqueFQDNSet = (
            self.ctx.dbSession.query(model_objects.UniqueFQDNSet)
            .order_by(model_objects.UniqueFQDNSet.id.asc())
            .first()
        )
        assert dbUniqueFQDNSet
        return dbUniqueFQDNSet

    @routes_tested(("admin:queue_certificate:new_structured",))
    def test_new_structured_html(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_QueueCertificate.test_new_structured_html
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

        # try with a CertificateSigned
        dbCertificateSigned = self._get_queueable_CertificateSigned()
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/new/structured?queue_source=CertificateSigned&certificate_signed=%s"
            % dbCertificateSigned.id,
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

    @routes_tested(("admin:queue_certificate:new_structured|json",))
    def test_new_structured_json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_QueueCertificate.test_new_structured_json
        """
        # TODO: test with objects that have issues
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/new/structured.json", status=200
        )
        assert res.json["result"] == "error"
        assert res.json["error"] == "invalid queue source"

        # try with an AcmeOrder
        dbAcmeOrder = self._get_queueable_AcmeOrder()
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

        # try with a CertificateSigned
        dbCertificateSigned = self._get_queueable_CertificateSigned()
        res_instructions = self.testapp.get(
            "/.well-known/admin/queue-certificate/new/structured.json?queue_source=CertificateSigned&certificate_signed=%s"
            % dbCertificateSigned.id,
            status=200,
        )
        account_key_global_default = res_instructions.json["valid_options"][
            "AcmeAccount_GlobalDefault"
        ]["AcmeAccountKey"]["key_pem_md5"]
        form = {
            "queue_source": "CertificateSigned",
            "certificate_signed": dbCertificateSigned.id,
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

    @routes_tested(("admin:queue_certificate:new_freeform",))
    def test_new_freeform_html(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_QueueCertificate.test_new_freeform_html
        """
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/new/freeform", status=200
        )
        form = res.form
        form["domain_names_http01"] = "test-new-freeform-html.example.com"
        res2 = form.submit()
        assert res2.status_code == 303
        matched = RE_QueueCertificate.match(res2.location)
        assert matched
        queue_id_1 = matched.groups()[0]

    @routes_tested(("admin:queue_certificate:new_freeform|json",))
    def test_new_freeform_json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_QueueCertificate.test_new_freeform_json
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
        form["domain_names_http01"] = "test-new-freeform-json.example.com"
        res3 = self.testapp.post(
            "/.well-known/admin/queue-certificate/new/freeform.json", form, status=200
        )
        assert res3.json["result"] == "success"
        assert "QueueCertificate" in res3.json
        queue_id_1 = res3.json["QueueCertificate"]

    def test_post_required_html(self):
        pass

    def test_post_required_json(self):
        (focus_item, focus_id) = self._get_one()
        dbAcmeOrder = self._get_queueable_AcmeOrder()

        # !!!: test `POST required` `queue-certificate/%s/mark.json`
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/%s/mark.json" % focus_id,
            {"action": "cancel"},
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `queue-certificates/process.json`
        res = self.testapp.get(
            "/.well-known/admin/api/queue-certificates/process.json", status=200
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `queue-certificates/update.json`
        res = self.testapp.get(
            "/.well-known/admin/api/queue-certificates/update.json", status=200
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `queue-certificate/new/structured.json`
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/new/structured.json?queue_source=AcmeOrder&acme_order=%s"
            % dbAcmeOrder.id,
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `queue-certificate/new/freeform.json`
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/new/freeform.json", status=200
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]


class FunctionalTests_QueueDomains(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_QueueDomains
    """

    def _get_one(self):
        # grab an item
        focus_item = (
            self.ctx.dbSession.query(model_objects.QueueDomain)
            .filter(model_objects.QueueDomain.is_active.op("IS")(True))
            .order_by(model_objects.QueueDomain.id.asc())
            .first()
        )
        assert focus_item is not None
        return focus_item, focus_item.id

    @routes_tested(
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

    @routes_tested(
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

    @routes_tested(("admin:queue_domains:add",))
    def test_add_html(self):
        res = self.testapp.get("/.well-known/admin/queue-domains/add", status=200)
        form = res.form
        form["domain_names_http01"] = TEST_FILES["Domains"]["Queue"]["1"]["add"]
        res2 = form.submit()
        assert res2.status_code == 303
        assert (
            """http://peter-sslers.example.com/.well-known/admin/queue-domains?result=success"""
            in res2.location
        )

    @routes_tested(("admin:queue_domains:add|json",))
    def test_add_json(self):
        res = self.testapp.get("/.well-known/admin/queue-domains/add.json", status=200)
        _data = {"domain_names_http01": TEST_FILES["Domains"]["Queue"]["1"]["add.json"]}
        res2 = self.testapp.post("/.well-known/admin/queue-domains/add.json", _data)
        assert res2.status_code == 200
        assert res2.json["result"] == "success"

    @routes_tested(("admin:queue_domain:focus",))
    def test_focus_html(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/queue-domain/%s" % focus_id, status=200
        )

    @routes_tested(("admin:queue_domain:focus|json",))
    def test_focus_json(self):
        (focus_item, focus_id) = self._get_one()

        res = self.testapp.get(
            "/.well-known/admin/queue-domain/%s.json" % focus_id, status=200
        )
        assert res.json["result"] == "success"
        assert "QueueDomain" in res.json
        assert res.json["QueueDomain"]["id"] == focus_id

    @routes_tested(("admin:queue_domain:focus:mark",))
    def test_manipulate_html(self):
        (focus_item, focus_id) = self._get_one()

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
            == "http://peter-sslers.example.com/.well-known/admin/queue-domain/%s?result=error&error=Error_Main--There+was+an+error+with+your+form.---action--Already+cancelled&operation=mark&action=cancel"
            % focus_id
        )

    @routes_tested(("admin:queue_domain:focus:mark|json",))
    def test_manipulate_json(self):
        (focus_item, focus_id) = self._get_one()

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

    def test_post_required_html(self):
        pass

    def test_post_required_json(self):
        (focus_item, focus_id) = self._get_one()

        # !!!: test `POST required` `queue-domains/process.json`
        res = self.testapp.get(
            "/.well-known/admin/queue-domains/process.json", status=200
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `queue-domain/mark.json`
        res = self.testapp.get(
            "/.well-known/admin/queue-domain/%s/mark.json" % focus_id,
            {"action": "cancel"},
            status=200,
        )
        assert "form_fields" in res.json
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]


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
            .filter(model_objects.CertificateSigned.is_active.op("IS")(True))
            .order_by(model_objects.CertificateSigned.id.desc())
            .first()
        )
        assert focus_item is not None
        assert focus_item.certificates_upchain
        return focus_item

    @routes_tested(
        (
            "admin:certificate_ca:focus:certificate_signeds_alt",
            "admin:certificate_ca:focus:certificate_signeds_alt_paginated",
        )
    )
    def test_CertificateCA_view(self):
        focus_CertificateSigned = self._get_one()
        for _to_ca_cert in focus_CertificateSigned.certificates_upchain:
            cert_ca_alt_id = _to_ca_cert.certificate_ca_id
            res = self.testapp.get(
                "/.well-known/admin/certificate-ca/%s" % cert_ca_alt_id, status=200
            )
            res = self.testapp.get(
                "/.well-known/admin/certificate-ca/%s/certificate-signeds-alt"
                % cert_ca_alt_id,
                status=200,
            )
            res = self.testapp.get(
                "/.well-known/admin/certificate-ca/%s/certificate-signeds-alt/1"
                % cert_ca_alt_id,
                status=200,
            )

    @routes_tested(
        (
            "admin:certificate_signed:focus:via_cert_ca:config|json",
            "admin:certificate_signed:focus:via_cert_ca:config|zip",
            "admin:certificate_signed:focus:via_cert_ca:chain:raw",
            "admin:certificate_signed:focus:via_cert_ca:fullchain:raw",
        )
    )
    def test_CertificateSigned_view(self):
        focus_CertificateSigned = self._get_one()

        certificate_signed_id = focus_CertificateSigned.id
        # this will have the primary root and the alternate roots;
        # pre-cache this now
        upchain_ids = [i.id for i in focus_CertificateSigned.iter_certificate_upchain]

        res = self.testapp.get(
            "/.well-known/admin/certificate-signed/%s" % certificate_signed_id,
            status=200,
        )

        for cert_ca_id in upchain_ids:
            focus_ids = (certificate_signed_id, cert_ca_id)

            # chain
            res = self.testapp.get(
                "/.well-known/admin/certificate-signed/%s/via-cert-ca/%s/chain.cer"
                % focus_ids,
                status=200,
            )
            res = self.testapp.get(
                "/.well-known/admin/certificate-signed/%s/via-cert-ca/%s/chain.crt"
                % focus_ids,
                status=200,
            )
            res = self.testapp.get(
                "/.well-known/admin/certificate-signed/%s/via-cert-ca/%s/chain.der"
                % focus_ids,
                status=200,
            )
            res = self.testapp.get(
                "/.well-known/admin/certificate-signed/%s/via-cert-ca/%s/chain.pem"
                % focus_ids,
                status=200,
            )
            res = self.testapp.get(
                "/.well-known/admin/certificate-signed/%s/via-cert-ca/%s/chain.pem.txt"
                % focus_ids,
                status=200,
            )

            # fullchain
            res = self.testapp.get(
                "/.well-known/admin/certificate-signed/%s/via-cert-ca/%s/fullchain.pem"
                % focus_ids,
                status=200,
            )
            res = self.testapp.get(
                "/.well-known/admin/certificate-signed/%s/via-cert-ca/%s/fullchain.pem.txt"
                % focus_ids,
                status=200,
            )

            # configs
            res = self.testapp.get(
                "/.well-known/admin/certificate-signed/%s/via-cert-ca/%s/config.json"
                % focus_ids,
                status=200,
            )

            res = self.testapp.get(
                "/.well-known/admin/certificate-signed/%s/via-cert-ca/%s/config.zip"
                % focus_ids,
                status=200,
            )
            assert res.headers["Content-Type"] == "application/zip"
            assert (
                res.headers["Content-Disposition"]
                == "attachment; filename= cert%s-chain%s.zip" % focus_ids
            )
            if six.PY2:
                z = zipfile.ZipFile(StringIO(res.body))
            else:
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


class FunctionalTests_AcmeServer(AppTest):
    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested("admin:acme_account:new")
    def test_AcmeAccount_new_html(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_AcmeAccount_new_html
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
        matched = RE_AcmeAccount_new.match(res2.location)
        assert matched
        obj_id = matched.groups()[0]

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested("admin:acme_account:new|json")
    def test_AcmeAccount_new_json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_AcmeAccount_new_json
        """
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

        form["account__private_key_technology"] = "RSA"
        res4 = self.testapp.post("/.well-known/admin/acme-account/new.json", form)
        assert res4.json["result"] == "success"
        assert "AcmeAccount" in res4.json
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
        assert focus_item is not None
        return focus_item, focus_item.id

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested("admin:acme_account:focus:acme_server:authenticate")
    def test_AcmeAccount_authenticate_html(self):
        """
        # this hits Pebble via http
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_AcmeAccount_authenticate_html
        """
        (focus_item, focus_id) = self._get_one_AcmeAccount()

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

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested("admin:acme_account:focus:acme_server:authenticate|json")
    def test_AcmeAccount_authenticate_json(self):
        """
        # this hits Pebble via http
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_AcmeAccount_authenticate_json
        """
        (focus_item, focus_id) = self._get_one_AcmeAccount()

        res = self.testapp.post(
            "/.well-known/admin/acme-account/%s/acme-server/authenticate.json"
            % focus_id,
            {},
        )
        assert res.status_code == 200
        assert res.location is None  # no redirect
        assert "AcmeAccount" in res.json

    @routes_tested(
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
        assert len(_test_data["acme-order/new/freeform#1"]["domain_names_http01"]) == 2

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
        res = self.testapp.get("%s.json" % res2.location, status=200)
        assert "AcmeOrder" in res.json
        acme_account_id = res.json["AcmeOrder"]["AcmeAccount"]["id"]
        assert acme_account_id

        # admin:acme_account:focus
        res = self.testapp.get(
            "/.well-known/admin/acme-account/%s" % acme_account_id, status=200
        )

        return acme_account_id

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_account:focus:acme_server:deactivate_pending_authorizations",  # real test
        )
    )
    def test_AcmeAccount_deactivate_pending_authorizations_html(self):
        """
        # this hits Pebble via http
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_AcmeAccount_deactivate_pending_authorizations_html
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

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_account:focus:acme_server:deactivate_pending_authorizations|json",  # real test
        )
    )
    def test_AcmeAccount_deactivate_pending_authorizations_json(self):
        """
        # this hits Pebble via http
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_AcmeAccount_deactivate_pending_authorizations_json
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

    @routes_tested(("admin:acme_order:new:freeform",))
    def _prep_AcmeOrder_html(self, processing_strategy=None):
        """
        this runs `@under_pebble`, but the invoking function should wrap it
        """
        _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]

        # we need two for this test
        assert len(_test_data["acme-order/new/freeform#1"]["domain_names_http01"]) == 2

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
        form["domain_names_http01"] = ",".join(
            _test_data["acme-order/new/freeform#1"]["domain_names_http01"]
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
            "admin:acme_order:focus:renew:custom",
            "admin:acme_order:focus:renew:quick",
            "admin:acme_order:focus:acme_server:deactivate_authorizations",
        )
    )
    def test_AcmeOrder_extended_html(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_AcmeOrder_extended_html

        NOTE: if domains are not randomized for the order, one needs to reset the pebble instance
        NOTE^^^ this now runs with it's own pebble instance
        """
        _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]

        (obj_id, obj_url) = self._prep_AcmeOrder_html()

        # /acme-order
        res = self.testapp.get(obj_url, status=200)

        # "admin:acme_order:focus:acme_server:sync",
        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/acme-server/sync" % obj_id, {}, status=303
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=success&operation=acme+server+sync"
            % obj_id
        )

        # "admin:acme_order:focus:acme_server:sync_authorizations",
        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/acme-server/sync-authorizations" % obj_id,
            {},
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=success&operation=acme+server+sync+authorizations"
            % obj_id
        )

        _dbAcmeOrder = self.ctx.dbSession.query(model_objects.AcmeOrder).get(obj_id)
        assert len(_dbAcmeOrder.acme_authorizations) == len(
            _test_data["acme-order/new/freeform#1"]["domain_names_http01"]
        )
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
            "/.well-known/admin/acme-authorization/%s" % auth_id_1, status=200
        )

        # "admin:acme_authorization:focus:sync"
        res = self.testapp.post(
            "/.well-known/admin/acme-authorization/%s/acme-server/sync" % auth_id_1,
            {},
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-authorization/%s?result=success&operation=acme+server+sync"
            % auth_id_1
        )

        # note: originally we triggered the AUTHORIZATION `acme-authorization/%s/acme-server/trigger`
        # that endpoint was removed
        res = self.testapp.post(
            "/.well-known/admin/acme-challenge/%s/acme-server/trigger" % challenge_id_1,
            {},
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/acme-challenge/%s?result=success&operation=acme+server+trigger"
            % challenge_id_1
        )
        res = self.testapp.post(
            "/.well-known/admin/acme-authorization/%s/acme-server/sync" % auth_id_1,
            {},
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-authorization/%s?result=success&operation=acme+server+sync"
            % auth_id_1
        )

        # AuthPair 2
        (auth_id_2, challenge_id_2) = _authorization_pairs[1]

        # "admin:acme_challenge:focus",
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge/%s" % challenge_id_2, status=200
        )

        # "admin:acme_challenge:focus:acme_server:sync",
        res = self.testapp.post(
            "/.well-known/admin/acme-challenge/%s/acme-server/sync" % challenge_id_2,
            {},
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/acme-challenge/%s?result=success&operation=acme+server+sync"
            % challenge_id_2
        )

        # "admin:acme_challenge:focus:acme_server:trigger",
        res = self.testapp.post(
            "/.well-known/admin/acme-challenge/%s/acme-server/trigger" % challenge_id_2,
            {},
            status=303,
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/acme-challenge/%s?result=success&operation=acme+server+trigger"
            % challenge_id_2
        )

        # "admin:acme_authorization:focus:sync"
        res = self.testapp.post(
            "/.well-known/admin/acme-authorization/%s/acme-server/sync" % auth_id_2,
            {},
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-authorization/%s?result=success&operation=acme+server+sync"
            % auth_id_2
        )

        # now go back to the order
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s" % obj_id,
            status=200,
        )
        assert (
            """<td><span class="label label-default">processing_started</span></td>"""
            in res.text
        )

        # "admin:acme_order:focus:acme_server:sync",
        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/acme-server/sync" % obj_id, {}, status=303
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=success&operation=acme+server+sync"
            % obj_id
        )

        res2 = self.testapp.post(
            "/.well-known/admin/acme-order/%s/acme-server/sync.json" % obj_id
        )
        res2 = self.testapp.get("/.well-known/admin/acme-authorization/%s.json" % 2)
        res2 = self.testapp.get("/.well-known/admin/acme-authorization/%s.json" % 3)

        res2 = self.testapp.get("/.well-known/admin/acme-order/%s.json" % obj_id)

        # "admin:acme_order:focus:acme_finalize",
        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/acme-finalize" % obj_id, {}, status=303
        )

        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=success&operation=acme+finalize"
            % obj_id
        )

        # now go back to the order
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s" % obj_id,
            status=200,
        )
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

        matched = RE_AcmeOrder_renew_quick.match(res2.location)
        assert matched
        obj_id__quick = matched.groups()[0]

        # "admin:acme_order:focus",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s" % obj_id__quick, status=200
        )
        # "admin:acme_order:focus:acme_server:sync",
        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/acme-server/sync" % obj_id__quick,
            {},
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
        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/acme-finalize" % obj_id__quick,
            {},
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=success&operation=acme+finalize"
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

        matched = RE_AcmeOrder_renew_custom.match(res2.location)
        assert matched
        obj_id__custom = matched.groups()[0]

        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/acme-server/sync" % obj_id__custom,
            {},
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
        assert len(_test_data["acme-order/new/freeform#2"]["domain_names_http01"]) == 2
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
        form["domain_names_http01"] = ",".join(
            _test_data["acme-order/new/freeform#2"]["domain_names_http01"]
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
        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/acme-server/sync-authorizations"
            % obj_id__2,
            {},
            status=303,
        )
        assert res.location == (
            "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=success&operation=acme+server+sync+authorizations"
            % obj_id__2
        )

        # grab the order
        # look for deactivate-authorizations
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s" % obj_id__2, status=200
        )
        assert RE_AcmeOrder_btn_deactive_authorizations.findall(res.text)

        # "admin:acme_order:focus:acme_server:deactivate_authorizations",
        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/acme-server/deactivate-authorizations"
            % obj_id__2,
            {},
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
        assert RE_AcmeOrder_btn_deactive_authorizations__off.findall(res.text)

        # "admin:acme_order:focus:retry",
        assert "acme_order-retry" in res.forms
        form = res.forms["acme_order-retry"]
        res = form.submit()
        assert res.status_code == 303

        matched = RE_AcmeOrder_retry.match(res.location)
        assert matched
        obj_id__3 = matched.groups()[0]

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
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_AcmeOrder_mark_html
        """
        (obj_id, obj_url) = self._prep_AcmeOrder_html()

        # grab the order
        res = self.testapp.get("/.well-known/admin/acme-order/%s" % obj_id, status=200)

        # "mark" deactivate
        assert (
            'href="/.well-known/admin/acme-order/%s/mark?action=deactivate"' % obj_id
            in res.text
        )

        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/mark?action=deactivate" % obj_id,
            {},
            status=303,
        )
        matched = RE_AcmeOrder_deactivated.match(res.location)
        assert matched

        # grab the order
        res = self.testapp.get("/.well-known/admin/acme-order/%s" % obj_id, status=200)

        # "mark" invalid
        assert "form-acme_order-mark_invalid" in res.forms
        form = res.forms["form-acme_order-mark_invalid"]
        res = form.submit()
        matched = RE_AcmeOrder_invalidated.match(res.location)
        assert matched

        # now try a manual post. it must fail.
        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/mark?action=invalid" % obj_id,
            {},
            status=303,
        )
        matched = RE_AcmeOrder_invalidated_error.match(res.location)
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

        # grab the NEW order
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s" % obj_id__4, status=200
        )

        # new orders should default to auto-renew on
        assert "acme_order-mark-renew_manual" in res.forms
        form = res.forms["acme_order-mark-renew_manual"]
        res = form.submit()
        assert res.status_code == 303
        assert (
            "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=success&operation=mark&action=renew_manual"
            % obj_id__4
        )

        # grab the order again...
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s" % obj_id__4, status=200
        )

        # and toggle it the other way
        assert "acme_order-mark-renew_auto" in res.forms
        form = res.forms["acme_order-mark-renew_auto"]
        res = form.submit()
        assert res.status_code == 303
        assert (
            "http://peter-sslers.example.com/.well-known/admin/acme-order/%s?result=success&operation=mark&action=renew_auto"
            % obj_id__4
        )

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_order:new:freeform",
            "admin:acme_order:focus",
        )
    )
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
        (obj_id, obj_url) = self._prep_AcmeOrder_html(
            processing_strategy="process_multi"
        )

        # /acme-order
        res = self.testapp.get(obj_url, status=200)
        assert RE_AcmeOrder_btn_acme_process__can.findall(res.text)

        process_url = "/.well-known/admin/acme-order/%s/acme-process" % obj_id

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
    def _prep_AcmeOrder_json(self, processing_strategy=None):
        """
        this runs `@under_pebble`, but the invoking function should wrap it
        """
        _test_data = TEST_FILES["AcmeOrder"]["test-extended_html"]

        # we need two for this test
        assert len(_test_data["acme-order/new/freeform#1"]["domain_names_http01"]) == 2

        # "admin:acme_order:new:freeform",
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
        form["domain_names_http01"] = ",".join(
            _test_data["acme-order/new/freeform#1"]["domain_names_http01"]
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
            "admin:acme_order:focus:renew:custom|json",
            "admin:acme_order:focus:renew:quick|json",
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

        # "admin:acme_order:focus|json",
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % obj_id, status=200
        )
        assert "AcmeOrder" in res.json

        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/acme-server/sync.json" % obj_id,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync"

        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/acme-server/sync-authorizations.json"
            % obj_id,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync-authorizations"

        _dbAcmeOrder = self.ctx.dbSession.query(model_objects.AcmeOrder).get(obj_id)
        assert len(_dbAcmeOrder.acme_authorizations) == len(
            _test_data["acme-order/new/freeform#1"]["domain_names_http01"]
        )
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
            "/.well-known/admin/acme-authorization/%s.json" % auth_id_1, status=200
        )
        assert "AcmeAuthorization" in res.json

        # "admin:acme_authorization:focus:sync|json"
        res = self.testapp.post(
            "/.well-known/admin/acme-authorization/%s/acme-server/sync.json"
            % auth_id_1,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync"

        # note: originally we triggered the AUTHORIZATION `acme-authorization/%s/acme-server/trigger.json`
        # "admin:acme_challenge:focus:acme_server:trigger|json",
        res = self.testapp.post(
            "/.well-known/admin/acme-challenge/%s/acme-server/trigger.json"
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
            "/.well-known/admin/acme-challenge/%s.json" % challenge_id_2, status=200
        )
        assert "AcmeChallenge" in res.json

        # "admin:acme_challenge:focus:acme_server:sync|json",
        res = self.testapp.post(
            "/.well-known/admin/acme-challenge/%s/acme-server/sync.json"
            % challenge_id_2,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync"

        # "admin:acme_challenge:focus:acme_server:trigger|json",
        res = self.testapp.post(
            "/.well-known/admin/acme-challenge/%s/acme-server/trigger.json"
            % challenge_id_2,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/trigger"

        # "admin:acme_authorization:focus:sync|json"
        res = self.testapp.post(
            "/.well-known/admin/acme-authorization/%s/acme-server/sync.json"
            % auth_id_2,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync"

        # now go back to the order
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % obj_id,
            status=200,
        )
        assert "AcmeOrder" in res.json
        assert (
            res.json["AcmeOrder"]["acme_order_processing_status"]
            == "processing_started"
        )

        # "admin:acme_order:focus:acme_server:sync|json",
        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/acme-server/sync.json" % obj_id,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "acme-server/sync"

        # "admin:acme_order:focus:acme_finalize|json",
        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/acme-finalize.json" % obj_id,
            {},
            status=200,
        )

        assert res.json["result"] == "success"
        assert res.json["operation"] == "finalize-order"

        # now go back to the order
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % obj_id,
            status=200,
        )
        assert "AcmeOrder" in res.json
        assert (
            res.json["AcmeOrder"]["acme_order_processing_status"]
            == "certificate_downloaded"
        )

        # "admin:acme_order:focus:renew:quick|json",

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
        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/acme-server/sync.json" % obj_id__quick,
            {},
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
        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/acme-finalize.json" % obj_id__quick,
            {},
            status=200,
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

        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/acme-server/sync.json" % obj_id__custom,
            {},
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
        assert len(_test_data["acme-order/new/freeform#2"]["domain_names_http01"]) == 2

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
        form["domain_names_http01"] = ",".join(
            _test_data["acme-order/new/freeform#2"]["domain_names_http01"]
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

        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/acme-server/sync-authorizations.json"
            % obj_id__2,
            {},
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
        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/acme-server/deactivate-authorizations.json"
            % obj_id__2,
            {},
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
        assert res.json["error"] == "HTTP POST required"

        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/retry.json" % obj_id__2, {}, status=200
        )
        assert res.json["result"] == "success"
        assert "AcmeOrder" in res.json
        obj_id__3 = res.json["AcmeOrder"]["id"]

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
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_AcmeOrder_mark_json
        """

        obj_id = self._prep_AcmeOrder_json()

        # grab the order
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % obj_id, status=200
        )
        assert "AcmeOrder" in res.json

        # "mark" deactivate
        assert res.json["AcmeOrder"]["is_processing"]

        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/mark.json?action=deactivate" % obj_id,
            {},
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
        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/mark.json?action=invalid" % obj_id,
            {},
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
        assert res.json["error"] == "HTTP POST required"

        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/retry.json" % obj_id, {}, status=200
        )
        assert res.json["result"] == "success"
        assert "AcmeOrder" in res.json
        obj_id__4 = res.json["AcmeOrder"]["id"]

        # grab the NEW order
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % obj_id__4, status=200
        )
        assert "AcmeOrder" in res.json

        # new orders should default to auto-renew on
        assert res.json["AcmeOrder"]["is_auto_renew"] is True

        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s" % obj_id__4, status=200
        )

        # "mark" manual
        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/mark.json?action=renew_manual" % obj_id,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "mark"
        assert res.json["action"] == "renew_manual"
        assert res.json["AcmeOrder"]["is_auto_renew"] is False

        # and toggle it the other way
        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/mark.json?action=renew_auto" % obj_id,
            {},
            status=200,
        )
        assert res.json["result"] == "success"
        assert res.json["operation"] == "mark"
        assert res.json["action"] == "renew_auto"
        assert res.json["AcmeOrder"]["is_auto_renew"] is True

        # lets make sure we can't do it again!
        res = self.testapp.post(
            "/.well-known/admin/acme-order/%s/mark.json?action=renew_auto" % obj_id,
            {},
            status=200,
        )
        assert res.json["result"] == "error"
        assert res.json["operation"] == "mark"
        assert res.json["error"] == "Can not mark this `AcmeOrder` for renewal."

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:acme_order:new:freeform|json",
            "admin:acme_order:focus|json",
        )
    )
    def test_AcmeOrder_process_single_json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_AcmeOrder_process_single_json
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
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_AcmeOrder_process_multi_json
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
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_AcmeOrder_download_certificate_html
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
        res = self.testapp.get("/.well-known/admin/acme-order/%s" % obj_id, status=200)
        assert "acme_order-download_certificate" in res.forms
        form = res.forms["acme_order-download_certificate"]
        res2 = form.submit()
        assert res2.status_code == 303
        assert RE_AcmeOrder_downloaded_certificate.match(res2.location)

        # grab the order again!
        res3 = self.testapp.get("/.well-known/admin/acme-order/%s" % obj_id, status=200)
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
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_AcmeOrder_download_certificate_json
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
            "/.well-known/admin/acme-order/%s.json" % obj_id, status=200
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
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_AcmeAuthorization_manipulate_html
        """
        (order_id, order_url) = self._prep_AcmeOrder_html()

        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % order_id, status=200
        )
        assert "AcmeOrder" in res.json
        acme_authorization_ids = res.json["AcmeOrder"]["acme_authorization_ids"]
        assert len(acme_authorization_ids) == 2

        #
        # for #1, we deactivate then sync
        #
        id_ = acme_authorization_ids[0]
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s" % id_, status=200
        )
        matched = RE_AcmeAuthorization_deactivate_btn.search(res.text)
        assert matched

        res_deactivated = self.testapp.post(
            "/.well-known/admin/acme-authorization/%s/acme-server/deactivate" % id_,
            {},
            status=303,
        )
        assert RE_AcmeAuthorization_deactivated.match(res_deactivated.location)

        # check the main record, ensure we don't have a match
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s" % id_, status=200
        )
        matched_btn = RE_AcmeAuthorization_deactivate_btn.search(res.text)
        assert not matched_btn
        matched_btn = RE_AcmeAuthorization_sync_btn.search(res.text)
        assert matched_btn

        # try again, and fail
        res_deactivated = self.testapp.post(
            "/.well-known/admin/acme-authorization/%s/acme-server/deactivate" % id_,
            {},
            status=303,
        )
        assert RE_AcmeAuthorization_deactivate_fail.match(res_deactivated.location)

        # now sync
        res_synced = self.testapp.post(
            "/.well-known/admin/acme-authorization/%s/acme-server/sync" % id_,
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
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_AcmeAuthorization_manipulate_json
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

        res_deactivated = self.testapp.post(
            "/.well-known/admin/acme-authorization/%s/acme-server/deactivate.json"
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
            "/.well-known/admin/acme-authorization/%s/acme-server/deactivate.json"
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
            "/.well-known/admin/acme-authorization/%s/acme-server/sync.json" % id_,
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
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_AcmeChallenge_manipulate_html
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
            res_auth = self.testapp.post(
                "/.well-known/admin/acme-authorization/%s/acme-server/sync.json"
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
                    "/.well-known/admin/acme-challenge/%s" % challenge_id, status=200
                )
                assert RE_AcmeChallenge_sync_btn.search(res_challenge.text)
                assert RE_AcmeChallenge_trigger_btn.search(res_challenge.text)

                # sync
                res_sync = self.testapp.post(
                    "/.well-known/admin/acme-challenge/%s/acme-server/sync"
                    % challenge_id,
                    {},
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
                res_trigger = self.testapp.post(
                    "/.well-known/admin/acme-challenge/%s/acme-server/trigger"
                    % challenge_id,
                    {},
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
                res_trigger = self.testapp.post(
                    "/.well-known/admin/acme-challenge/%s/acme-server/trigger"
                    % challenge_id,
                    {},
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
                res_trigger = self.testapp.post(
                    "/.well-known/admin/acme-challenge/%s/acme-server/trigger"
                    % challenge_id,
                    {},
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
                res_sync = self.testapp.post(
                    "/.well-known/admin/acme-challenge/%s/acme-server/sync"
                    % challenge_id,
                    {},
                    status=303,
                )
                assert RE_AcmeChallenge_synced.match(res_sync.location)

                # Get/Audit Main Record
                res_challenge = self.testapp.get(
                    "/.well-known/admin/acme-challenge/%s" % challenge_id, status=200
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
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_AcmeChallenge_manipulate_json
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
            res_auth = self.testapp.post(
                "/.well-known/admin/acme-authorization/%s/acme-server/sync.json"
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
                res_sync = self.testapp.post(
                    "/.well-known/admin/acme-challenge/%s/acme-server/sync.json"
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
                    "/.well-known/admin/acme-challenge/%s/acme-server/trigger.json"
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
                    "/.well-known/admin/acme-challenge/%s/acme-server/trigger.json"
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
                res_trigger = self.testapp.post(
                    "/.well-known/admin/acme-challenge/%s/acme-server/trigger.json"
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
                    "/.well-known/admin/acme-challenge/%s/acme-server/sync.json"
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
    @routes_tested(
        (
            "admin:queue_domains:add",
            "admin:queue_domains:process",
        )
    )
    def test_QueueDomains_process_html__create_order(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_QueueDomains_process_html__create_order
        """
        _domain_names = [
            "test-QueueDomains-process-html-create-order--1.example.com",
            "test-QueueDomains-process-html-create-order--2.example.com",
        ]

        # start off with some domains in the queue!
        res = self.testapp.get("/.well-known/admin/queue-domains/add", status=200)
        form = res.form
        form["domain_names_http01"] = ",".join(_domain_names)
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

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:queue_domains:add",
            "admin:queue_domains:process",
        )
    )
    def test_QueueDomains_process_html__process_single(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_QueueDomains_process_html__process_single

        NOTE: it is not necessary to test `process_multi` as that just does "create_order" with processing done via the AcmeOrder endpoints
        """
        _domain_names = [
            "test-QueueDomains-process-html-process-single--1.example.com",
            "test-QueueDomains-process-html-process-single--2.example.com",
        ]

        # start off with some domains in the queue!
        res = self.testapp.get("/.well-known/admin/queue-domains/add", status=200)
        form = res.form
        form["domain_names_http01"] = ",".join(_domain_names)
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

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(
        (
            "admin:queue_domains:add|json",
            "admin:queue_domains:process|json",
        )
    )
    def test_QueueDomains_process_json__create_order(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_QueueDomains_process_json__create_order
        """
        _domain_names = [
            "test-QueueDomains-process-json-create-order--1.example.com",
            "test-QueueDomains-process-json-create-order--2.example.com",
        ]

        # start off with some domains in the queue!
        res = self.testapp.get("/.well-known/admin/queue-domains/add.json", status=200)
        _data = {"domain_names_http01": ",".join(_domain_names)}
        res2 = self.testapp.post("/.well-known/admin/queue-domains/add.json", _data)
        assert res2.status_code == 200
        assert res2.json["result"] == "success"
        assert "domains" in res2.json
        for _domain in _domain_names:
            _domain = _domain.lower()
            assert _domain in res2.json["domains"]
            assert res2.json["domains"][_domain] == "queued"

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

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(("admin:queue_domains:process|json",))
    def test_QueueDomains_process_json__process_single(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_QueueDomains_process_json__process_single
        """
        _domain_names = [
            "test-QueueDomains-process-json-process-single--1.example.com",
            "test-QueueDomains-process-json-process-single--2.example.com",
        ]

        # start off with some domains in the queue!
        res = self.testapp.get("/.well-known/admin/queue-domains/add.json", status=200)
        _data = {"domain_names_http01": ",".join(_domain_names)}
        res2 = self.testapp.post("/.well-known/admin/queue-domains/add.json", _data)
        assert res2.status_code == 200
        assert res2.json["result"] == "success"
        assert "domains" in res2.json

        for _domain in _domain_names:
            _domain = _domain.lower()
            assert _domain in res2.json["domains"]
            assert res2.json["domains"][_domain] == "queued"

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

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(("admin:api:queue_certificates:update",))
    def test_QueueCertificates_api_update_html(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_QueueCertificates_api_update_html
        """
        res = self.testapp.get(
            "/.well-known/admin/api/queue-certificates/update", status=303
        )
        assert (
            res.location
            == """http://peter-sslers.example.com/.well-known/admin/queue-certificates?result=success&operation=update&results=true"""
        )
        # TODO - populate the database so it will actually update the queue, retest

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(("admin:api:queue_certificates:update|json",))
    def test_QueueCertificates_api_update_json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_QueueCertificates_api_update_json
        """

        res = self.testapp.post(
            "/.well-known/admin/api/queue-certificates/update.json", status=200
        )
        assert res.json["result"] == "success"
        assert res.json["results"] is True
        # TODO - populate the database so it will actually update the queue, retest

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(("admin:api:queue_certificates:process",))
    def test_QueueCertificates_api_process_html(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_QueueCertificates_api_process_html
        """
        res = self.testapp.get(
            "/.well-known/admin/api/queue-certificates/process", status=303
        )
        assert res.location.startswith(
            """http://peter-sslers.example.com/.well-known/admin/queue-certificates?result=success&operation=process&results="""
        )

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(("admin:api:queue_certificates:process|json",))
    def test_QueueCertificates_api_process_json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_QueueCertificates_api_process_json
        """

        res = self.testapp.post(
            "/.well-known/admin/api/queue-certificates/process.json", status=200
        )
        assert res.json["result"] == "success"
        assert "queue_results" in res.json

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @routes_tested(("admin:api:domain:autocert|json",))
    def test_Api_Domain_autocert_json(self):
        """
        python -m unittest tests.test_pyramid_app.FunctionalTests_AcmeServer.test_Api_Domain_autocert_json
        """
        res = self.testapp.post(
            "/.well-known/admin/api/domain/autocert.json", {}, status=200
        )
        assert "result" in res.json
        assert res.json["result"] == "error"
        assert "form_errors" in res.json
        assert res.json["form_errors"]["Error_Main"] == "Nothing submitted."
        assert res.json["domain"] is None
        assert res.json["certificate_signed__latest_single"] is None
        assert res.json["certificate_signed__latest_multi"] is None

        # Test 1 -- autocert a domain we don't know, but want to pass
        res = self.testapp.post(
            "/.well-known/admin/api/domain/autocert.json",
            {"domain_name": "test-domain-autocert-1.example.com"},
            status=200,
        )
        assert res.json["result"] == "success"
        assert "domain" in res.json
        assert "certificate_signed__latest_multi" in res.json
        assert "certificate_signed__latest_single" in res.json
        assert res.json["certificate_signed__latest_single"] is not None
        assert "AcmeOrder" in res.json

        # Test 2 -- autocert that same domain
        res = self.testapp.post(
            "/.well-known/admin/api/domain/autocert.json",
            {"domain_name": "test-domain-autocert-1.example.com"},
            status=200,
        )
        assert res.json["result"] == "success"
        assert "domain" in res.json
        assert "certificate_signed__latest_multi" in res.json
        assert "certificate_signed__latest_single" in res.json
        assert res.json["certificate_signed__latest_single"] is not None
        assert "AcmeOrder" not in res.json

        # Test 3 -- blocklist a domain, then try to autocert
        dbDomainBlocklisted = model_objects.DomainBlocklisted()
        dbDomainBlocklisted.domain_name = "test-domain-autocert-2.example.com"
        self.ctx.dbSession.add(dbDomainBlocklisted)
        self.ctx.dbSession.flush(
            objects=[
                dbDomainBlocklisted,
            ]
        )
        self.ctx.dbSession.commit()
        res = self.testapp.post(
            "/.well-known/admin/api/domain/autocert.json",
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
        assert res.json["domain"] is None
        assert res.json["certificate_signed__latest_single"] is None
        assert res.json["certificate_signed__latest_multi"] is None

        # Test 4 -- autocert an inactive domain
        # 4.1 add the domain
        res = self.testapp.get("/.well-known/admin/domain/new", status=200)
        assert "form-domain-new" in res.forms
        form = res.forms["form-domain-new"]
        form["domain_name"] = "test-domain-autocert-3.example.com"
        res2 = form.submit()
        assert res2.status_code == 303
        matched = RE_Domain_new.match(res2.location)
        assert matched
        focus_id = matched.groups()[0]

        # 4.2 mark the domain inactve
        res = self.testapp.post(
            "/.well-known/admin/domain/%s/mark" % focus_id,
            {"action": "inactive"},
        )
        assert res.status_code == 303
        assert res.location.endswith("?result=success&operation=mark&action=inactive")

        # 4.3 autocert
        res = self.testapp.post(
            "/.well-known/admin/api/domain/autocert.json",
            {"domain_name": "test-domain-autocert-3.example.com"},
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
            == "This domain_name has been disabled"
        )
        assert res.json["domain"] is None
        assert res.json["certificate_signed__latest_single"] is None
        assert res.json["certificate_signed__latest_multi"] is None


class FunctionalTests_API(AppTest):
    """
    python -m unittest tests.test_pyramid_app.FunctionalTests_API
    """

    @routes_tested(("admin:api", "admin:api:domain:autocert"))
    def test_passive(self):
        res = self.testapp.get("/.well-known/admin/api", status=200)
        res = self.testapp.get("/.well-known/admin/api/domain/autocert", status=200)

    @routes_tested(
        (
            "admin:api:domain:enable",
            "admin:api:domain:disable",
        )
    )
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

    @routes_tested(
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

        res = self.testapp.post(
            "/.well-known/admin/api/deactivate-expired.json", {}, status=200
        )
        assert res.json["result"] == "success"

        # update-recents
        res = self.testapp.get("/.well-known/admin/api/update-recents", status=303)
        assert (
            "/.well-known/admin/operations/log?result=success&event.id=" in res.location
        )

        res = self.testapp.post(
            "/.well-known/admin/api/update-recents.json", {}, status=200
        )
        assert res.json["result"] == "success"

    @routes_tested(
        (
            "admin:api:certificate_ca:letsencrypt_sync",
            "admin:api:certificate_ca:letsencrypt_sync|json",
        )
    )
    def test_letsencrypt_sync(self):
        res = self.testapp.post(
            "/.well-known/admin/api/certificate-ca/letsencrypt-sync", {}, status=303
        )
        assert (
            "/admin/operations/certificate-ca-downloads?result=success&event.id="
            in res.location
        )

        res = self.testapp.post(
            "/.well-known/admin/api/certificate-ca/letsencrypt-sync.json",
            {},
            status=200,
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
            "/.well-known/admin/api/update-recents.json", {}, status=200
        )
        assert res.json["result"] == "success"

        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

        res = self.testapp.get("/.well-known/admin/api/redis/prime", status=303)
        assert (
            "/.well-known/admin/operations/redis?result=success&operation=redis_prime&event.id="
            in res.location
        )

        res = self.testapp.post(
            "/.well-known/admin/api/redis/prime.json", {}, status=200
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
        res = self.testapp.get("/.well-known/admin/api/nginx/cache-flush", status=303)
        assert (
            "/.well-known/admin/operations/nginx?result=success&operation=nginx_cache_flush&event.id="
            in res.location
        )

        res = self.testapp.get(
            "/.well-known/admin/api/nginx/cache-flush.json", status=200
        )
        assert res.json["result"] == "success"
        assert "servers_status" in res.json
        assert "errors" in res.json["servers_status"]
        assert not res.json["servers_status"]["errors"]
        for server in self.testapp.app.registry.settings["app_settings"][
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

        res = self.testapp.get("/.well-known/admin/api/nginx/status.json", status=200)
        assert res.json["result"] == "success"
        assert "servers_status" in res.json
        assert "errors" in res.json["servers_status"]
        assert not res.json["servers_status"]["errors"]
        for server in self.testapp.app.registry.settings["app_settings"][
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

    def test_post_required_html(self):
        res = self.testapp.get(
            "/.well-known/admin/api/certificate-ca/letsencrypt-sync", status=303
        )
        assert (
            res.location
            == "http://peter-sslers.example.com/.well-known/admin/operations/certificate-ca-downloads?result=error&operation=certificate_ca-letsencrypt_sync&error=HTTP+POST+required"
        )

    def test_post_required_json(self):
        # !!!: test `POST required` `api/domain/autocert.json`
        res = self.testapp.get(
            "/.well-known/admin/api/domain/autocert.json", status=200
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `api/deactivate-expired.json`
        res = self.testapp.get(
            "/.well-known/admin/api/deactivate-expired.json", status=200
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `api/update-recents.json`
        res = self.testapp.get("/.well-known/admin/api/update-recents.json", status=200)
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        # !!!: test `POST required` `api/certificate-ca/letsencrypt-sync.json`
        res = self.testapp.get(
            "/.well-known/admin/api/certificate-ca/letsencrypt-sync.json",
            status=200,
        )
        assert "instructions" in res.json
        assert "HTTP POST required" in res.json["instructions"]

        try:
            res = self.testapp.get(
                "/.well-known/admin/api/redis/prime.json", status=200
            )
            assert "instructions" in res.json
            assert "HTTP POST required" in res.json["instructions"]
        except:
            if RUN_REDIS_TESTS:
                raise


class IntegratedTests_AcmeServer(AppTestWSGI):
    """
    This test suite runs against a Pebble instance, which will try to validate the domains.
    This tests serving and responding to validations.

    python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer
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
            self._filepath_testfile(account_key_file_pem),
            "rb",
        )
        form["account__contact"] = account__contact
        form["account__private_key_cycle"] = "account_daily"
        form["private_key_cycle__renewal"] = "account_key_default"
        form["private_key_option"] = "private_key_for_account_key"
        form["domain_names_http01"] = ",".join(domain_names)
        form["processing_strategy"] = "process_single"
        resp = requests.post(
            "http://peter-sslers.example.com:5002/.well-known/admin/acme-order/new/freeform.json",
            data=form,
            files=files,
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

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble_strict
    def test_AcmeOrder_nocleanup(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer.test_AcmeOrder_nocleanup

        this test is not focused on routes, but cleaning up an order

        must use pebble_strict so there are no reused auths
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
            # because we could have failed on any of the 20 authorizations
            # start with 20 auths
            _expected_max = stats_og["count-AcmeAuthorization-pending"] + 20
            # no need to assume one for the failed auth
            _expected_min = stats_og["count-AcmeAuthorization-pending"] + 1
            assert stats_b["count-AcmeAuthorization-pending"] < _expected_max
            assert stats_b["count-AcmeAuthorization-pending"] > _expected_min

        finally:
            # reset
            self.testapp_wsgi.test_app.registry.settings["app_settings"][
                "cleanup_pending_authorizations"
            ] = True

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble_strict
    @routes_tested(("admin:api:domain:certificate-if-needed",))
    def test_domain_certificate_if_needed(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer.test_domain_certificate_if_needed
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
        form["domain_name"] = _domain_name
        res3 = self.testapp.post(
            "/.well-known/admin/api/domain/certificate-if-needed", form
        )
        assert res3.status_code == 200
        assert res3.json["result"] == "success"
        assert "domain_results" in res3.json
        assert _domain_name in res3.json["domain_results"]
        try:
            assert (
                res3.json["domain_results"][_domain_name]["certificate_signed.status"]
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
        form["domain_name"] = ",".join(_domain_names)
        res4 = self.testapp.post(
            "/.well-known/admin/api/domain/certificate-if-needed", form
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
            "/.well-known/admin/api/domain/certificate-if-needed", form
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
            "/.well-known/admin/api/domain/certificate-if-needed", form
        )
        assert res6.status_code == 200
        assert res6.json["result"] == "success"
        assert "domain_results" in res6.json
        assert _domain_name in res6.json["domain_results"]
        assert (
            res6.json["domain_results"][_domain_name]["certificate_signed.status"]
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
        form["domain_name"] = _domain_name
        res7 = self.testapp.post(
            "/.well-known/admin/api/domain/certificate-if-needed", form
        )
        assert res7.status_code == 200
        assert res7.json["result"] == "success"
        assert "domain_results" in res7.json
        assert _domain_name in res7.json["domain_results"]
        assert (
            res7.json["domain_results"][_domain_name]["certificate_signed.status"]
            == "exists"
        )
        assert (
            res7.json["domain_results"][_domain_name]["domain.status"]
            == "existing.activated"
        )
        assert res7.json["domain_results"][_domain_name]["acme_order.id"] is None

    @unittest.skipUnless(RUN_REDIS_TESTS, "Not Running Against: redis")
    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @under_redis
    @routes_tested(
        (
            "admin:api:redis:prime",
            "admin:api:redis:prime|json",
        )
    )
    def test_redis(self):
        """
        python -m unittest tests.test_pyramid_app.IntegratedTests_AcmeServer.test_redis
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
        form["domain_name"] = _domain_name
        res = self.testapp.post(
            "/.well-known/admin/api/domain/certificate-if-needed", form
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
