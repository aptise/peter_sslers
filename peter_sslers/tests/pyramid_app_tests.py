from __future__ import print_function

# stdlib
import datetime
import json
import os
import pdb
import pprint
import re
import unittest

# pypi
from webtest import Upload
from webtest.http import StopableWSGIServer

# local
from ._utils import FakeRequest
from ._utils import TEST_FILES
from ._utils import AppTest
from ..model import objects as model_objects
from ..model import utils as model_utils

# local, flags
from ._utils import DISABLE_UNWRITTEN_TESTS
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
        def _wrapper(*args, **kwargs):
            _function(*args, **kwargs)

        return _wrapper

    return _decorator


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
    def test_whoami(self):
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
    def test_whoami(self):
        res = self.testapp.get("/.well-known/public/whoami", status=200)


class FunctionalTests_AcmeAccountKey(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AcmeAccountKey

    python -m unittest peter_sslers.tests.FunctionalTests_AcmeAccountKey.test_new
    python -m unittest peter_sslers.tests.FunctionalTests_AcmeAccountKey.test_upload
    """

    def _get_item(self):
        # grab a Key
        focus_item = (
            self.ctx.dbSession.query(model_objects.AcmeAccountKey)
            .filter(model_objects.AcmeAccountKey.is_active.op("IS")(True))
            .order_by(model_objects.AcmeAccountKey.id.asc())
            .first()
        )
        return focus_item

    @tests_routes("admin:acme_account_key:upload")
    def test_upload_html(self):

        # this should be creating a new key
        _key_filename = TEST_FILES["AcmeAccountKey"]["2"]["key"]
        _private_key_cycle = TEST_FILES["AcmeAccountKey"]["2"]["private_key_cycle"]
        key_filepath = self._filepath_testfile(_key_filename)

        res = self.testapp.get("/.well-known/admin/acme-account-key/upload", status=200)
        form = res.form
        form["account_key_file_pem"] = Upload(key_filepath)
        form["acme_account_provider_id"].force_value(
            str(1)
        )  # acme_account_provider_id(1) == pebble
        res2 = form.submit()
        assert res2.status_code == 303
        assert res2.location.startswith(
            """http://localhost:80/.well-known/admin/acme-account-key/"""
        )
        assert res2.location.endswith(
            """?result=success&operation=upload&is_created=1"""
        )
        res3 = self.testapp.get(res2.location, status=200)

    @tests_routes("admin:acme_account_key:upload|json")
    def test_upload_json(self):
        _key_filename = TEST_FILES["AcmeAccountKey"]["2"]["key"]
        _private_key_cycle = TEST_FILES["AcmeAccountKey"]["2"]["private_key_cycle"]
        key_filepath = self._filepath_testfile(_key_filename)

        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/upload.json", status=200
        )
        res_json = json.loads(res.body)
        assert "instructions" in res_json

        form = {}
        form["account_key_file_pem"] = Upload(key_filepath)
        form["acme_account_provider_id"] = "1"  # acme_account_provider_id(1) == pebble
        res2 = self.testapp.post(
            "/.well-known/admin/acme-account-key/upload.json", form
        )
        assert res2.status_code == 200
        res2_json = json.loads(res2.body)
        assert "result" in res2_json
        pprint.pprint(res2_json)
        assert res2_json["result"] == "error"
        assert "form_errors" in res2_json
        assert isinstance(res2_json["form_errors"], dict)
        assert len(res2_json["form_errors"].keys()) == 2
        assert (
            res2_json["form_errors"]["Error_Main"]
            == "There was an error with your form."
        )
        assert res2_json["form_errors"]["private_key_cycle"] == "Missing value"

        form = {}
        form["account_key_file_pem"] = Upload(key_filepath)
        form["acme_account_provider_id"] = "1"  # acme_account_provider_id(1) == pebble
        form["private_key_cycle"] = TEST_FILES["AcmeAccountKey"]["2"][
            "private_key_cycle"
        ]
        res3 = self.testapp.post(
            "/.well-known/admin/acme-account-key/upload.json", form
        )
        assert res3.status_code == 200
        res3_json = json.loads(res3.body)
        assert "result" in res3_json
        pprint.pprint(res3_json)
        assert res3_json["result"] == "success"

    @tests_routes(("admin:acme_account_keys", "admin:acme_account_keys_paginated"))
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/acme-account-keys", status=200)
        # paginated
        res = self.testapp.get("/.well-known/admin/acme-account-keys/1", status=200)

    @tests_routes(
        ("admin:acme_account_keys|json", "admin:acme_account_keys_paginated|json")
    )
    def test_list_json(self):
        # json root
        res = self.testapp.get("/.well-known/admin/acme-account-keys.json", status=200)
        res_json = json.loads(res.body)
        assert "AcmeAccountKeys" in res_json

        # json paginated
        res = self.testapp.get(
            "/.well-known/admin/acme-account-keys/1.json", status=200
        )
        res_json = json.loads(res.body)
        assert "AcmeAccountKeys" in res_json

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "not running against LetsEncrypt API")
    @tests_routes("admin:acme_account_key:new")
    def test_new_html(self):
        res = self.testapp.get("/.well-known/admin/acme-account-key/new", status=200)
        form = res.form
        form["acme_account_provider_id"].force_value(
            str(1)
        )  # acme_account_provider_id(1) == pebble
        res2 = form.submit()
        assert res2.status_code == 200
        assert "There was an error with your form." in res2.body
        assert "contact is required." in res2.body

        form = res2.form
        form["contact"].force_value("foo@example.com")
        res2 = form.submit()
        assert res2.status_code == 303
        # assert res2.location == """http://localhost:80/.well-known/admin/acme-account-key/2?result=success&operation=new&is_created=1"""
        assert res2.location.startswith(
            """http://localhost:80/.well-known/admin/acme-account-key/"""
        )
        assert res2.location.endswith("""?result=success&operation=new&is_created=1""")

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "not running against LetsEncrypt API")
    @tests_routes("admin:acme_account_key:new|json")
    def test_new_json(self):
        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/new.json", status=200
        )
        assert "form_fields" in res.json

        form = {}
        res2 = self.testapp.post("/.well-known/admin/acme-account-key/new.json", form)
        assert res2.json["result"] == "error"
        assert "form_errors" in res2.json
        assert isinstance(res2.json["form_errors"], dict)
        assert len(res2.json["form_errors"]) == 1
        assert res2.json["form_errors"]["Error_Main"] == "Nothing submitted."

        form = {
            "acme_account_provider_id": 1,
            "contact": "bar@example.com",
            "private_key_cycle": "single_certificate",
        }
        res3 = self.testapp.post("/.well-known/admin/acme-account-key/new.json", form)
        assert res3.json["result"] == "success"
        assert "AcmeAccountKey" in res3.json

    @tests_routes(
        (
            "admin:acme_account_key:focus",
            "admin:acme_account_key:focus:acme_authorizations",
            "admin:acme_account_key:focus:acme_authorizations_paginated",
            "admin:acme_account_key:focus:acme_orders",
            "admin:acme_account_key:focus:acme_orders_paginated",
            "admin:acme_account_key:focus:private_keys",
            "admin:acme_account_key:focus:private_keys_paginated",
            "admin:acme_account_key:focus:server_certificates",
            "admin:acme_account_key:focus:server_certificates_paginated",
        )
    )
    def test_focus_html(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s/acme-authorizations" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s/acme-authorizations/1" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s/acme-orders" % focus_id, status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s/acme-orders/1" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s/private-keys" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s/private-keys/1" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s/server-certificates" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s/server-certificates/1" % focus_id,
            status=200,
        )

    @tests_routes(
        (
            "admin:acme_account_key:focus|json",
            "admin:acme_account_key:focus:config|json",
            "admin:acme_account_key:focus:parse|json",
            "admin:acme_account_key:focus:acme_authorizations|json",
            "admin:acme_account_key:focus:acme_authorizations_paginated|json",
        )
    )
    def test_focus_json(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s.json" % focus_id, status=200
        )
        res_json = json.loads(res.body)
        assert "AcmeAccountKey" in res_json

        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s/config.json" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s/parse.json" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s/acme-authorizations.json"
            % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s/acme-authorizations/1.json"
            % focus_id,
            status=200,
        )

    @tests_routes("admin:acme_account_key:focus:raw")
    def test_focus_raw(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s/key.key" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s/key.pem" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s/key.pem.txt" % focus_id, status=200
        )

    @tests_routes(
        ("admin:acme_account_key:focus:edit", "admin:acme_account_key:focus:mark")
    )
    def test_manipulate_html(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        if not focus_item.is_global_default:
            # make sure to roundtrip!
            # note we expect a 303 on success!
            if focus_item.is_active:
                res = self.testapp.get(
                    "/.well-known/admin/acme-account-key/%s/mark" % focus_id,
                    {"action": "inactive"},
                    status=303,
                )
            else:
                res = self.testapp.get(
                    "/.well-known/admin/acme-account-key/%s/mark" % focus_id,
                    {"action": "active"},
                    status=303,
                )
        else:
            # TODO
            raise ValueError("MUST TEST non-default")

        # edit it
        # only the private_key_cycle
        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s/edit" % focus_id, status=200
        )
        form = res.form
        _existing = form["private_key_cycle"].value
        _new = None
        if _existing == "single_certificate":
            _new = "account_daily"
        else:
            _new = "single_certificate"
        form["private_key_cycle"] = _new
        res2 = form.submit()
        assert res2.status_code == 303
        assert (
            res2.location
            == """http://localhost:80/.well-known/admin/acme-account-key/%s?result=success&operation=edit"""
            % focus_id
        )
        res3 = self.testapp.get(res2.location, status=200)

    @tests_routes(
        (
            "admin:acme_account_key:focus:edit|json",
            "admin:acme_account_key:focus:mark|json",
        )
    )
    def test_manipulate_json(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        if not focus_item.is_global_default:
            # make sure to roundtrip!
            # note we expect a 303 on success!
            if focus_item.is_active:
                res = self.testapp.get(
                    "/.well-known/admin/acme-account-key/%s/mark.json" % focus_id,
                    {"action": "active"},
                    status=200,
                )
            else:
                res = self.testapp.get(
                    "/.well-known/admin/acme-account-key/%s/mark.json" % focus_id,
                    {"action": "inactive"},
                    status=200,
                )
        else:
            # TODO
            raise ValueError("MUST TEST non-default")

        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s/edit.json" % focus_id, status=200
        )
        assert "form_fields" in res.json

        form = {}
        res2 = self.testapp.post(
            "/.well-known/admin/acme-account-key/%s/edit.json" % focus_id, form
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
        form = {"private_key_cycle": _new}
        res3 = self.testapp.post(
            "/.well-known/admin/acme-account-key/%s/edit.json" % focus_id, form
        )
        assert res3.json["result"] == "success"
        assert "AcmeAccountKey" in res3.json

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "not running against LetsEncrypt API")
    @tests_routes("admin:acme_account_key:focus:authenticate")
    def test_authenticate_html(self):
        # this hits Pebble via http
        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/1/authenticate", status=303
        )
        assert (
            res.location
            == "http://localhost:80/.well-known/admin/acme-account-key/1?result=error&error=post+required&operation=authenticate"
        )

        res = self.testapp.post(
            "/.well-known/admin/acme-account-key/1/authenticate", {}
        )
        assert (
            res.location
            == """http://localhost:80/.well-known/admin/acme-account-key/1?result=success&operation=authenticate&is_authenticated=True"""
        )

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "not running against LetsEncrypt API")
    @tests_routes("admin:acme_account_key:focus:authenticate|json")
    def test_authenticate_json(self):
        # this hits Pebble via http
        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/1/authenticate.json", status=200
        )
        assert res.location is None  # no redirect

        res = self.testapp.post(
            "/.well-known/admin/acme-account-key/1/authenticate.json", {}
        )
        assert res.status_code == 200
        assert res.location is None  # no redirect
        assert "AcmeAccountKey" in res.json


class FunctionalTests_AcmeAuthorizations(AppTest):
    """
    python -m unittest peter_sslers.tests.FunctionalTests_AcmeAuthorizations
    """

    def _get_item(self):
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
        res_json = json.loads(res.body)
        assert "AcmeAuthorizations" in res_json
        # json paginated
        res = self.testapp.get(
            "/.well-known/admin/acme-authorizations/1.json", status=200
        )
        res_json = json.loads(res.body)
        assert "AcmeAuthorizations" in res_json

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
        focus_item = self._get_item()
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
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s.json" % focus_id, status=200
        )
        res_json = json.loads(res.body)
        assert "AcmeAuthorization" in res_json

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "not running against LetsEncrypt API")
    @tests_routes(
        (
            "admin:acme_authorization:focus:acme_server:deactivate",
            "admin:acme_authorization:focus:acme_server:sync",
            "admin:acme_authorization:focus:acme_server:trigger",
        )
    )
    def test_manipulate_html(self):
        """
        "/acme-authorization/{@id}/acme-server/sync",
        "/acme-authorization/{@id}/acme-server/deactivate",
        "/acme-authorization/{@id}/acme-server/trigger",
        """
        raise ValueError("TESTS NOT WRITTEN YET")

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "not running against LetsEncrypt API")
    @tests_routes(
        (
            "admin:acme_authorization:focus:acme_server:deactivate|json",
            "admin:acme_authorization:focus:acme_server:sync|json",
            "admin:acme_authorization:focus:acme_server:trigger|json",
        )
    )
    def test_manipulate_json(self):
        """
        "/acme-authorization/{@id}/acme-server/sync.json",
        "/acme-authorization/{@id}/acme-server/deactivate.json",
        "/acme-authorization/{@id}/acme-server/trigger.json",
        """
        raise ValueError("TESTS NOT WRITTEN YET")


class FunctionalTests_AcmeChallenges(AppTest):
    def _get_item(self):
        # grab an order
        focus_item = (
            self.ctx.dbSession.query(model_objects.AcmeChallenge)
            .order_by(model_objects.AcmeChallenge.id.asc())
            .first()
        )
        return focus_item

    @tests_routes(("admin:acme_challenges", "admin:acme_challenges_paginated"))
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/acme-challenges", status=200)
        # paginated
        res = self.testapp.get("/.well-known/admin/acme-challenges/1", status=200)

    @tests_routes(
        ("admin:acme_challenges|json", "admin:acme_challenges_paginated|json")
    )
    def test_list_json(self):
        # json root
        res = self.testapp.get("/.well-known/admin/acme-challenges.json", status=200)
        res_json = json.loads(res.body)
        assert "AcmeChallenges" in res_json

        # json paginated
        res = self.testapp.get("/.well-known/admin/acme-challenges/1.json", status=200)
        res_json = json.loads(res.body)
        assert "AcmeChallenges" in res_json

    @tests_routes(("admin:acme_challenge:focus"))
    def test_focus_html(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-challenge/%s" % focus_id, status=200
        )

    @tests_routes(("public_challenge"))
    def test_public_challenge(self):
        raise ValueError("TODO")
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id
        challenge = None

        res = self.testapp.get("/.well-known/acme-challenge/%s" % challenge, status=200)

    @tests_routes(("admin:acme_challenge:focus|json"))
    def test_focus_json(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-challenge/%s.json" % focus_id, status=200
        )
        res_json = json.loads(res.body)
        assert "AcmeChallenge" in res_json

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "not running against LetsEncrypt API")
    @tests_routes(
        (
            "admin:acme_challenge:focus:acme_server:sync",
            "admin:acme_challenge:focus:acme_server:trigger",
        )
    )
    def test_manipulate_html(self):
        pass
        """
        "admin:acme_challenge:focus:acme_server:sync",
        "admin:acme_challenge:focus:acme_server:trigger",
        """
        raise ValueError("TESTS NOT WRITTEN YET")

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "not running against LetsEncrypt API")
    @tests_routes(
        (
            "admin:acme_challenge:focus:acme_server:sync|json",
            "admin:acme_challenge:focus:acme_server:trigger|json",
        )
    )
    def test_manipulate_json(self):
        pass
        """
        "admin:acme_challenge:focus:acme_server:sync.json",
        "admin:acme_challenge:focus:acme_server:trigger.json",
        """
        raise ValueError("TESTS NOT WRITTEN YET")


class FunctionalTests_AcmeChallengePolls(AppTest):
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
        res_json = json.loads(res.body)
        assert "AcmeChallengePolls" in res_json

        # json paginated
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge-polls/1.json", status=200
        )
        res_json = json.loads(res.body)
        assert "AcmeChallengePolls" in res_json


class FunctionalTests_AcmeChallengeUnknownPolls(AppTest):
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
        res_json = json.loads(res.body)
        assert "AcmeChallengeUnknownPolls" in res_json

        # json paginated
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge-unknown-polls/1.json", status=200
        )
        res_json = json.loads(res.body)
        assert "AcmeChallengeUnknownPolls" in res_json


class FunctionalTests_AcmeEventLog(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_AcmeEventLog"""

    def _get_item(self):
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
        res_json = json.loads(res.body)
        assert "AcmeEventLogs" in res_json
        # json paginated
        res = self.testapp.get("/.well-known/admin/acme-event-logs/1.json", status=200)
        res_json = json.loads(res.body)
        assert "AcmeEventLogs" in res_json

    @tests_routes(("admin:acme_event_log:focus"))
    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "not running against LetsEncrypt API")
    def test_focus_html(self):
        """logs are only populated when running against the LetsEncrypt API
        """
        # focus
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id
        res = self.testapp.get(
            "/.well-known/admin/acme-event-log/%s" % focus_id, status=200
        )

    @tests_routes(("admin:acme_event_log:focus|json"))
    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "not running against LetsEncrypt API")
    def test_focus_json(self):
        """logs are only populated when running against the LetsEncrypt API
        """
        res = self.testapp.get(
            "/.well-known/admin/acme-event-log/%s.json" % focus_id, status=200
        )
        res_json = json.loads(res.body)
        assert "AcmeEventLog" in res_json


class FunctionalTests_AcmeOrder(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_AcmeOrder"""

    def _get_item(self):
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
        res_json = json.loads(res.body)
        assert "AcmeOrders" in res_json

        res = self.testapp.get("/.well-known/admin/acme-orders/1.json", status=200)
        res_json = json.loads(res.body)
        assert "AcmeOrders" in res_json

    @tests_routes(
        (
            "admin:acme_order:focus",
            "admin:acme_order:focus:acme_event_logs",
            "admin:acme_order:focus:acme_event_logs_paginated",
        )
    )
    def test_focus_html(self):
        focus_item = self._get_item()
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

    @tests_routes("admin:acme_order:focus|json")
    def test_focus_json(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % focus_id, status=200
        )
        res_json = json.loads(res.body)
        assert "AcmeOrder" in res_json

    @tests_routes(
        (
            "admin:acme_order:focus:acme_process",
            "admin:acme_order:focus:finalize",
            "admin:acme_order:focus:acme_server:sync",
            "admin:acme_order:focus:acme_server:sync_authorizations",
            "admin:acme_order:focus:acme_server:deactivate_authorizations",
            "admin:acme_order:focus:acme_server:download_certificate",
            "admin:acme_order:focus:mark",
            "admin:acme_order:focus:retry",
            "admin:acme_order:focus:renew:custom",
            "admin:acme_order:focus:renew:quick",
            "admin:acme_order:new:automated",
        )
    )
    def test_manipulate_html(self):
        raise ValueError("todo")

    @tests_routes(
        (
            "admin:acme_order:focus:acme_process|json",
            "admin:acme_order:focus:finalize|json",
            "admin:acme_order:focus:acme_server:sync|json",
            "admin:acme_order:focus:acme_server:sync_authorizations|json",
            "admin:acme_order:focus:acme_server:deactivate_authorizations|json",
            "admin:acme_order:focus:acme_server:download_certificate|json",
            "admin:acme_order:focus:mark|json",
            "admin:acme_order:focus:retry|json",
            "admin:acme_order:focus:renew:custom|json",
            "admin:acme_order:focus:renew:quick|json",
            "admin:acme_order:new:automated|json",
        )
    )
    def test_manipulate_json(self):
        raise ValueError("todo")

        @unittest.skipUnless(
            RUN_API_TESTS__PEBBLE, "not running against LetsEncrypt API"
        )
        def test_api__pebble(self):
            self.testapp_http = StopableWSGIServer.create(
                self.testapp.app, port=SSL_TEST_PORT
            )
            self.testapp_http.wait()
            res = self.testapp.get(
                "/.well-known/admin/acme-order/new/automated", status=200
            )
            form = res.form
            form["account_key_file_pem"] = Upload(
                self._filepath_testfile(
                    TEST_FILES["CertificateRequests"]["acme_test"]["account_key"]
                )
            )
            form["private_key_file_pem"] = Upload(
                self._filepath_testfile(
                    TEST_FILES["CertificateRequests"]["acme_test"]["private_key"]
                )
            )
            form["domain_names"] = TEST_FILES["CertificateRequests"]["acme_test"][
                "domains"
            ]
            res2 = form.submit()
            assert res2.status_code == 303
            if not LETSENCRYPT_API_VALIDATES:
                if (
                    "/.well-known/admin/certificate-requests?error=new-AcmeAutomated&message=Wrote keyauth challenge, but couldn't download"
                    not in res2.location
                ):
                    raise ValueError("Expected an error: failure to validate")
            else:
                if (
                    "/.well-known/admin/certificate-requests?error=new-AcmeAutomated&message=Wrote keyauth challenge, but couldn't download"
                    in res2.location
                ):
                    raise ValueError("Failed to validate domain")
                if "/.well-known/admin/server-certificate/2" not in res2.location:
                    raise ValueError("Expected certificate/2")


class FunctionalTests_AcmeOrderless(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_AcmeOrderless"""

    def _get_item(self):
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
        res_json = json.loads(res.body)
        assert "AcmeOrderless" in res_json
        res = self.testapp.get("/.well-known/admin/acme-orderlesss/1.json", status=200)
        res_json = json.loads(res.body)
        assert "AcmeOrderless" in res_json

    @tests_routes(("admin:acme_orderless:focus",))
    def test_focus_html(self):
        focus_item = self._get_item()
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
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id
        challenge_id = focus_item.acme_challenges[0].id

        res = self.testapp.get(
            "/.well-known/admin/acme-orderless/%.json" % focus_id, status=200
        )
        res_json = json.loads(res.body)
        assert "AcmeOrderless" in res_json

        res = self.testapp.get(
            "/.well-known/admin/acme-orderless/%/acme-challenge/%s.json"
            % (focus_id, challenge_id),
            status=200,
        )
        res_json = json.loads(res.body)
        assert "AcmeOrderless" in res_json
        assert "AcmeChallenge" in res_json

    @tests_routes(
        (
            "admin:acme_orderless:new",
            "admin:acme_orderless:focus",
            "admin:acme_orderless:focus:add",
            "admin:acme_orderless:focus:acme_challenge",
            "admin:acme_orderless:focus:update",
            "admin:acme_orderless:focus:deactivate",
        )
    )
    def test_new_html(self):
        raise ValueError("this urls are not the same anymore")
        res = self.testapp.get("/.well-known/admin/acme-orderless/new", status=200)
        form = res.form
        form["domain_names"] = TEST_FILES["CertificateRequests"]["1"]["domains"]
        res2 = form.submit()
        assert res2.status_code == 303
        re_expected = re.compile(
            r"""^http://localhost/\.well-known/admin/certificate-request/(\d+)/acme-orderless/manage$"""
        )
        matched = re_expected.match(res2.location)
        assert matched
        url_id = matched.groups()[0]

        # make sure we can get this
        res = self.testapp.get(
            "/.well-known/admin/certificate-request/%s/acme-orderless/manage" % url_id,
            status=200,
        )
        domains = [
            i.strip().lower()
            for i in TEST_FILES["CertificateRequests"]["1"]["domains"].split(",")
        ]
        for _domain in domains:
            res = self.testapp.get(
                "/.well-known/admin/certificate-request/%s/acme-orderless/manage/domain/%s"
                % (url_id, _domain),
                status=200,
            )
            form = res.form
            form["challenge_key"] = "foo"
            form["challenge_text"] = "foo"
            res2 = form.submit()
            # we're not sure what the domain id is, so just check the location
            assert "?result=success" in res2.location

        # deactivate!
        res = self.testapp.get(
            "/.well-known/admin/certificate-request/%s/acme-orderless/deactivate"
            % url_id,
            status=303,
        )
        assert "?result=success" in res.location

        # acme-orderless/{@id}/deactivate.json
        res = self.testapp.get(
            "/.well-known/admin/certificate-request/%s/acme-orderless/deactivate.json"
            % url_id,
            status=200,
        )

    @tests_routes(
        (
            "admin:acme_orderless:new|json",
            "admin:acme_orderless:focus|json",
            "admin:acme_orderless:focus:acme_challenge|json",
            "admin:acme_orderless:focus:add|json",
            "admin:acme_orderless:focus:update|json",
            "admin:acme_orderless:focus:deactivate|json",
        )
    )
    def test_new_json(self):
        raise ValueError("todo")


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
        res_json = res.json
        assert "AcmeAccountProviders" in res_json


class FunctionalTests_CACertificate(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_CACertificate"""

    """python -m unittest peter_sslers.tests.FunctionalTests_CACertificate.test_upload"""

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
        res_json = json.loads(res.body)
        assert "CACertificates" in res_json

        # JSON paginated
        res = self.testapp.get("/.well-known/admin/ca-certificates/1.json", status=200)
        res_json = json.loads(res.body)
        assert "CACertificates" in res_json

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
        assert (
            res2.location
            == """http://localhost/.well-known/admin/ca-certificate/3?result=success&is_created=1"""
        )
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
            == """http://localhost/.well-known/admin/ca-certificates?uploaded=1"""
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
        res2_json = json.loads(res2.body)
        assert res2_json["result"] == "success"
        assert res2_json["ca_certificate"]["id"] == 4
        assert res2_json["ca_certificate"]["created"] is True
        res3 = self.testapp.get("/.well-known/admin/ca-certificate/4", status=200)

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
        res2_json = json.loads(res2.body)
        assert res2_json["result"] == "success"
        # this is going to be too messy to check all the vars
        # {u'isrgrootx1_pem': {u'id': 5, u'created': False}, u'le_x2_auth_pem': {u'id': 3, u'created': False}, u'le_x4_cross_signed_pem': {u'id': 6, u'created': False}, u'le_x2_cross_signed_pem': {u'id': 7, u'created': False}, u'le_x3_cross_signed_pem': {u'id': 8, u'created': False}, u'result': u'success', u'le_x1_cross_signed_pem': {u'id': 4, u'created': False}, u'le_x1_auth_pem': {u'id': 1, u'created': False}}


class FunctionalTests_CertificateRequest(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_CertificateRequest"""

    def _get_item(self):
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
        res_json = json.loads(res.body)
        assert "CertificateRequests" in res_json

        # paginated
        res = self.testapp.get(
            "/.well-known/admin/certificate-requests/1.json", status=200
        )
        res_json = json.loads(res.body)
        assert "CertificateRequests" in res_json

    @tests_routes(
        (
            "admin:certificate_request:focus",
            "admin:certificate_request:focus:acme_orders",
            "admin:certificate_request:focus:acme_orders_paginated",
        )
    )
    def test_focus_html(self):
        focus_item = self._get_item()
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
            "/.well-known/admin/certificate-request/%sacme-orders/1" % focus_id,
            status=200,
        )

    @tests_routes(("admin:certificate_request:focus:raw",))
    def test_focus_raw(self):
        focus_item = self._get_item()
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
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/certificate-request/%s.json" % focus_id, status=200
        )
        res_json = json.loads(res.body)
        assert "CertificateRequest" in res_json


class FunctionalTests_Domain(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_Domain"""

    def _get_item(self):
        # grab a certificate
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
        res_json = json.loads(res.body)
        assert "Domains" in res_json

        res = self.testapp.get("/.well-known/admin/domains/challenged.json", status=200)
        res_json = json.loads(res.body)
        assert "Domains" in res_json

        res = self.testapp.get("/.well-known/admin/domains/expiring.json", status=200)
        res_json = json.loads(res.body)
        assert "Domains" in res_json

        # json paginated
        res = self.testapp.get("/.well-known/admin/domains/1.json", status=200)
        res_json = json.loads(res.body)
        assert "Domains" in res_json

        res = self.testapp.get(
            "/.well-known/admin/domains/challenged/1.json", status=200
        )
        res_json = json.loads(res.body)
        assert "Domains" in res_json

        res = self.testapp.get("/.well-known/admin/domains/expiring/1.json", status=200)
        res_json = json.loads(res.body)
        assert "Domains" in res_json

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
            "admin:domain:focus:unique_fqdn_sets",
            "admin:domain:focus:unique_fqdn_sets_paginated",
        )
    )
    def test_focus_html(self):
        focus_item = self._get_item()
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
        res = self.testapp.get(
            "/.well-known/admin/domain/%s.json" % focus_id, status=200
        )
        res_json = json.loads(res.body)
        assert "Domain" in res_json

        res = self.testapp.get(
            "/.well-known/admin/domain/%s.json" % focus_name, status=200
        )
        res_json = json.loads(res.body)
        assert "Domain" in res_json

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/config.json" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/calendar.json" % focus_id, status=200
        )

    @tests_routes(("admin:domain:focus:mark",))
    def test_manipulate_html(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        # make sure to roundtrip!
        # note we expect a 303 on success!
        if focus_item.is_active:
            res = self.testapp.get(
                "/.well-known/admin/domain/%s/mark" % focus_id,
                {"action": "inactive"},
                status=303,
            )
        else:
            res = self.testapp.get(
                "/.well-known/admin/domain/%s/mark" % focus_id,
                {"action": "active"},
                status=303,
            )

    @tests_routes(("admin:domain:focus:mark|json",))
    def test_manipulate_json(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        # make sure to roundtrip!
        # note we expect a 303 on success!
        if focus_item.is_active:
            res = self.testapp.get(
                "/.well-known/admin/domain/%s/mark.json" % focus_id,
                {"action": "active"},
                status=200,
            )
        else:
            res = self.testapp.get(
                "/.well-known/admin/domain/%s/mark.json" % focus_id,
                {"action": "inactive"},
                status=200,
            )

    @unittest.skipUnless(RUN_NGINX_TESTS, "not running against nginx")
    @tests_routes(("admin:domain:focus:nginx_cache_expire",))
    def test_nginx_html(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id
        focus_name = focus_item.domain_name

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/nginx-cache-expire" % focus_id, status=303
        )
        assert (
            "/.well-known/admin/domain/%s?result=success&operation=nginx_cache_expire&event.id="
            % focus_id
            in res.location
        )

    @unittest.skipUnless(RUN_NGINX_TESTS, "not running against nginx")
    @tests_routes(("admin:domain:focus:nginx_cache_expire|json",))
    def test_nginx_json(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id
        focus_name = focus_item.domain_name

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/nginx-cache-expire.json" % focus_id,
            status=200,
        )
        res_json = json.loads(res.body)
        assert res_json["result"] == "success"


class FunctionalTests_Operations(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_Operations"""

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
        assert res.location == "http://localhost/.well-known/admin/operations/log"

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

        res = self.testapp.get("/.well-known/admin/operations/nginx", status=200)
        res = self.testapp.get("/.well-known/admin/operations/nginx/1", status=200)
        res = self.testapp.get("/.well-known/admin/operations/redis", status=200)
        res = self.testapp.get("/.well-known/admin/operations/redis/1", status=200)


class FunctionalTests_PrivateKey(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_PrivateKey
    """

    def _get_item(self):
        # grab a Key
        focus_item = (
            self.ctx.dbSession.query(model_objects.PrivateKey)
            .filter(model_objects.PrivateKey.is_active.op("IS")(True))
            .order_by(model_objects.PrivateKey.id.asc())
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
        res_json = json.loads(res.body)
        assert "PrivateKeys" in res_json

        res = self.testapp.get("/.well-known/admin/private-keys/1.json", status=200)
        res_json = json.loads(res.body)
        assert "PrivateKeys" in res_json

    @tests_routes(
        (
            "admin:private_key:focus",
            "admin:private_key:focus:certificate_requests",
            "admin:private_key:focus:certificate_requests_paginated",
            "admin:private_key:focus:server_certificates",
            "admin:private_key:focus:server_certificates_paginated",
        )
    )
    def test_focus_html(self):
        focus_item = self._get_item()
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

    @tests_routes(
        ("admin:private_key:focus|json", "admin:private_key:focus:parse|json",)
    )
    def test_focus_json(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/private-key/%s.json" % focus_id, status=200
        )
        res_json = json.loads(res.body)
        assert "PrivateKey" in res_json

        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/parse.json" % focus_id, status=200
        )

    @tests_routes(("admin:private_key:focus:raw",))
    def test_focus_raw(self):
        focus_item = self._get_item()
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
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        if not focus_item.is_compromised:
            # make sure to roundtrip!
            # note we expect a 303 on success!
            if focus_item.is_active:
                res = self.testapp.get(
                    "/.well-known/admin/private-key/%s/mark" % focus_id,
                    {"action": "inactive"},
                    status=303,
                )
            else:
                res = self.testapp.get(
                    "/.well-known/admin/private-key/%s/mark" % focus_id,
                    {"action": "active"},
                    status=303,
                )
        else:
            # TODO
            print("MUST TEST compromised")

    @tests_routes(("admin:private_key:focus:mark|json",))
    def test_manipulate_json(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        if not focus_item.is_compromised:
            # make sure to roundtrip!
            # note we expect a 303 on success!
            if focus_item.is_active:
                res = self.testapp.get(
                    "/.well-known/admin/private-key/%s/mark.json" % focus_id,
                    {"action": "active"},
                    status=200,
                )
            else:
                res = self.testapp.get(
                    "/.well-known/admin/private-key/%s/mark.json" % focus_id,
                    {"action": "inactive"},
                    status=200,
                )
        else:
            # TODO
            print("MUST TEST compromised")

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

    @tests_routes(("admin:private_key:upload|json", "admin:private_key:new|json",))
    def test_new_json(self):
        res = self.testapp.get("/.well-known/admin/private-key/upload.json", status=200)
        form = {}
        form["private_key_file_pem"] = Upload(key_filepath)
        res2 = self.testapp.post("/.well-known/admin/private-key/upload.json", form)
        assert res2.status_code == 200

        res = self.testapp.get("/.well-known/admin/private-key/new.json", status=200)
        form = {}  # "bits": "4096"}
        res2 = self.testapp.post("/.well-known/admin/private-key/new.json", form)
        assert res2.status_code == 200
        res2_json = json.loads(res2.body)
        assert "PrivateKey" in res2


class FunctionalTests_QueueCertificate(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_QueueCertificate"""

    def _get_item(self):
        # grab an item
        focus_item = (
            self.ctx.dbSession.query(model_objects.QueueCertificate)
            .order_by(model_objects.QueueCertificate.id.asc())
            .first()
        )
        return focus_item

    @tests_routes(
        (
            "admin:queue_certificates",
            "admin:queue_certificates_paginated",
            "admin:queue_certificates:all",
            "admin:queue_certificates:all_paginated",
            "admin:queue_certificates:active_failures",
            "admin:queue_certificates:active_failures_paginated",
        )
    )
    def test_list_html(self):
        # root
        res = self.testapp.get("/.well-known/admin/queue-certificates", status=200)
        res = self.testapp.get("/.well-known/admin/queue-certificates/all", status=200)
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/active-failures", status=200
        )

        # paginated
        res = self.testapp.get("/.well-known/admin/queue-certificates/1", status=200)
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/all/1", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/active-failures/1", status=200
        )

    @tests_routes(
        (
            "admin:queue_certificates|json",
            "admin:queue_certificates_paginated|json",
            "admin:queue_certificates:all|json",
            "admin:queue_certificates:all_paginated|json",
            "admin:queue_certificates:active_failures|json",
            "admin:queue_certificates:active_failures_paginated|json",
        )
    )
    def test_list_json(self):
        # root|json
        res = self.testapp.get("/.well-known/admin/queue-certificates.json", status=200)
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/all.json", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/active-failures.json", status=200
        )
        # paginated|json
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/1.json", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/all/1.json", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/active-failures/1.json", status=200
        )

    @tests_routes(("admin:queue_certificate:new",))
    def test_new_html(self):
        res = self.testapp.get("/.well-known/admin/queue-certificate/new", status=200)
        raise ValueError("finish tests")

    @tests_routes(("admin:queue_certificate:new|json",))
    def test_new_json(self):
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/new.json", status=200
        )
        raise ValueError("finish tests")

    @tests_routes(("admin:queue_certificate:focus",))
    def test_focus_html(self):
        """this doesn't work on solo tests"""
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/%s" % focus_id, status=200
        )

    @tests_routes(("admin:queue_certificate:focus|json",))
    def test_focus_json(self):
        """this doesn't work on solo tests"""
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/%s.json" % focus_id, status=200
        )

    @tests_routes(("admin:queue_certificate:focus:mark",))
    def test_manipulate_html(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/%s/mark" % focus_id,
            {"action": "cancel"},
            status=303,
        )

    @tests_routes(("admin:queue_certificate:focus:mark|json",))
    def test_manipulate_json(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/%s/mark.json" % focus_id,
            {"action": "cancel"},
            status=200,
        )

    @tests_routes(
        (
            "admin:api:queue_certificates:process",
            "admin:api:queue_certificates:process|json",
        )
    )
    def test_api_process(self):
        raise ValueError("todo")
        if DISABLE_UNWRITTEN_TESTS:
            return True
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/process", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/process.json", status=200
        )

    @tests_routes(
        (
            "admin:api:queue_certificates:update",
            "admin:api:queue_certificates:update|json",
        )
    )
    def test_api_update(self):
        raise ValueError("todo")
        if DISABLE_UNWRITTEN_TESTS:
            return True
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/process", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/process.json", status=200
        )


class FunctionalTests_QueueDomains(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_QueueDomains"""

    def _get_item(self):
        # grab an item
        focus_item = (
            self.ctx.dbSession.query(model_objects.QueueDomain)
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
            """http://localhost/.well-known/admin/queue-domains?result=success"""
            in res2.location
        )

    @tests_routes(("admin:queue_domains:add|json",))
    def test_add_json(self):
        res = self.testapp.get("/.well-known/admin/queue-domains/add.json", status=200)
        _data = {"domain_names": TEST_FILES["Domains"]["Queue"]["1"]["add.json"]}
        res2 = self.testapp.post("/.well-known/admin/queue-domains/add.json", _data)
        assert res2.status_code == 200
        res2_json = json.loads(res2.body)
        assert res2_json["result"] == "success"

    @tests_routes(("admin:queue_domains:process",))
    def test_process(self):
        raise ValueError("todo")
        res = self.testapp.get("/.well-known/admin/queue-domains/process", status=200)

    @tests_routes(("admin:queue_domains:process|json",))
    def test_process_json(self):
        raise ValueError("todo")
        res = self.testapp.get(
            "/.well-known/admin/queue-domains/process.json", status=200
        )

    @tests_routes(("admin:queue_domain:focus",))
    def test_focus_html(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/queue-domain/%s" % focus_id, status=200
        )

    @tests_routes(("admin:queue_domain:focus|json",))
    def test_focus_json(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/queue-domain/%s.json" % focus_id, status=200
        )

    @tests_routes(("admin:queue_domain:focus:mark",))
    def test_manipulate_html(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/queue-domain/%s/mark" % focus_id,
            {"action": "cancel"},
            status=303,
        )

    @tests_routes(("admin:queue_domain:focus:mark|json",))
    def test_manipulate_json(self):
        res = self.testapp.get(
            "/.well-known/admin/queue-domain/%s/mark.json" % focus_id,
            {"action": "cancel"},
            status=200,
        )


class FunctionalTests_ServerCertificate(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_ServerCertificate"""

    def _get_item(self):
        # grab a certificate
        focus_item = (
            self.ctx.dbSession.query(model_objects.ServerCertificate)
            .filter(model_objects.ServerCertificate.is_active.op("IS")(True))
            .order_by(model_objects.ServerCertificate.id.asc())
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
        res_json = json.loads(res.body)
        assert "ServerCertificates" in res_json

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
        res_json = json.loads(res.body)
        assert "ServerCertificates" in res_json

        # paginated
        res = self.testapp.get(
            "/.well-known/admin/server-certificates/1.json", status=200
        )
        res_json = json.loads(res.body)
        assert "ServerCertificates" in res_json

        for _type in (
            "active",
            "expiring",
            "inactive",
        ):
            res = self.testapp.get(
                "/.well-known/admin/server-certificates/%s.json" % _type, status=200
            )
            res_json = json.loads(res.body)
            assert "ServerCertificates" in res_json

            res = self.testapp.get(
                "/.well-known/admin/server-certificates/%s/1.json" % _type, status=200
            )
            res_json = json.loads(res.body)
            assert "ServerCertificates" in res_json

    @tests_routes(("admin:server_certificate:focus",))
    def test_focus_html(self):
        focus_item = self._get_item()
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

    @tests_routes(
        (
            "admin:server_certificate:focus:chain:raw",
            "admin:server_certificate:focus:fullchain:raw",
            "admin:server_certificate:focus:privatekey:raw",
            "admin:server_certificate:focus:cert:raw",
        )
    )
    def test_focus_raw(self):
        focus_item = self._get_item()
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
        focus_item = self._get_item()
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
        res_json = json.loads(res.body)
        assert "ServerCertificate" in res_json

        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/config.json" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/parse.json" % focus_id, status=200
        )

    @tests_routes(("admin:server_certificate:focus:mark",))
    def test_manipulate_html(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        if not focus_item.is_revoked:
            # make sure to roundtrip!
            # note we expect a 303 on success!
            if focus_item.is_active:
                res = self.testapp.get(
                    "/.well-known/admin/server-certificate/%s/mark" % focus_id,
                    {"action": "inactive"},
                    status=303,
                )
            else:
                res = self.testapp.get(
                    "/.well-known/admin/server-certificate/%s/mark" % focus_id,
                    {"action": "active"},
                    status=303,
                )
        else:
            # TODO
            print("MUST TEST revoked")

    @tests_routes(("admin:server_certificate:focus:mark|json",))
    def test_manipulate_json(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        if not focus_item.is_revoked:
            # make sure to roundtrip!
            # note we expect a 303 on success!
            if focus_item.is_active:
                res = self.testapp.get(
                    "/.well-known/admin/server-certificate/%s/mark.json" % focus_id,
                    {"action": "active"},
                    status=200,
                )
            else:
                res = self.testapp.get(
                    "/.well-known/admin/server-certificate/%s/mark.json" % focus_id,
                    {"action": "inactive"},
                    status=200,
                )
        else:
            # TODO
            print("MUST TEST revoked")

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
            """http://localhost/.well-known/admin/server-certificate/"""
        )

    @tests_routes(("admin:server_certificate:upload|json",))
    def test_upload_html(self):
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
        res2_json = json.loads(res2.body)
        assert res2_json["result"] == "success"
        assert res2_json["certificate"]["created"] is True
        certificate_id = res2_json["certificate"]["id"]
        res3 = self.testapp.get(
            "/.well-known/admin/server-certificate/%s" % certificate_id, status=200
        )

    @unittest.skipUnless(RUN_NGINX_TESTS, "not running against nginx")
    @tests_routes(("admin:server_certificate:focus:nginx_cache_expire",))
    def test_nginx_html(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/nginx-cache-expire" % focus_id,
            status=303,
        )
        assert (
            "/.well-known/admin/server-certificate/%s?result=success&operation=nginx_cache_expire&event.id="
            % focus_id
            in res.location
        )

    @unittest.skipUnless(RUN_NGINX_TESTS, "not running against nginx")
    @tests_routes(("admin:server_certificate:focus:nginx_cache_expire|json",))
    def test_nginx_json(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/nginx-cache-expire.json"
            % focus_id,
            status=200,
        )
        res_json = json.loads(res.body)
        assert res_json["result"] == "success"


class FunctionalTests_UniqueFQDNSet(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_UniqueFQDNSet"""

    def _get_item(self):
        # grab a Key
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
        res_json = json.loads(res.body)
        assert "UniqueFQDNSets" in res_json

        # paginated
        res = self.testapp.get("/.well-known/admin/unique-fqdn-sets/1.json", status=200)
        res_json = json.loads(res.body)
        assert "UniqueFQDNSets" in res_json

    @tests_routes(
        (
            "admin:unique_fqdn_set:focus",
            "admin:unique_fqdn_set:focus:acme_orders",
            "admin:unique_fqdn_set:focus:acme_orders_paginated",
            "admin:unique_fqdn_set:focus:certificate_requests",
            "admin:unique_fqdn_set:focus:certificate_requests_paginated",
            "admin:unique_fqdn_set:focus:server_certificates",
            "admin:unique_fqdn_set:focus:server_certificates_paginated",
        )
    )
    def test_focus_html(self):
        focus_item = self._get_item()
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

    @tests_routes(
        (
            "admin:unique_fqdn_set:focus|json",
            "admin:unique_fqdn_set:focus:calendar|json",
        )
    )
    def test_focus_json(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s.json" % focus_id, status=200
        )
        res_json = json.loads(res.body)
        assert "UniqueFQDNSet" in res_json

        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s/calendar.json" % focus_id, status=200
        )


class ZZZ_FunctionalTests_API(AppTest):
    """python -m unittest peter_sslers.tests.ZZZ_FunctionalTests_API"""

    """this is prefixed `ZZZ_` so it runs last.
    When run, some API endpoints will deactivate the test certificates - which will
    cause other tests to fail.
    """

    @tests_routes(("admin:api",))
    def test_passive(self):
        res = self.testapp.get("/.well-known/admin/api", status=200)

    @tests_routes(
        (
            "admin:api:domain:enable",
            "admin:api:domain:disable",
            "admin:api:domain:certificate-if-needed",
        )
    )
    def test_domains(self):
        # enable
        _data = {"domain_names": "example.com,foo.example.com, bar.example.com"}
        res = self.testapp.post("/.well-known/admin/api/domain/enable", _data)
        assert res.status_code == 200
        res_json = json.loads(res.body)
        assert res_json["result"] == "success"

        # disable
        _data = {"domain_names": "example.com,biz.example.com"}
        res = self.testapp.post("/.well-known/admin/api/domain/disable", _data)
        assert res.status_code == 200
        res_json = json.loads(res.body)
        assert res_json["result"] == "success"

        raise ValueError("TODO - admin:api:domain:certificate-if-needed")

    @unittest.skipUnless(RUN_NGINX_TESTS, "not running against nginx")
    @tests_routes(
        (
            "admin:api:nginx:cache_flush",
            "admin:api:nginx:cache_flush|json",
            "admin:api:nginx:status|json",
        )
    )
    def test_nginx(self):
        res = self.testapp.get("/.well-known/admin/api/nginx/cache-flush", status=303)
        assert (
            "/.well-known/admin/operations/nginx?result=success&operation=nginx_cache_flush&event.id="
            in res.location
        )

        res = self.testapp.get(
            "/.well-known/admin/api/nginx/cache-flush.json", status=200
        )
        res_json = json.loads(res.body)
        assert res_json["result"] == "success"

        res = self.testapp.get("/.well-known/admin/api/nginx/status.json", status=200)
        res_json = json.loads(res.body)
        assert res_json["result"] == "success"

    @unittest.skipUnless(RUN_REDIS_TESTS, "not running against redis")
    @tests_routes(("admin:api:redis:prime", "admin:api:redis:prime|json",))
    def test_redis(self):
        res = self.testapp.get("/.well-known/admin/api/redis/prime", status=303)
        assert (
            "/.well-known/admin/operations/redis?result=success&operation=redis_prime&event.id="
            in res.location
        )

        res = self.testapp.get("/.well-known/admin/api/redis/prime.json", status=200)
        res_json = json.loads(res.body)
        assert res_json["result"] == "success"

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
        res_json = json.loads(res.body)
        assert res_json["result"] == "success"

        # update-recents
        res = self.testapp.get("/.well-known/admin/api/update-recents", status=303)
        assert (
            "/.well-known/admin/operations/log?result=success&event.id=" in res.location
        )
        res = self.testapp.get("/.well-known/admin/api/update-recents.json", status=200)
        res_json = json.loads(res.body)
        assert res_json["result"] == "success"

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "not running against LetsEncrypt API")
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
        res_json = json.loads(res.body)
        assert res_json["result"] == "success"


class FunctionalTests_AuditRoutes(AppTest):
    """
    python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_AuditRoutes
    """

    def test_audit(self):
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
