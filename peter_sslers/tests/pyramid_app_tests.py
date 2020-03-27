from __future__ import print_function

# stdlib
import datetime
import json
import os
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
from ._utils import RUN_LETSENCRYPT_API_TESTS
from ._utils import RUN_NGINX_TESTS
from ._utils import RUN_REDIS_TESTS
from ._utils import SSL_TEST_PORT


# ==============================================================================


class FunctionalTests_Main(AppTest):
    """
    python -m unittest peter_sslers.tests.FunctionalTests_Main
    """

    def test_root(self):
        res = self.testapp.get("/.well-known/admin", status=200)

    def test_whoami(self):
        res = self.testapp.get("/.well-known/admin/whoami", status=200)

    def test_help(self):
        res = self.testapp.get("/.well-known/admin/help", status=200)

    def test_settings(self):
        res = self.testapp.get("/.well-known/admin/settings", status=200)

    def test_api_docs(self):
        res = self.testapp.get("/.well-known/admin/api", status=200)

    def test_search(self):
        res = self.testapp.get("/.well-known/admin/search", status=200)


class FunctionalTests_Passes(AppTest):
    """
    python -m unittest peter_sslers.tests.FunctionalTests_Passes
    this is only used to test setup
    """

    def tests_passes(self):
        return True


class FunctionalTests_AcmeAccountKey(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_AcmeAccountKey"""

    """python -m unittest peter_sslers.tests.FunctionalTests_AcmeAccountKey.test_new"""

    def _get_item(self):
        # grab a Key
        focus_item = (
            self.ctx.dbSession.query(model_objects.AcmeAccountKey)
            .filter(model_objects.AcmeAccountKey.is_active.op("IS")(True))
            .order_by(model_objects.AcmeAccountKey.id.asc())
            .first()
        )
        return focus_item

    def test_list(self):
        # root
        res = self.testapp.get("/.well-known/admin/acme-account-keys", status=200)
        # paginated
        res = self.testapp.get("/.well-known/admin/acme-account-keys/1", status=200)

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

    def test_focus(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s" % focus_id, status=200
        )
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
            "/.well-known/admin/acme-account-key/%s/key.key" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s/key.pem" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s/key.pem.txt" % focus_id, status=200
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
            "/.well-known/admin/acme-account-key/%s/server-certificates" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/%s/server-certificates/1" % focus_id,
            status=200,
        )

    def test_manipulate(self):
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
                res = self.testapp.get(
                    "/.well-known/admin/acme-account-key/%s/mark.json" % focus_id,
                    {"action": "active"},
                    status=200,
                )
            else:
                res = self.testapp.get(
                    "/.well-known/admin/acme-account-key/%s/mark" % focus_id,
                    {"action": "active"},
                    status=303,
                )
                res = self.testapp.get(
                    "/.well-known/admin/acme-account-key/%s/mark.json" % focus_id,
                    {"action": "inactive"},
                    status=200,
                )
        else:
            # TODO
            print("MUST TEST non-default")

    def test_new(self):
        # this should be creating a new key
        _key_filename = TEST_FILES["AcmeAccountKey"]["2"]
        key_filepath = self._filepath_testfile(_key_filename)

        res = self.testapp.get("/.well-known/admin/acme-account-key/upload", status=200)
        form = res.form
        form["account_key_file_pem"] = Upload(key_filepath)
        form["acme_account_provider_id"].force_value(
            str(DEFAULT_acme_account_provider_id)
        )  # why aren't any valid options showing?'
        res2 = form.submit()
        assert res2.status_code == 303
        assert res2.location in (
            """http://localhost/.well-known/admin/acme-account-key/2?result=success&is_created=1""",
            """http://localhost:80/.well-known/admin/acme-account-key/2?result=success&is_created=1""",
        )
        res3 = self.testapp.get(res2.location, status=200)

        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/upload.json", status=200
        )
        res_json = json.loads(res.body)
        assert "instructions" in res_json

        form = {}
        form["account_key_file_pem"] = Upload(key_filepath)
        form["acme_account_provider_id"] = str(DEFAULT_acme_account_provider_id)
        res2 = self.testapp.post(
            "/.well-known/admin/acme-account-key/upload.json", form
        )
        assert res2.status_code == 200
        res2_json = json.loads(res2.body)
        assert "result" in res2_json
        assert res2_json["result"] == "success"

    @unittest.skipUnless(
        RUN_LETSENCRYPT_API_TESTS, "not running against letsencrypt api"
    )
    def tests_letsencrypt_api(self):
        # this hits LE
        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/1/authenticate", status=303
        )
        assert (
            res.location
            == "http://localhost/.well-known/admin/acme-account-key/1?operation=authenticate&result=post+required"
        )
        res = self.testapp.post(
            "/.well-known/admin/acme-account-key/1/authenticate", {}
        )
        assert res.location in (
            """http://localhost/.well-known/admin/acme-account-key/1?result=success&is_authenticated=existing-account""",
            """http://localhost/.well-known/admin/acme-account-key/1?result=success&is_authenticated=new-account""",
        )

        res = self.testapp.get(
            "/.well-known/admin/acme-account-key/1/authenticate.json", status=200
        )
        res = self.testapp.post(
            "/.well-known/admin/acme-account-key/1/authenticate.json", {}
        )
        assert res.status == 200


class FunctionalTests_AcmeAuthorizations(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_AcmeAuthorizations"""

    def _get_item(self):
        # grab an order
        focus_item = (
            self.ctx.dbSession.query(model_objects.AcmeAuthorization)
            .order_by(model_objects.AcmeAuthorization.id.asc())
            .first()
        )
        return focus_item

    def test_list(self):
        # root
        res = self.testapp.get("/.well-known/admin/acme-authorizations", status=200)
        # paginated
        res = self.testapp.get("/.well-known/admin/acme-authorizations/1", status=200)

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

    def test_focus(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-authorization/%s.json" % focus_id, status=200
        )
        res_json = json.loads(res.body)
        assert "AcmeAuthorization" in res_json

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

    @unittest.skip("tests not written yet")
    def test_manipulate(self):
        """
        "/acme-authorization/{@id}/acme-server/sync",
        "/acme-authorization/{@id}/acme-server/sync.json",
        "/acme-authorization/{@id}/acme-server/deactivate",
        "/acme-authorization/{@id}/acme-server/deactivate.json",
        """
        pass


class FunctionalTests_AcmeChallenges(AppTest):
    def _get_item(self):
        # grab an order
        focus_item = (
            self.ctx.dbSession.query(model_objects.AcmeChallenge)
            .order_by(model_objects.AcmeChallenge.id.asc())
            .first()
        )
        return focus_item

    def test_list(self):
        # root
        res = self.testapp.get("/.well-known/admin/acme-challenges", status=200)
        # paginated
        res = self.testapp.get("/.well-known/admin/acme-challenges/1", status=200)

        # json root
        res = self.testapp.get("/.well-known/admin/acme-challenges.json", status=200)
        res_json = json.loads(res.body)
        assert "AcmeChallenges" in res_json

        # json paginated
        res = self.testapp.get("/.well-known/admin/acme-challenges/1.json", status=200)
        res_json = json.loads(res.body)
        assert "AcmeChallenges" in res_json

    def test_focus(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-challenge/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge/%s.json" % focus_id, status=200
        )
        res_json = json.loads(res.body)
        assert "AcmeChallenge" in res_json

    @unittest.skip("tests not written yet")
    def test_manipulate(self):
        pass
        """
        "admin:acme_challenge:focus:acme_server:sync",
        "admin:acme_challenge:focus:acme_server:sync|json",
        """


class FunctionalTests_AcmeChallengePolls(AppTest):
    def test_list(self):
        # root
        res = self.testapp.get("/.well-known/admin/acme-challenge-polls", status=200)
        # paginated
        res = self.testapp.get("/.well-known/admin/acme-challenge-polls/1", status=200)

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
    def test_list(self):
        # root
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge-unknown-polls", status=200
        )
        # paginated
        res = self.testapp.get(
            "/.well-known/admin/acme-challenge-unknown-polls/1", status=200
        )

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

    def test_list(self):
        # root
        res = self.testapp.get("/.well-known/admin/acme-event-logs", status=200)
        # paginated
        res = self.testapp.get("/.well-known/admin/acme-event-logs/1", status=200)

        # json root
        res = self.testapp.get("/.well-known/admin/acme-event-logs.json", status=200)
        res_json = json.loads(res.body)
        assert "AcmeEventLogs" in res_json
        # json paginated
        res = self.testapp.get("/.well-known/admin/acme-event-logs/1.json", status=200)
        res_json = json.loads(res.body)
        assert "AcmeEventLogs" in res_json

    @unittest.skipUnless(
        RUN_LETSENCRYPT_API_TESTS, "not running against letsencrypt api"
    )
    def test_focus(self):
        """logs are only populated when running against the letsencrypt api
        """
        # focus
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id
        res = self.testapp.get(
            "/.well-known/admin/acme-event-log/%s" % focus_id, status=200
        )

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

    def test_list(self):
        # root
        res = self.testapp.get("/.well-known/admin/acme-orders", status=200)
        res = self.testapp.get("/.well-known/admin/acme-orders/1", status=200)

        # json root
        res = self.testapp.get("/.well-known/admin/acme-orders.json", status=200)
        res_json = json.loads(res.body)
        assert "AcmeOrders" in res_json

        res = self.testapp.get("/.well-known/admin/acme-orders/1.json", status=200)
        res_json = json.loads(res.body)
        assert "AcmeOrders" in res_json

    def test_focus(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s.json" % focus_id, status=200
        )
        res_json = json.loads(res.body)
        assert "AcmeOrder" in res_json

        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-event-logs" % focus_id, status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-order/%s/acme-event-logs/1" % focus_id, status=200,
        )

    @unittest.skip("tests not written yet")
    def test_manipulate(self):
        """
        config.add_route_7("admin:acme_order:focus:process", "/acme-order/{@id}/process")
        config.add_route_7(
            "admin:acme_order:focus:acme_server:sync", "/acme-order/{@id}/acme-server/sync"
        )
        config.add_route_7(
            "admin:acme_order:focus:acme_server:sync|json",
            "/acme-order/{@id}/acme-server/sync.json",
        )
        config.add_route_7(
            "admin:acme_order:focus:acme_server:deactivate_authorizations",
            "/acme-order/{@id}/acme-server/deactivate-authorizations",
        )
        config.add_route_7(
            "admin:acme_order:focus:acme_server:deactivate_authorizations|json",
            "/acme-order/{@id}/acme-server/deactivate-authorizations.json",
        )

        config.add_route_7("admin:acme_order:focus:retry", "/acme-order/{@id}/retry")
        config.add_route_7("admin:acme_order:focus:mark", "/acme-order/{@id}/mark")
        config.add_route_7(
            "admin:acme_order:focus:mark|json", "/acme-order/{@id}/mark.json"
        )
        config.add_route_7("admin:acme_order:new:automated", "/acme-order/new/automated")
        """
        pass


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

    def test_list(self):
        # root
        res = self.testapp.get("/.well-known/admin/acme-orderlesss", status=200)
        res = self.testapp.get("/.well-known/admin/acme-orderlesss/1", status=200)

        # json root
        res = self.testapp.get("/.well-known/admin/acme-orderlesss.json", status=200)
        res_json = json.loads(res.body)
        assert "AcmeOrderless" in res_json
        res = self.testapp.get("/.well-known/admin/acme-orderlesss/1.json", status=200)
        res_json = json.loads(res.body)
        assert "AcmeOrderless" in res_json

    def test_focus(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        challenge_id = focus_item.acme_challenges[0].id

        res = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-orderless/%.json" % focus_id, status=200
        )
        res_json = json.loads(res.body)
        assert "AcmeOrderless" in res_json

        res = self.testapp.get(
            "/.well-known/admin/acme-orderless/%s/acme-challenge/%s"
            % (focus_id, challenge_id),
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/acme-orderless/%/acme-challenge/%s.json"
            % (focus_id, challenge_id),
            status=200,
        )
        res_json = json.loads(res.body)
        assert "AcmeOrderless" in res_json
        assert "AcmeChallenge" in res_json

    @unittest.skip("tests not written yet")
    def test_manipulate(self):
        pass
        """
        config.add_route_7("admin:acme_orderless:new", "/acme-orderless/new")
        config.add_route_7("admin:acme_orderless:new|json", "/acme-orderless/new.json")

        config.add_route_7(
            "admin:acme_orderless:focus:add", "/acme-orderless/{@id}/add",
        )
        config.add_route_7(
            "admin:acme_orderless:focus:add|json", "/acme-orderless/{@id}/add.json",
        )
        config.add_route_7(
            "admin:acme_orderless:focus:update", "/acme-orderless/{@id}/update",
        )
        config.add_route_7(
            "admin:acme_orderless:focus:update|json", "/acme-orderless/{@id}/update.json"
        )
        config.add_route_7(
            "admin:acme_orderless:focus:deactivate", "/acme-orderless/{@id}/deactivate",
        )
        config.add_route_7(
            "admin:acme_orderless:focus:deactivate|json",
            "/acme-orderless/{@id}/deactivate.json",
        )
        """

    def tests_acme_orderless(self):
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


class FunctionalTests_AcmeProviders(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_AcmeProviders"""

    def test_list(self):
        # root
        res = self.testapp.get("/.well-known/admin/acme-account-providers", status=200)

        # json root
        res = self.testapp.get(
            "/.well-known/admin/acme-account-providers.json", status=200
        )
        res_json = json.loads(res.body)
        assert "AcmeProviders" in res_json


class FunctionalTests_CACertificate(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_CACertificate"""

    """python -m unittest peter_sslers.tests.FunctionalTests_CACertificate.test_upload"""

    def test_list(self):
        # root
        res = self.testapp.get("/.well-known/admin/ca-certificates", status=200)
        # paginated
        res = self.testapp.get("/.well-known/admin/ca-certificates/1", status=200)

        # JSON root
        res = self.testapp.get("/.well-known/admin/ca-certificates.json", status=200)
        res_json = json.loads(res.body)
        assert "CACertificates" in res_json

        # JSON paginated
        res = self.testapp.get("/.well-known/admin/ca-certificates/1.json", status=200)
        res_json = json.loads(res.body)
        assert "CACertificates" in res_json

    def test_focus(self):
        res = self.testapp.get("/.well-known/admin/ca-certificate/1", status=200)
        res = self.testapp.get("/.well-known/admin/ca-certificate/1.json", status=200)
        res = self.testapp.get(
            "/.well-known/admin/ca-certificate/1/parse.json", status=200
        )

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

    def test_upload(self):
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

        """This should enter in item #4"""
        _ca_cert_id = TEST_FILES["CACertificates"]["order"][2]
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


class FunctionalTests_Certificate(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_Certificate"""

    def _get_item(self):
        # grab a certificate
        focus_item = (
            self.ctx.dbSession.query(model_objects.ServerCertificate)
            .filter(model_objects.ServerCertificate.is_active.op("IS")(True))
            .order_by(model_objects.ServerCertificate.id.asc())
            .first()
        )
        return focus_item

    def test_list(self):
        # root
        res = self.testapp.get("/.well-known/admin/server-certificates", status=200)
        res = self.testapp.get(
            "/.well-known/admin/server-certificates.json", status=200
        )
        res_json = json.loads(res.body)
        assert "ServerCertificates" in res_json

        # paginated
        res = self.testapp.get("/.well-known/admin/server-certificates/1", status=200)
        res = self.testapp.get(
            "/.well-known/admin/server-certificates/1.json", status=200
        )
        res_json = json.loads(res.body)
        assert "ServerCertificates" in res_json

        for _type in ("active", "inactive", "expiring"):
            res = self.testapp.get(
                "/.well-known/admin/server-certificates/%s" % _type, status=200
            )
            res = self.testapp.get(
                "/.well-known/admin/server-certificates/%s/1" % _type, status=200
            )

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

    def test_focus(self):
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

        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/renew/queue" % focus_id,
            status=303,
        )
        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/renew/queue.json" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/renew/quick" % focus_id,
            status=303,
        )
        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/renew/quick.json" % focus_id,
            status=200,
        )

        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/renew/custom" % focus_id,
            status=200,
        )
        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/renew/custom.json" % focus_id,
            status=200,
        )

    def test_manipulate(self):
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
                res = self.testapp.get(
                    "/.well-known/admin/server-certificate/%s/mark.json" % focus_id,
                    {"action": "active"},
                    status=200,
                )
            else:
                res = self.testapp.get(
                    "/.well-known/admin/server-certificate/%s/mark" % focus_id,
                    {"action": "active"},
                    status=303,
                )
                res = self.testapp.get(
                    "/.well-known/admin/server-certificate/%s/mark.json" % focus_id,
                    {"action": "inactive"},
                    status=200,
                )
        else:
            # TODO
            print("MUST TEST revoked")

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

    @unittest.skipUnless(
        RUN_LETSENCRYPT_API_TESTS, "not running against letsencrypt api"
    )
    def tests_letsencrypt_api(self):
        if DISABLE_UNWRITTEN_TESTS:
            return True
        raise NotImplementedError()
        # config.add_route_7('admin:server_certificate:focus:renew:quick', '/server-certificate/{@id}/renew/quick')
        # config.add_route_7('admin:server_certificate:focus:renew:quick.json', '/server-certificate/{@id}/renew/quick.json')
        # config.add_route_7('admin:server_certificate:focus:renew:custom', '/server-certificate/{@id}/renew/custom')
        # config.add_route_7('admin:server_certificate:focus:renew:custom.json', '/server-certificate/{@id}/renew/custom.json')

    @unittest.skipUnless(RUN_NGINX_TESTS, "not running against nginx")
    def tests_nginx(self):
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

        res = self.testapp.get(
            "/.well-known/admin/server-certificate/%s/nginx-cache-expire.json"
            % focus_id,
            status=200,
        )
        res_json = json.loads(res.body)
        assert res_json["result"] == "success"


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

    def test_list(self):
        # root
        res = self.testapp.get("/.well-known/admin/certificate-requests", status=200)

        # paginated
        res = self.testapp.get("/.well-known/admin/certificate-requests/1", status=200)

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

    def test_focus(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/certificate-request/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/certificate-request/%s.json" % focus_id, status=200
        )
        res_json = json.loads(res.body)
        assert "CertificateRequest" in res_json

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

    @unittest.skipUnless(
        RUN_LETSENCRYPT_API_TESTS, "not running against letsencrypt api"
    )
    def tests_letsencrypt_api(self):
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
        form["domain_names"] = TEST_FILES["CertificateRequests"]["acme_test"]["domains"]
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

    def test_list(self):
        # root
        res = self.testapp.get("/.well-known/admin/domains", status=200)
        res = self.testapp.get("/.well-known/admin/domains/expiring", status=200)

        # paginated
        res = self.testapp.get("/.well-known/admin/domains/1", status=200)
        res = self.testapp.get("/.well-known/admin/domains/expiring/1", status=200)

        # json root
        res = self.testapp.get("/.well-known/admin/domains.json", status=200)
        res_json = json.loads(res.body)
        assert "Domains" in res_json

        res = self.testapp.get("/.well-known/admin/domains/expiring.json", status=200)
        res_json = json.loads(res.body)
        assert "Domains" in res_json

        # json paginated
        res = self.testapp.get("/.well-known/admin/domains/1.json", status=200)
        res_json = json.loads(res.body)
        assert "Domains" in res_json

        res = self.testapp.get("/.well-known/admin/domains/expiring/1.json", status=200)
        res_json = json.loads(res.body)
        assert "Domains" in res_json

    def test_focus(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id
        focus_name = focus_item.domain_name

        res = self.testapp.get("/.well-known/admin/domain/%s" % focus_id, status=200)
        res = self.testapp.get("/.well-known/admin/domain/%s" % focus_name, status=200)

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
            "/.well-known/admin/domain/%s/server-certificates" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/server-certificates/1" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/certificate-requests" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/certificate-requests/1" % focus_id, status=200
        )

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/unique-fqdn-sets" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/domain/%s/unique-fqdn-sets/1" % focus_id, status=200
        )

    def test_manipulate(self):
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
            res = self.testapp.get(
                "/.well-known/admin/domain/%s/mark.json" % focus_id,
                {"action": "active"},
                status=200,
            )
        else:
            res = self.testapp.get(
                "/.well-known/admin/domain/%s/mark" % focus_id,
                {"action": "active"},
                status=303,
            )
            res = self.testapp.get(
                "/.well-known/admin/domain/%s/mark.json" % focus_id,
                {"action": "inactive"},
                status=200,
            )

    @unittest.skipUnless(RUN_NGINX_TESTS, "not running against nginx")
    def tests_nginx(self):
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

        res = self.testapp.get(
            "/.well-known/admin/domain/%s/nginx-cache-expire.json" % focus_id,
            status=200,
        )
        res_json = json.loads(res.body)
        assert res_json["result"] == "success"

    def test_search(self):
        res = self.testapp.get("/.well-known/admin/domains/search", status=200)
        res2 = self.testapp.post(
            "/.well-known/admin/domains/search", {"domain": "example.com"}
        )

        res = self.testapp.get("/.well-known/admin/domains/search.json", status=200)
        res2 = self.testapp.post(
            "/.well-known/admin/domains/search.json", {"domain": "example.com"}
        )


class FunctionalTests_PrivateKeys(AppTest):
    """python -m unittest peter_sslers.tests.pyramid_app_tests.FunctionalTests_PrivateKeys"""

    def _get_item(self):
        # grab a Key
        focus_item = (
            self.ctx.dbSession.query(model_objects.PrivateKey)
            .filter(model_objects.PrivateKey.is_active.op("IS")(True))
            .order_by(model_objects.PrivateKey.id.asc())
            .first()
        )
        return focus_item

    def test_list(self):
        # root
        res = self.testapp.get("/.well-known/admin/private-keys", status=200)

        # paginated
        res = self.testapp.get("/.well-known/admin/private-keys/1", status=200)

        # json
        res = self.testapp.get("/.well-known/admin/private-keys.json", status=200)
        res_json = json.loads(res.body)
        assert "PrivateKeys" in res_json

        res = self.testapp.get("/.well-known/admin/private-keys/1.json", status=200)
        res_json = json.loads(res.body)
        assert "PrivateKeys" in res_json

    def test_focus(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/private-key/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/private-key/%s.json" % focus_id, status=200
        )
        res_json = json.loads(res.body)
        assert "PrivateKey" in res_json

        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/parse.json" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/key.key" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/key.pem" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/private-key/%s/key.pem.txt" % focus_id, status=200
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

    def test_manipulate(self):
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
                res = self.testapp.get(
                    "/.well-known/admin/private-key/%s/mark.json" % focus_id,
                    {"action": "active"},
                    status=200,
                )
            else:
                res = self.testapp.get(
                    "/.well-known/admin/private-key/%s/mark" % focus_id,
                    {"action": "active"},
                    status=303,
                )
                res = self.testapp.get(
                    "/.well-known/admin/private-key/%s/mark.json" % focus_id,
                    {"action": "inactive"},
                    status=200,
                )
        else:
            # TODO
            print("MUST TEST compromised")

    def test_new(self):
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

        res = self.testapp.get("/.well-known/admin/private-key/upload.json", status=200)
        form = {}
        form["private_key_file_pem"] = Upload(key_filepath)
        res2 = self.testapp.post("/.well-known/admin/private-key/upload.json", form)
        assert res2.status_code == 200

        res = self.testapp.get("/.well-known/admin/private-key/new", status=200)
        form = {"bits": "4096"}
        res2 = self.testapp.post("/.well-known/admin/private-key/new", form)
        assert res2.status_code == 303
        assert """/.well-known/admin/private-key/""" in res2.location

        res = self.testapp.get("/.well-known/admin/private-key/new.json", status=200)
        form = {"bits": "4096"}
        res2 = self.testapp.post("/.well-known/admin/private-key/new.json", form)
        assert res2.status_code == 200
        res2_json = json.loads(res2.body)
        assert "PrivateKey" in res2


class FunctionalTests_UniqueFQDNSets(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_UniqueFQDNSets"""

    def _get_item(self):
        # grab a Key
        focus_item = (
            self.ctx.dbSession.query(model_objects.UniqueFQDNSet)
            .order_by(model_objects.UniqueFQDNSet.id.asc())
            .first()
        )
        return focus_item

    def test_list(self):
        # root
        res = self.testapp.get("/.well-known/admin/unique-fqdn-sets", status=200)
        res = self.testapp.get("/.well-known/admin/unique-fqdn-sets.json", status=200)
        res_json = json.loads(res.body)
        assert "UniqueFQDNSets" in res_json

        # paginated
        res = self.testapp.get("/.well-known/admin/unique-fqdn-sets/1", status=200)
        res = self.testapp.get("/.well-known/admin/unique-fqdn-sets/1.json", status=200)
        res_json = json.loads(res.body)
        assert "UniqueFQDNSets" in res_json

    def test_focus(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s.json" % focus_id, status=200
        )
        res_json = json.loads(res.body)
        assert "UniqueFQDNSet" in res_json

        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s/calendar.json" % focus_id, status=200
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

    def test_manipulate(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s/renew/queue" % focus_id,
            {"action": "cancel"},
            status=303,
        )
        res = self.testapp.get(
            "/.well-known/admin/unique-fqdn-set/%s/renew/queue.json" % focus_id,
            {"action": "cancel"},
            status=200,
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

    def test_list(self):
        # root
        res = self.testapp.get("/.well-known/admin/queue-domains", status=200)
        res = self.testapp.get("/.well-known/admin/queue-domains/all", status=200)
        # paginated
        res = self.testapp.get("/.well-known/admin/queue-domains/1", status=200)
        res = self.testapp.get("/.well-known/admin/queue-domains/all/1", status=200)

        # json root
        res = self.testapp.get("/.well-known/admin/queue-domains.json", status=200)
        res = self.testapp.get("/.well-known/admin/queue-domains/all.json", status=200)
        # json paginated
        res = self.testapp.get("/.well-known/admin/queue-domains/1.json", status=200)
        res = self.testapp.get(
            "/.well-known/admin/queue-domains/all/1.json", status=200
        )

    def test_focus(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/queue-domain/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/queue-domain/%s.json" % focus_id, status=200
        )

    def tests_add(self):
        res = self.testapp.get("/.well-known/admin/queue-domains/add", status=200)
        form = res.form
        form["domain_names"] = TEST_FILES["Domains"]["Queue"]["1"]["add"]
        res2 = form.submit()
        assert res2.status_code == 303
        assert (
            """http://localhost/.well-known/admin/queue-domains?result=success"""
            in res2.location
        )

        res = self.testapp.get("/.well-known/admin/queue-domains/add.json", status=200)
        _data = {"domain_names": TEST_FILES["Domains"]["Queue"]["1"]["add.json"]}
        res2 = self.testapp.post("/.well-known/admin/queue-domains/add.json", _data)
        assert res2.status_code == 200
        res2_json = json.loads(res2.body)
        assert res2_json["result"] == "success"

    @unittest.skip("tests not written yet")
    def tests_todo(self):
        # todo
        if DISABLE_UNWRITTEN_TESTS:
            return True
        res = self.testapp.get("/.well-known/admin/queue-domains/process", status=200)
        res = self.testapp.get(
            "/.well-known/admin/queue-domains/process.json", status=200
        )

    def test_manipulate(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/queue-domain/%s/mark" % focus_id,
            {"action": "cancel"},
            status=303,
        )
        res = self.testapp.get(
            "/.well-known/admin/queue-domain/%s/mark.json" % focus_id,
            {"action": "cancel"},
            status=200,
        )


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

    def test_list(self):
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

    def test_focus(self):
        """this doesn't work on solo tests"""
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/%s" % focus_id, status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/%s.json" % focus_id, status=200
        )

    @unittest.skip("tests not written yet")
    def tests_todo(self):
        # todo
        if DISABLE_UNWRITTEN_TESTS:
            return True
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/process", status=200
        )
        res = self.testapp.get(
            "/.well-known/admin/queue-certificates/process.json", status=200
        )

    def test_manipulate(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/%s/mark" % focus_id,
            {"action": "cancel"},
            status=303,
        )
        res = self.testapp.get(
            "/.well-known/admin/queue-certificate/%s/mark.json" % focus_id,
            {"action": "cancel"},
            status=200,
        )


class FunctionalTests_Operations(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_Operations"""

    def tests_passive(self):
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
        res = self.testapp.get("/.well-known/admin/operations/nginx", status=200)
        res = self.testapp.get("/.well-known/admin/operations/nginx/1", status=200)
        res = self.testapp.get("/.well-known/admin/operations/redis", status=200)
        res = self.testapp.get("/.well-known/admin/operations/redis/1", status=200)
        res = self.testapp.get("/.well-known/admin/operations/object-log", status=200)
        res = self.testapp.get("/.well-known/admin/operations/object-log/1", status=200)

        focus_item = (
            self.ctx.dbSession.query(model_objects.OperationsEvent)
            .order_by(model_objects.OperationsEvent.id.asc())
            .limit(1)
            .one()
        )
        res = self.testapp.get(
            "/.well-known/admin/operations/log/item/%s" % focus_item.id, status=200
        )

        focus_item_event = (
            self.ctx.dbSession.query(model_objects.OperationsObjectEvent)
            .order_by(model_objects.OperationsObjectEvent.id.asc())
            .limit(1)
            .one()
        )
        res = self.testapp.get(
            "/.well-known/admin/operations/object-log/item/%s" % focus_item_event.id,
            status=200,
        )


class ZZZ_FunctionalTests_API(AppTest):
    """python -m unittest peter_sslers.tests.ZZZ_FunctionalTests_API"""

    """this is prefixed `ZZZ_` so it runs last.
    When run, some API endpoints will deactivate the test certificates - which will
    cause other tests to fail.
    """

    def tests_passive(self):
        res = self.testapp.get("/.well-known/admin/api", status=200)

    def tests_domains(self):
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

    @unittest.skipUnless(RUN_NGINX_TESTS, "not running against nginx")
    def tests_nginx(self):
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

    @unittest.skipUnless(RUN_REDIS_TESTS, "not running against nginx")
    def tests_redis(self):
        res = self.testapp.get("/.well-known/admin/api/redis/prime", status=303)
        assert (
            "/.well-known/admin/operations/redis?result=success&operation=redis_prime&event.id="
            in res.location
        )

        res = self.testapp.get("/.well-known/admin/api/redis/prime.json", status=200)
        res_json = json.loads(res.body)
        assert res_json["result"] == "success"

    def tests_manipulate(self):
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

    @unittest.skipUnless(
        RUN_LETSENCRYPT_API_TESTS, "not running against letsencrypt api"
    )
    def tests_letsencrypt_api(self):
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

    @unittest.skip("tests not written yet")
    def tests__certificate_if_needed(self):
        """
        ApiDomains__certificate_if_needed
        """
        pass
