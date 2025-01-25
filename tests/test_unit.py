# stdlib
import http.client
from io import BytesIO
import test
import test.test_httplib
from typing import Callable
from typing import Dict
import unittest
from urllib.response import addinfourl

# pypi
import cert_utils
from cert_utils import letsencrypt_info

# local
from peter_sslers.lib import acme_v2
from peter_sslers.lib import utils
from peter_sslers.lib.db import getcreate as lib_db_getcreate
from peter_sslers.model import utils as model_utils
from ._utils import AppTest


# ==============================================================================


class _MixIn_AcmeAccount(object):
    _filedata_testfile: Callable
    ctx: Callable[[], utils.ApiContext]

    def _makeOne_AcmeAccount(
        self,
        private_key_cycle=None,
        private_key_technology=None,
        existing_account_key=None,
        contact=None,
    ):
        """
        create a new AcmeAccount with a given private_key_cycle
        """
        if contact is None:
            contact = "%s@example.com" % private_key_cycle
        _kwargs = {}
        if private_key_technology is not None:
            _kwargs["private_key_technology_id"] = (
                model_utils.KeyTechnology.from_string(private_key_technology)
            )
            _kwargs["order_default_private_key_technology_id"] = (
                model_utils.KeyTechnology.from_string(private_key_technology)
            )
        if not existing_account_key:
            key_pem = cert_utils.new_account_key()
        else:
            _key_filename = (
                "key_technology-rsa/AcmeAccountKey-cycle-%s.pem" % private_key_cycle
            )
            key_pem = self._filedata_testfile(_key_filename)

        (dbAcmeAccount, _is_created) = lib_db_getcreate.getcreate__AcmeAccount(
            self.ctx,
            acme_account_key_source_id=model_utils.AcmeAccountKeySource.IMPORTED,
            key_pem=key_pem,
            acme_server_id=1,  # pebble
            contact=contact,
            order_default_private_key_cycle_id=model_utils.PrivateKeyCycle.from_string(
                private_key_cycle
            ),
            **_kwargs,
        )
        return dbAcmeAccount


# ==============================================================================


class UnitTest_PrivateKeyCycling(AppTest, _MixIn_AcmeAccount):
    """
    uses `AppTest` so we have access to a `self.ctx`

    These tests ensure that PrivateKey cycling for an AcmeAccount works

    It tests `getcreate__PrivateKey_for_AcmeAccount`, which is invoked during AcmeOrder processing

    python -m unittest tests.test_unit.UnitTest_PrivateKeyCycling
    """

    def test__single_use(self):
        """
        auto-generate a new key for an account
        """
        dbAcmeAccount = self._makeOne_AcmeAccount(
            private_key_cycle="single_use", existing_account_key=True
        )
        self.assertEqual(
            dbAcmeAccount.private_key_technology,
            model_utils.KeyTechnology._DEFAULT_AcmeAccount,
        )
        dbPrivateKey_1 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx,
            dbAcmeAccount=dbAcmeAccount,
        )
        dbPrivateKey_2 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx,
            dbAcmeAccount=dbAcmeAccount,
        )
        self.assertNotEqual(dbPrivateKey_1.id, dbPrivateKey_2.id)
        self.assertEqual(
            dbAcmeAccount.private_key_technology, dbPrivateKey_1.key_technology
        )
        self.assertEqual(dbPrivateKey_1.key_technology, dbPrivateKey_2.key_technology)
        self.assertEqual(dbPrivateKey_1.acme_account_id__owner, dbAcmeAccount.id)
        self.assertEqual(dbPrivateKey_1.private_key_source, "generated")
        self.assertEqual(dbPrivateKey_1.private_key_type, "single_use")
        self.assertEqual(dbPrivateKey_2.acme_account_id__owner, dbAcmeAccount.id)
        self.assertEqual(dbPrivateKey_2.private_key_source, "generated")
        self.assertEqual(dbPrivateKey_2.private_key_type, "single_use")

    def test__account_weekly(self, existing_account_key=True):
        """
        this will not auto-generate a new key, because it is weekly
        """
        dbAcmeAccount = self._makeOne_AcmeAccount(private_key_cycle="account_weekly")
        dbPrivateKey_1 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx,
            dbAcmeAccount=dbAcmeAccount,
        )
        dbPrivateKey_2 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx,
            dbAcmeAccount=dbAcmeAccount,
        )
        assert dbPrivateKey_1.id == dbPrivateKey_2.id
        assert dbPrivateKey_1.acme_account_id__owner == dbAcmeAccount.id
        assert dbPrivateKey_1.private_key_source == "generated"
        assert dbPrivateKey_1.private_key_type == "account_weekly"

    def test__account_daily(self, existing_account_key=True):
        """
        this will not auto-generate a new key, because it is daily
        """
        dbAcmeAccount = self._makeOne_AcmeAccount(private_key_cycle="account_daily")
        dbPrivateKey_1 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx,
            dbAcmeAccount=dbAcmeAccount,
        )
        dbPrivateKey_2 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx,
            dbAcmeAccount=dbAcmeAccount,
        )
        assert dbPrivateKey_1.id == dbPrivateKey_2.id
        assert dbPrivateKey_1.acme_account_id__owner == dbAcmeAccount.id
        assert dbPrivateKey_1.private_key_source == "generated"
        assert dbPrivateKey_1.private_key_type == "account_daily"

    def test__global_weekly(self, existing_account_key=True):
        """
        this will not auto-generate a new key, because it is weekly
        """
        dbAcmeAccount = self._makeOne_AcmeAccount(private_key_cycle="global_weekly")
        dbPrivateKey_1 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx,
            dbAcmeAccount=dbAcmeAccount,
        )
        dbPrivateKey_2 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx,
            dbAcmeAccount=dbAcmeAccount,
        )
        assert dbPrivateKey_1.id == dbPrivateKey_2.id
        assert dbPrivateKey_1.acme_account_id__owner is None
        assert dbPrivateKey_1.private_key_source == "generated"
        assert dbPrivateKey_1.private_key_type == "global_weekly"

    def test__global_daily(self, existing_account_key=True):
        """
        this will not auto-generate a new key, because it is daily
        """
        dbAcmeAccount = self._makeOne_AcmeAccount(private_key_cycle="global_daily")
        dbPrivateKey_1 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx,
            dbAcmeAccount=dbAcmeAccount,
        )
        dbPrivateKey_2 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx,
            dbAcmeAccount=dbAcmeAccount,
        )
        assert dbPrivateKey_1.id == dbPrivateKey_2.id
        assert dbPrivateKey_1.acme_account_id__owner is None
        assert dbPrivateKey_1.private_key_source == "generated"
        assert dbPrivateKey_1.private_key_type == "global_daily"


class UnitTest_PrivateKeyCycling_KeyTechnology(AppTest, _MixIn_AcmeAccount):
    """
    uses `AppTest` so we have access to a `self.ctx`

    These tests ensure that PrivateKey cycling for an AcmeAccount works

    It tests `getcreate__PrivateKey_for_AcmeAccount`, which is invoked during AcmeOrder processing

    python -m unittest tests.test_unit.UnitTest_PrivateKeyCycling_KeyTechnology
    """

    def _test__single_use(self, private_key_technology=None):
        """
        auto-generate a new key for an account
        """
        private_key_technology_expected = (
            private_key_technology or model_utils.KeyTechnology._DEFAULT_AcmeAccount
        )
        dbAcmeAccount = self._makeOne_AcmeAccount(
            private_key_cycle="single_use",
            private_key_technology=private_key_technology,
            existing_account_key=False,
            contact="single_use-%s-%s@example.com"
            % (
                private_key_technology,
                self.__class__.__name__,
            ),
        )
        self.assertEqual(
            dbAcmeAccount.private_key_technology,
            private_key_technology_expected,
        )
        dbPrivateKey_1 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx,
            dbAcmeAccount=dbAcmeAccount,
        )
        dbPrivateKey_2 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx,
            dbAcmeAccount=dbAcmeAccount,
        )
        self.assertNotEqual(dbPrivateKey_1.id, dbPrivateKey_2.id)
        self.assertEqual(
            dbAcmeAccount.private_key_technology, dbPrivateKey_1.key_technology
        )
        self.assertEqual(dbPrivateKey_1.key_technology, dbPrivateKey_2.key_technology)
        self.assertEqual(dbPrivateKey_1.acme_account_id__owner, dbAcmeAccount.id)
        self.assertEqual(dbPrivateKey_1.private_key_source, "generated")
        self.assertEqual(dbPrivateKey_1.private_key_type, "single_use")
        self.assertEqual(dbPrivateKey_2.acme_account_id__owner, dbAcmeAccount.id)
        self.assertEqual(dbPrivateKey_2.private_key_source, "generated")
        self.assertEqual(dbPrivateKey_2.private_key_type, "single_use")

    def test__key_technology__none(self):
        """
        python -m unittest tests.test_unit.UnitTest_PrivateKeyCycling_KeyTechnology.test__key_technology__none
        """
        self._test__single_use(
            private_key_technology=None,
        )

    def test__key_technology__rsa(self):
        self._test__single_use(
            private_key_technology="RSA_2048",
        )

    def test__key_technology__ec(self):
        self._test__single_use(
            private_key_technology="EC_P256",
        )


class _MockedFP(BytesIO):
    """
    used to mock some objects for tests
    this does nothing but avoid errors!
    """

    def read(self, size=-1) -> bytes:
        return b""

    def readline(self, hint=None) -> bytes:
        return b""

    def close(self):
        pass


class UnitTest_ACME_v2(unittest.TestCase):
    """
    python2 -m unittest tests.test_unit.UnitTest_ACME_v2
    python3 -m unittest tests.test_unit.UnitTest_ACME_v2
    """

    def test__parse_headers(self):
        # python 2 and 3 implement the http headers differently
        _message_template = b"HTTP/1.1 200 OK\r\n%s\r\n"
        _link_1 = b"""Link: <https://acme-staging-v02.api.letsencrypt.org/directory>;rel="index"\r\n"""
        _link_2 = b"""Link: <https://acme-staging-v02.api.letsencrypt.org/acme/cert/12345/1>;rel="alternate"\r\n"""
        body_1 = _message_template % _link_1
        body_2 = _message_template % (b"%s%s" % (_link_1, _link_2))

        message_1 = http.client.HTTPResponse(test.test_httplib.FakeSocket(body_1))
        message_1.begin()

        message_2 = http.client.HTTPResponse(test.test_httplib.FakeSocket(body_2))
        message_2.begin()

        # In an ideal world, that would be all, but we need some more massaging
        # of the data objects
        # Python2:
        #   message_1.getheaders() = LIST
        #   message_1.msg = httplib.HTTPMessage
        #   message_1.msg.headers = LIST
        # Python3:
        #   message_1.getheaders() = LIST
        #   message_1.msg = http.client.HTTPMessage
        #   message_1.msg.headers = DOES NOT EXIST

        fp = _MockedFP()
        message_1_ = addinfourl(fp, message_1.msg, "")
        message_2_ = addinfourl(fp, message_2.msg, "")

        message_1_alts = acme_v2.get_header_links(message_1_.headers, "alternate")
        assert len(message_1_alts) == 0

        message_2_alts = acme_v2.get_header_links(message_2_.headers, "alternate")
        assert len(message_2_alts) == 1


class UnitTest_LetsEncrypt_Data(unittest.TestCase):
    """
    python -m unittest tests.test_unit.UnitTest_LetsEncrypt_Data
    """

    def test_formatting(self):
        self.assertTrue(hasattr(letsencrypt_info, "CERT_CAS_VERSION"))
        self.assertTrue(hasattr(letsencrypt_info, "CERT_CAS_DATA"))
        self.assertTrue(hasattr(letsencrypt_info, "CA_LE_INTERMEDIATES_CROSSED"))
        self.assertTrue(hasattr(letsencrypt_info, "CA_LE_INTERMEDIATES"))

        seen: Dict = {
            "url_pem": [],
            "display_name": [],
        }
        for cert_id, cert_payload in letsencrypt_info.CERT_CAS_DATA.items():
            # Make sure every cert has it's chain present
            _signed_by = cert_payload.get("signed_by")
            self.assertIn(_signed_by, letsencrypt_info.CERT_CAS_DATA)

            if cert_payload.get("is_self_signed"):
                self.assertEqual(cert_id, _signed_by)

            # Make sure every ALTERNATE has a corresponding reference
            # and vice-versa
            _alternates = cert_payload.get("alternates")
            _alternate_of = cert_payload.get("alternate_of")
            self.assertFalse(_alternates and _alternate_of)
            if _alternates:
                for _alternate in _alternates:
                    self.assertIn(_alternate, letsencrypt_info.CERT_CAS_DATA)
                    _alternate_payload = letsencrypt_info.CERT_CAS_DATA[_alternate]
                    self.assertEqual(cert_id, _alternate_payload["alternate_of"])
            if _alternate_of:
                _alternate_payload = letsencrypt_info.CERT_CAS_DATA[_alternate_of]
                self.assertIn("alternates", _alternate_payload)

            # these
            _url_pem = cert_payload.get("url_pem")
            self.assertNotIn(_url_pem, seen["url_pem"])
            seen["url_pem"].append(_url_pem)

            # our display_name should be unique
            _display_name = cert_payload.get("display_name")
            self.assertNotIn(_display_name, seen["display_name"])
            seen["display_name"].append(_display_name)
