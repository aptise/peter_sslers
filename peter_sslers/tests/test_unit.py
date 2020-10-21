from __future__ import print_function

# stdlib
import os
import os.path
import pdb
import unittest
from io import open  # overwrite `open` in Python2


# pypi
from acme import crypto_util as acme_crypto_util
from certbot import crypto_util as certbot_crypto_util

# from Crypto.Util import asn1 as crypto_util_asn1
from OpenSSL import crypto as openssl_crypto
from cryptography.hazmat.primitives import serialization as cryptography_serialization
import josepy
import cryptography

# local
from ._utils import AppTestCore
from ._utils import AppTest
from ._utils import TEST_FILES
from ._utils import _Mixin_filedata
from ..lib import cert_utils
from ..lib import utils
from ..lib.db import get as lib_db_get
from ..lib.db import getcreate as lib_db_getcreate
from ..model import objects as model_objects
from ..model import utils as model_utils


# ==============================================================================


class UnitTest_CertUtils(unittest.TestCase, _Mixin_filedata):
    """python -m unittest peter_sslers.tests.test_unit.UnitTest_CertUtils"""

    _account_sets = {
        "001": {
            "letsencrypt": True,
            "pem": True,
            "signature.input": "example.sample",
            "signature.output": "hN3bre1YpxSGbvKmx8zK9_o0yaxtDblDfS3Q3CsjAas9wUVIHk7NqxXH0HeEeZG_7T0AHH6HTfxMbucXK_dLog_g9AxQYFsRBc8587C8Z5rWF2YDCoo0W7JB7VOoLEHGfe7JRXeqgA9QSnci0wMFlKXC_6MbKxql8QtswOdvtFM85qcJsMCOSu2Xf6HLIAYFhdBJH-DvQGzE4ctOKAYCmDyXs42DBUU4CU0cNXj8TsN0cFRXvInvSqDsiPNSjyV32WC4clPHX69KEbs5Wr0WV2diHR-Q6w0QUljWZEDpcl8mb86LZwBqoUTHX2xstQI77sLcg7YhDfaIPrCjYJcNZw",
        },
    }
    _cert_sets = {
        "001": {
            "csr.domains.all": [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ],
            "csr.domains.subject": None,
            "csr.domains.san": [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ],
            "cert": True,
            "cert.domains.all": [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ],
            "cert.domains.subject": "a.example.com",
            "cert.domains.san": [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ],
            "pubkey_modulus_md5": "052dec9ebfb5036c7aa6dd61888765b6",
            "cert.notAfter": "2025-06-16 20:19:30",  # "Jun 16 20:19:30 2025 GMT",
            "cert.notBefore": "2020-06-16 20:19:30",
        },
        "002": {
            "csr.domains.all": [
                "example.com",
            ],
            "csr.domains.subject": "example.com",
            "csr.domains.san": [],
            "cert": False,
            "pubkey_modulus_md5": "c25a298dc7de8f855453a6ed8be8bb5f",
        },
        "003": {
            "csr.domains.all": [
                "example.com",
            ],
            "csr.domains.subject": None,
            "csr.domains.san": ["example.com"],
            "cert": True,
            "cert.domains.all": [
                "example.com",
            ],
            "cert.domains.subject": "example.com",
            "cert.domains.san": [
                "example.com",
            ],
            "pubkey_modulus_md5": "f625ac6f399f90867cbf6a4e5dd8fc9e",
            "cert.notAfter": "2025-06-16 22:06:46",  # "Jun 16 22:06:46 2025 GMT",
            "cert.notBefore": "2020-06-16 22:06:46",
        },
        "004": {
            "csr.domains.all": [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ],
            "csr.domains.subject": None,
            "csr.domains.san": [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ],
            "cert": True,
            "cert.domains.all": [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ],
            "cert.domains.subject": "a.example.com",
            "cert.domains.san": [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ],
            "pubkey_modulus_md5": "797ba616e62dedcb014a7a37bcde3fdf",
            "cert.notAfter": "2025-06-16 22:07:02",  # "Jun 16 22:07:02 2025 GMT",
            "cert.notBefore": "2020-06-16 22:07:02",
        },
        "005": {
            "csr.domains.all": [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ],
            "csr.domains.subject": "a.example.com",
            "csr.domains.san": [
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ],
            "cert": False,
            "pubkey_modulus_md5": "f4614ec52f34066ce074798cdc494d74",
        },
    }

    def test__parse_cert__domains(self):
        """
        python -m unittest peter_sslers.tests.test_unit.UnitTest_CertUtils.test__parse_cert__domains
        """

        for cert_set in sorted(self._cert_sets.keys()):
            if not self._cert_sets[cert_set]["cert"]:
                continue
            cert_filename = "unit_tests/cert_%s/cert.pem" % cert_set
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)
            cert_domains = cert_utils.parse_cert__domains(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
            )
            self.assertEqual(
                cert_domains, self._cert_sets[cert_set]["cert.domains.all"]
            )

    def test__parse_csr_domains(self):
        """
        python -m unittest peter_sslers.tests.test_unit.UnitTest_CertUtils.test__parse_csr_domains
        """

        for cert_set in sorted(self._cert_sets.keys()):
            csr_filename = "unit_tests/cert_%s/csr.pem" % cert_set
            csr_pem_filepath = self._filepath_testfile(csr_filename)
            csr_pem = self._filedata_testfile(csr_filename)
            csr_domains = cert_utils.parse_csr_domains(
                csr_pem=csr_pem,
                csr_pem_filepath=csr_pem_filepath,
                submitted_domain_names=self._cert_sets[cert_set]["csr.domains.all"],
            )
            self.assertEqual(csr_domains, self._cert_sets[cert_set]["csr.domains.all"])

    def test__validate_csr(self):
        """
        python -m unittest peter_sslers.tests.test_unit.UnitTest_CertUtils.test__validate_csr
        """

        for cert_set in sorted(self._cert_sets.keys()):
            csr_filename = "unit_tests/cert_%s/csr.pem" % cert_set
            csr_pem_filepath = self._filepath_testfile(csr_filename)
            csr_pem = self._filedata_testfile(csr_filename)
            cert_utils.validate_csr(csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath)

    def test__validate_key(self):
        """
        python -m unittest peter_sslers.tests.test_unit.UnitTest_CertUtils.test__validate_key
        """

        for cert_set in sorted(self._cert_sets.keys()):
            key_filename = "unit_tests/cert_%s/privkey.pem" % cert_set
            key_pem_filepath = self._filepath_testfile(key_filename)
            key_pem = self._filedata_testfile(key_filename)
            cert_utils.validate_key(key_pem=key_pem, key_pem_filepath=key_pem_filepath)

    def test__validate_cert(self):
        """
        python -m unittest peter_sslers.tests.test_unit.UnitTest_CertUtils.test__validate_cert
        """

        for cert_set in sorted(self._cert_sets.keys()):
            if not self._cert_sets[cert_set]["cert"]:
                continue
            cert_filename = "unit_tests/cert_%s/cert.pem" % cert_set
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)
            cert_utils.validate_cert(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
            )

    def test__make_csr(self):
        """
        python -m unittest peter_sslers.tests.test_unit.UnitTest_CertUtils.test__make_csr
        """

        for cert_set in sorted(self._cert_sets.keys()):
            key_filename = "unit_tests/cert_%s/privkey.pem" % cert_set
            key_pem_filepath = self._filepath_testfile(key_filename)
            key_pem = self._filedata_testfile(key_filename)
            csr_pem = cert_utils.make_csr(
                domain_names=self._cert_sets[cert_set]["csr.domains.all"],
                key_pem=key_pem,
                key_pem_filepath=key_pem_filepath,
            )

    def test__modulus_md5_key(self):
        """
        python -m unittest peter_sslers.tests.test_unit.UnitTest_CertUtils.test__modulus_md5_key
        """

        for cert_set in sorted(self._cert_sets.keys()):
            key_filename = "unit_tests/cert_%s/privkey.pem" % cert_set
            key_pem_filepath = self._filepath_testfile(key_filename)
            key_pem = self._filedata_testfile(key_filename)
            modulus_md5 = cert_utils.modulus_md5_key(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )
            self.assertEqual(
                modulus_md5, self._cert_sets[cert_set]["pubkey_modulus_md5"]
            )

    def test__modulus_md5_csr(self):
        """
        python -m unittest peter_sslers.tests.test_unit.UnitTest_CertUtils.test__modulus_md5_csr
        """

        for cert_set in sorted(self._cert_sets.keys()):
            csr_filename = "unit_tests/cert_%s/csr.pem" % cert_set
            csr_pem_filepath = self._filepath_testfile(csr_filename)
            csr_pem = self._filedata_testfile(csr_filename)
            modulus_md5 = cert_utils.modulus_md5_csr(
                csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath
            )
            self.assertEqual(
                modulus_md5, self._cert_sets[cert_set]["pubkey_modulus_md5"]
            )

    def test__modulus_md5_cert(self):
        """
        python -m unittest peter_sslers.tests.test_unit.UnitTest_CertUtils.test__modulus_md5_cert
        """

        for cert_set in sorted(self._cert_sets.keys()):
            if not self._cert_sets[cert_set]["cert"]:
                continue
            cert_filename = "unit_tests/cert_%s/cert.pem" % cert_set
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)
            modulus_md5 = cert_utils.modulus_md5_cert(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
            )
            self.assertEqual(
                modulus_md5, self._cert_sets[cert_set]["pubkey_modulus_md5"]
            )

    def test__parse_cert__enddate(self):
        """
        python -m unittest peter_sslers.tests.test_unit.UnitTest_CertUtils.test__parse_cert__enddate
        """

        for cert_set in sorted(self._cert_sets.keys()):
            if not self._cert_sets[cert_set]["cert"]:
                continue
            cert_filename = "unit_tests/cert_%s/cert.pem" % cert_set
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)
            cert_enddate = cert_utils.parse_cert__enddate(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
            )
            self.assertEqual(
                str(cert_enddate), self._cert_sets[cert_set]["cert.notAfter"]
            )

    def test__parse_cert__startdate(self):
        """
        python -m unittest peter_sslers.tests.test_unit.UnitTest_CertUtils.test__parse_cert__startdate
        """

        for cert_set in sorted(self._cert_sets.keys()):
            if not self._cert_sets[cert_set]["cert"]:
                continue
            cert_filename = "unit_tests/cert_%s/cert.pem" % cert_set
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)
            cert_startdate = cert_utils.parse_cert__startdate(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
            )
            self.assertEqual(
                str(cert_startdate), self._cert_sets[cert_set]["cert.notBefore"]
            )

    def test__parse_key(self):
        """
        python -m unittest peter_sslers.tests.test_unit.UnitTest_CertUtils.test__parse_key

        This is a debugging display function. The output is not guaranteed across installations.
        """

        for cert_set in sorted(self._cert_sets.keys()):
            key_filename = "unit_tests/cert_%s/privkey.pem" % cert_set
            key_pem_filepath = self._filepath_testfile(key_filename)
            key_pem = self._filedata_testfile(key_filename)
            rval = cert_utils.parse_key(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )

    def test__parse_cert(self):
        """
        python -m unittest peter_sslers.tests.test_unit.UnitTest_CertUtils.test__parse_cert
        """

        for cert_set in sorted(self._cert_sets.keys()):
            if not self._cert_sets[cert_set]["cert"]:
                continue
            cert_filename = "unit_tests/cert_%s/cert.pem" % cert_set
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)
            rval = cert_utils.parse_cert(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
            )

    def test__cert_and_chain_from_fullchain(self):
        """
        python -m unittest peter_sslers.tests.test_unit.UnitTest_CertUtils.test__cert_and_chain_from_fullchain
        """
        for cert_set in sorted(self._cert_sets.keys()):
            if not self._cert_sets[cert_set]["cert"]:
                continue
            fullchain_filename = "unit_tests/cert_%s/fullchain.pem" % cert_set
            fullchain_pem_filepath = self._filepath_testfile(fullchain_filename)
            fullchain_pem = self._filedata_testfile(fullchain_filename)

            cert_filename = "unit_tests/cert_%s/cert.pem" % cert_set
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)

            (_cert, _chain) = cert_utils.cert_and_chain_from_fullchain(fullchain_pem)
            self.assertEqual(_cert, cert_pem)

    def test__convert_lejson_to_pem(self):
        """
        python -m unittest peter_sslers.tests.test_unit.UnitTest_CertUtils.test__convert_lejson_to_pem
        """
        for account_set in sorted(self._account_sets.keys()):
            if not self._account_sets[account_set]["letsencrypt"]:
                continue
            if not self._account_sets[account_set]["pem"]:
                raise ValueError("need pem")

            # load the json
            key_jsons_filename = "unit_tests/account_%s/private_key.json" % account_set
            key_jsons_filepath = self._filepath_testfile(key_jsons_filename)
            key_jsons = self._filedata_testfile(key_jsons_filepath)

            # load the pem
            key_pem_filename = "unit_tests/account_%s/private_key.pem" % account_set
            key_pem_filepath = self._filepath_testfile(key_pem_filename)
            key_pem = self._filedata_testfile(key_pem_filepath)

            # convert
            rval = cert_utils.convert_lejson_to_pem(key_jsons)

            # compare
            self.assertEqual(rval, key_pem)

    def test__account_key__parse(self):
        """
        python -m unittest peter_sslers.tests.test_unit.UnitTest_CertUtils.test__account_key__parse
        """
        for account_set in sorted(self._account_sets.keys()):
            if not self._account_sets[account_set]["pem"]:
                raise ValueError("need pem")

            # load the pem
            key_pem_filename = "unit_tests/account_%s/private_key.pem" % account_set
            key_pem_filepath = self._filepath_testfile(key_pem_filename)
            key_pem = self._filedata_testfile(key_pem_filepath)

            rval = cert_utils.account_key__parse(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )

    def test__account_key__sign(self):
        """
        python -m unittest peter_sslers.tests.test_unit.UnitTest_CertUtils.test__account_key__sign
        """
        for account_set in sorted(self._account_sets.keys()):
            if not self._account_sets[account_set]["pem"]:
                raise ValueError("need pem")

            # load the pem
            key_pem_filename = "unit_tests/account_%s/private_key.pem" % account_set
            key_pem_filepath = self._filepath_testfile(key_pem_filename)
            key_pem = self._filedata_testfile(key_pem_filepath)

            input = self._account_sets[account_set]["signature.input"]
            expected = self._account_sets[account_set]["signature.output"]

            signature = cert_utils.account_key__sign(
                input, key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )
            signature = cert_utils._b64(signature)
            self.assertEqual(signature, expected)


class UnitTest_OpenSSL(unittest.TestCase, _Mixin_filedata):
    """python -m unittest peter_sslers.tests.test_unit.UnitTest_OpenSSL"""

    def test_modulus_PrivateKey(self):
        for pkey_set_id, set_data in sorted(TEST_FILES["PrivateKey"].items()):
            key_pem_filepath = self._filepath_testfile(set_data["file"])
            key_pem = self._filedata_testfile(key_pem_filepath)
            _computed_modulus_md5 = cert_utils.modulus_md5_key(
                key_pem=key_pem,
                key_pem_filepath=key_pem_filepath,
            )
            _expected_modulus_md5 = set_data["key_pem_modulus_md5"]
            assert _computed_modulus_md5 == _expected_modulus_md5
            _computed_md5 = utils.md5_text(self._filedata_testfile(key_pem_filepath))
            _expected_md5 = set_data["key_pem_md5"]
            assert _computed_md5 == _expected_md5


class _MixinNoCrypto(object):
    def setUp(self):
        # print("_MixinNoCrypto.setUp")
        cert_utils.acme_crypto_util = None
        cert_utils.openssl_crypto = None
        cert_utils.certbot_crypto_util = None
        # cert_utils.crypto_util_asn1 = None
        cert_utils.josepy = None
        cert_utils.cryptography_serialization = None
        cryptography = None

    def tearDown(self):
        # print("_MixinNoCrypto.tearDown")
        cert_utils.acme_crypto_util = acme_crypto_util
        cert_utils.openssl_crypto = openssl_crypto
        cert_utils.certbot_crypto_util = certbot_crypto_util
        # cert_utils.crypto_util_asn1 = crypto_util_asn1
        cert_utils.josepy = josepy
        cert_utils.cryptography_serialization = cryptography_serialization
        cert_utils.cryptography = cryptography


class UnitTest_CertUtils_fallback(_MixinNoCrypto, UnitTest_CertUtils):
    """python -m unittest peter_sslers.tests.test_unit.UnitTest_CertUtils_fallback"""

    pass


class UnitTest_OpenSSL_fallback(_MixinNoCrypto, UnitTest_CertUtils):
    """python -m unittest peter_sslers.tests.test_unit.UnitTest_OpenSSL_fallback"""

    pass


class UnitTest_PrivateKeyCycling(AppTest):
    """
    uses `AppTest` so we have access to a `self.ctx`

    These tests ensure that PrivateKey cycling for an AcmeAccount works

    It tests `getcreate__PrivateKey_for_AcmeAccount`, which is invoked during AcmeOrder processing

    python -m unittest peter_sslers.tests.test_unit.UnitTest_PrivateKeyCycling
    """

    def _makeOne_AcmeAccount(self, private_key_cycle):
        """
        create a new AcmeAccount with a given private_key_cycle
        """
        contact = "%s@example.com" % private_key_cycle
        _key_filename = "AcmeAccountKey-cycle-%s.pem" % private_key_cycle
        key_pem = self._filedata_testfile(_key_filename)
        (dbAcmeAccount, _is_created) = lib_db_getcreate.getcreate__AcmeAccount(
            self.ctx,
            key_pem=key_pem,
            acme_account_provider_id=1,  # pebble
            acme_account_key_source_id=model_utils.AcmeAccountKeySource.from_string(
                "imported"
            ),
            contact=contact,
            private_key_cycle_id=model_utils.PrivateKeyCycle.from_string(
                private_key_cycle
            ),
        )
        return dbAcmeAccount

    def test__single_certificate(self):
        dbAcmeAccount = self._makeOne_AcmeAccount("single_certificate")
        dbPrivateKey_1 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx,
            dbAcmeAccount=dbAcmeAccount,
        )
        dbPrivateKey_2 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx,
            dbAcmeAccount=dbAcmeAccount,
        )
        assert dbPrivateKey_1.id != dbPrivateKey_2.id
        assert dbPrivateKey_1.acme_account_id__owner == dbAcmeAccount.id
        assert dbPrivateKey_1.private_key_source == "generated"
        assert dbPrivateKey_1.private_key_type == "single_certificate"

        assert dbPrivateKey_2.acme_account_id__owner == dbAcmeAccount.id
        assert dbPrivateKey_2.private_key_source == "generated"
        assert dbPrivateKey_2.private_key_type == "single_certificate"

    def test__account_weekly(self):
        dbAcmeAccount = self._makeOne_AcmeAccount("account_weekly")
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

    def test__account_daily(self):
        dbAcmeAccount = self._makeOne_AcmeAccount("account_daily")
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

    def test__global_weekly(self):
        dbAcmeAccount = self._makeOne_AcmeAccount("global_weekly")
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

    def test__global_daily(self):
        dbAcmeAccount = self._makeOne_AcmeAccount("global_daily")
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
