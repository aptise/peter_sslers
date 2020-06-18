from __future__ import print_function

# stdlib
import os
import os.path
import pdb
import unittest
from io import open  # overwrite `open` in Python2


# pypi
from acme import crypto_util as acme_crypto_util
from certbot import crypto_util
from OpenSSL import crypto

# local
from ._utils import AppTestCore
from ._utils import AppTest
from ._utils import TEST_FILES
from ..lib import cert_utils
from ..lib import utils
from ..lib.db import get as lib_db_get
from ..lib.db import getcreate as lib_db_getcreate
from ..model import objects as model_objects
from ..model import utils as model_utils


# ==============================================================================


class UnitTest_CertUtils(unittest.TestCase):
    """python -m unittest peter_sslers.tests.unit_tests.UnitTest_CertUtils"""

    _data_root = os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data")
    _cert_sets = {
        "001": {
                "csr.domains.all": ["a.example.com", "b.example.com", "c.example.com", "d.example.com",],
                "csr.domains.subject": None,
                "csr.domains.san": ["a.example.com", "b.example.com", "c.example.com", "d.example.com",],
                "cert": True,
                "cert.domains.all": ["a.example.com", "b.example.com", "c.example.com", "d.example.com",],
                "cert.domains.subject": "a.example.com",
                "cert.domains.san": ["a.example.com", "b.example.com", "c.example.com", "d.example.com",],
                },
        "002": {
                "csr.domains.all": ["example.com",],
                "csr.domains.subject": "example.com",
                "csr.domains.san": [],
                "cert": False,
                },
        "003": {
                "csr.domains.all": ["example.com",],
                "csr.domains.subject": None,
                "csr.domains.san": ["example.com"],
                "cert": True,
                "cert.domains.all": ["example.com",],
                "cert.domains.subject": "example.com",
                "cert.domains.san": ["example.com",],
                },
        "004": {
                "csr.domains.all": ["a.example.com", "b.example.com", "c.example.com", "d.example.com",],
                "csr.domains.subject": None,
                "csr.domains.san": ["a.example.com", "b.example.com", "c.example.com", "d.example.com",],
                "cert": True,
                "cert.domains.all": ["a.example.com", "b.example.com", "c.example.com", "d.example.com",],
                "cert.domains.subject": "a.example.com",
                "cert.domains.san": ["a.example.com", "b.example.com", "c.example.com", "d.example.com",],
                },
        "005": {
                "csr.domains.all": ["a.example.com", "b.example.com", "c.example.com", "d.example.com",],
                "csr.domains.subject": "a.example.com",
                "csr.domains.san": ["b.example.com", "c.example.com", "d.example.com",],
                "cert": False,
                },
    
    }
    
    def _filepath_testfile(self, filename):
        return os.path.join(self._data_root, filename)

    def _filedata_testfile(self, filename):
        with open(os.path.join(self._data_root, filename), "rt", encoding="utf-8") as f:
            data = f.read()
        return data

    def test__parse_cert_domains(self):
        """
        python -m unittest peter_sslers.tests.unit_tests.UnitTest_CertUtils.test__parse_cert_domains
        """
        
        for cert_set in self._cert_sets.keys():
            if not self._cert_sets[cert_set]["cert"]:
                continue
            cert_filename = "unit_tests/cert_%s/cert.pem" % cert_set
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)
            cert_domains = cert_utils.parse_cert_domains(cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath)
            self.assertEqual(cert_domains, self._cert_sets[cert_set]["cert.domains.all"])

    def test__parse_csr_domains(self):
        """
        python -m unittest peter_sslers.tests.unit_tests.UnitTest_CertUtils.test__parse_csr_domains
        """
        
        for cert_set in sorted(self._cert_sets.keys()):
            csr_filename = "unit_tests/cert_%s/csr.pem" % cert_set
            csr_pem_filepath = self._filepath_testfile(csr_filename)
            csr_pem = self._filedata_testfile(csr_filename)
            csr_domains = cert_utils.parse_csr_domains(csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath, submitted_domain_names=self._cert_sets[cert_set]["csr.domains.all"])
            self.assertEqual(csr_domains, self._cert_sets[cert_set]["csr.domains.all"])

    def test__validate_csr(self):
        """
        python -m unittest peter_sslers.tests.unit_tests.UnitTest_CertUtils.test__validate_csr
        """
        
        for cert_set in self._cert_sets.keys():
            csr_filename = "unit_tests/cert_%s/csr.pem" % cert_set
            csr_pem_filepath = self._filepath_testfile(csr_filename)
            csr_pem = self._filedata_testfile(csr_filename)
            cert_utils.validate_csr(csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath)

    def test__validate_key(self):
        """
        python -m unittest peter_sslers.tests.unit_tests.UnitTest_CertUtils.test__validate_key
        """
        
        for cert_set in self._cert_sets.keys():
            key_filename = "unit_tests/cert_%s/privkey.pem" % cert_set
            key_pem_filepath = self._filepath_testfile(key_filename)
            key_pem = self._filedata_testfile(key_filename)
            cert_utils.validate_key(key_pem=key_pem, key_pem_filepath=key_pem_filepath)

    def test__validate_cert(self):
        """
        python -m unittest peter_sslers.tests.unit_tests.UnitTest_CertUtils.test__validate_cert
        """
        
        for cert_set in self._cert_sets.keys():
            if not self._cert_sets[cert_set]["cert"]:
                continue
            cert_filename = "unit_tests/cert_%s/cert.pem" % cert_set
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)
            cert_utils.validate_cert(cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath)

    def test__make_csr(self):
        """
        python -m unittest peter_sslers.tests.unit_tests.UnitTest_CertUtils.test__make_csr
        """
        
        for cert_set in self._cert_sets.keys():
            key_filename = "unit_tests/cert_%s/privkey.pem" % cert_set
            key_pem_filepath = self._filepath_testfile(key_filename)
            key_pem = self._filedata_testfile(key_filename)
            csr_pem = cert_utils.make_csr(
                domain_names=self._cert_sets[cert_set]["csr.domains.all"],
                key_pem=key_pem,
                key_pem_filepath=key_pem_filepath,
            )


class UnitTest_CertUtils_fallback(UnitTest_CertUtils):
    """python -m unittest peter_sslers.tests.unit_tests.UnitTest_CertUtils_fallback"""

    def setUp(self):
        cert_utils.acme_crypto_util = None
        cert_utils.crypto = None
        cert_utils.crypto_util = None

    def tearDown(self):
        cert_utils.acme_crypto_util = acme_crypto_util
        cert_utils.crypto = crypto
        cert_utils.crypto_util = crypto_util



class UnitTest_OpenSSL(AppTestCore):
    """python -m unittest peter_sslers.tests.unit_tests.UnitTest_OpenSSL"""

    def test_modulus_PrivateKey(self):
        for pkey_set_id, set_data in TEST_FILES["PrivateKey"].items():
            pem_filepath = self._filepath_testfile(set_data["file"])
            _computed_modulus_md5 = cert_utils.modulus_md5_key(
                key_pem=dbPrivateKey.key_pem,
                key_pem_filepath=pem_filepath,
            )
            _expected_modulus_md5 = set_data["key_pem_modulus_md5"]
            assert _computed_modulus_md5 == _expected_modulus_md5
            _computed_md5 = utils.md5_text(self._filedata_testfile(pem_filepath))
            _expected_md5 = set_data["key_pem_md5"]
            assert _computed_md5 == _expected_md5


class UnitTest_PrivateKeyCycling(AppTest):
    """
    uses `AppTest` so we have access to a `self.ctx`

    These tests ensure that PrivateKey cycling for an AcmeAccount works

    It tests `getcreate__PrivateKey_for_AcmeAccount`, which is invoked during AcmeOrder processing

    python -m unittest peter_sslers.tests.unit_tests.UnitTest_PrivateKeyCycling
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
            self.ctx, dbAcmeAccount=dbAcmeAccount,
        )
        dbPrivateKey_2 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx, dbAcmeAccount=dbAcmeAccount,
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
            self.ctx, dbAcmeAccount=dbAcmeAccount,
        )
        dbPrivateKey_2 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx, dbAcmeAccount=dbAcmeAccount,
        )
        assert dbPrivateKey_1.id == dbPrivateKey_2.id
        assert dbPrivateKey_1.acme_account_id__owner == dbAcmeAccount.id
        assert dbPrivateKey_1.private_key_source == "generated"
        assert dbPrivateKey_1.private_key_type == "account_weekly"

    def test__account_daily(self):
        dbAcmeAccount = self._makeOne_AcmeAccount("account_daily")
        dbPrivateKey_1 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx, dbAcmeAccount=dbAcmeAccount,
        )
        dbPrivateKey_2 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx, dbAcmeAccount=dbAcmeAccount,
        )
        assert dbPrivateKey_1.id == dbPrivateKey_2.id
        assert dbPrivateKey_1.acme_account_id__owner == dbAcmeAccount.id
        assert dbPrivateKey_1.private_key_source == "generated"
        assert dbPrivateKey_1.private_key_type == "account_daily"

    def test__global_weekly(self):
        dbAcmeAccount = self._makeOne_AcmeAccount("global_weekly")
        dbPrivateKey_1 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx, dbAcmeAccount=dbAcmeAccount,
        )
        dbPrivateKey_2 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx, dbAcmeAccount=dbAcmeAccount,
        )
        assert dbPrivateKey_1.id == dbPrivateKey_2.id
        assert dbPrivateKey_1.acme_account_id__owner is None
        assert dbPrivateKey_1.private_key_source == "generated"
        assert dbPrivateKey_1.private_key_type == "global_weekly"

    def test__global_daily(self):
        dbAcmeAccount = self._makeOne_AcmeAccount("global_daily")
        dbPrivateKey_1 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx, dbAcmeAccount=dbAcmeAccount,
        )
        dbPrivateKey_2 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccount(
            self.ctx, dbAcmeAccount=dbAcmeAccount,
        )
        assert dbPrivateKey_1.id == dbPrivateKey_2.id
        assert dbPrivateKey_1.acme_account_id__owner is None
        assert dbPrivateKey_1.private_key_source == "generated"
        assert dbPrivateKey_1.private_key_type == "global_daily"
