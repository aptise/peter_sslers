from __future__ import print_function

# stdlib
import json
import os
import os.path
import pdb
import pprint
import tempfile
import test
import test.test_httplib
import unittest
from io import open  # overwrite `open` in Python2


# pypi
from acme import crypto_util as acme_crypto_util
from certbot import crypto_util as certbot_crypto_util
import six
from six.moves import http_client
from six.moves.urllib.response import addinfourl

# from Crypto.Util import asn1 as crypto_util_asn1
from OpenSSL import crypto as openssl_crypto
from cryptography.hazmat.primitives import serialization as cryptography_serialization
import josepy
import cryptography

# local
from peter_sslers.lib import acme_v2
from peter_sslers.lib import cert_utils
from peter_sslers.lib import letsencrypt_info
from peter_sslers.lib import utils
from peter_sslers.lib.db import get as lib_db_get
from peter_sslers.lib.db import getcreate as lib_db_getcreate
from peter_sslers.model import objects as model_objects
from peter_sslers.model import utils as model_utils

from ._utils import AppTestCore
from ._utils import AppTest
from ._utils import CERT_CA_SETS
from ._utils import CSR_SETS
from ._utils import KEY_SETS
from ._utils import TEST_FILES
from ._utils import _Mixin_filedata


# ==============================================================================


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


class _MixIn_AcmeAccount(object):
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
            _kwargs[
                "private_key_technology_id"
            ] = model_utils.KeyTechnology.from_string(private_key_technology)
        if not existing_account_key:
            key_pem = cert_utils.new_account_key()
        else:
            _key_filename = (
                "key_technology-rsa/AcmeAccountKey-cycle-%s.pem" % private_key_cycle
            )
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
            **_kwargs
        )
        return dbAcmeAccount


# ==============================================================================


class UnitTest_CertUtils(unittest.TestCase, _Mixin_filedata):
    """python -m unittest tests.test_unit.UnitTest_CertUtils"""

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
            "csr": True,
            "csr.subject": "",
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
            "cert.notAfter": "2025-06-16 20:19:30",  # "Jun 16 20:19:30 2025 GMT",
            "cert.notBefore": "2020-06-16 20:19:30",
            "cert.fingerprints": {
                "sha1": "F6:3C:5C:66:B5:25:51:EE:DA:DF:7C:E4:43:01:D6:46:68:0B:8F:5D",
                "sha256": "02:7E:69:B3:5F:0D:8F:2D:2A:3D:06:D4:72:08:F0:C4:FD:31:B6:9A:42:9D:FC:36:BE:8D:D0:D5:B7:3D:8D:C4",
                "md5": "21:C6:0F:E6:39:DF:16:CA:5B:F1:5D:82:07:F0:7A:42",
            },
            "cert.authority_key_identifier": "D1:59:01:00:94:B0:A6:2A:DB:AB:E5:4B:23:21:CA:1B:6E:BA:93:E7",
            "cert.issuer_uri": None,
            "key_technology": "RSA",
            "pubkey_modulus_md5": "052dec9ebfb5036c7aa6dd61888765b6",
            "spki_sha256": "NOZ8xhV2HLra9DCy4C4Ow5yZ7vxzzORpsYrlSjfvaUI=",
        },
        "002": {
            "csr": True,
            "csr.subject": "CN=example.com",
            "csr.domains.all": [
                "example.com",
            ],
            "csr.domains.subject": "example.com",
            "csr.domains.san": [],
            "cert": False,
            "key_technology": "RSA",
            "pubkey_modulus_md5": "c25a298dc7de8f855453a6ed8be8bb5f",
            "spki_sha256": "wf9xRu6GFHmumXYXy5lEJJBflEHG2eZpqabMUgRFxmM=",
        },
        "003": {
            "csr": True,
            "csr.subject": "",
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
            "cert.notAfter": "2025-06-16 22:06:46",  # "Jun 16 22:06:46 2025 GMT",
            "cert.notBefore": "2020-06-16 22:06:46",
            "cert.fingerprints": {
                "sha1": "E8:50:3E:AC:0F:4F:96:85:84:1F:96:1A:D9:66:77:4D:66:52:1C:5E",
                "sha256": "CC:8D:06:6A:7C:59:D6:7A:4D:AE:E0:2A:C6:7B:AA:C5:DA:02:96:30:37:58:CC:82:4A:F6:24:3D:5A:8C:78:F6",
                "md5": "45:5A:11:B0:57:29:B3:BD:E1:1A:86:D5:A9:4C:40:D7",
            },
            "cert.authority_key_identifier": "D1:59:01:00:94:B0:A6:2A:DB:AB:E5:4B:23:21:CA:1B:6E:BA:93:E7",
            "cert.issuer_uri": None,
            "key_technology": "RSA",
            "pubkey_modulus_md5": "f625ac6f399f90867cbf6a4e5dd8fc9e",
            "spki_sha256": "BDrxucwa+SXBMuGVdPt7JR9yfVXhhdmIK3py8R+CrZc=",
        },
        "004": {
            "csr": True,
            "csr.subject": "",
            "csr.domains.all": [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
            ],
            "csr.domains.subject": "",
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
            "cert.notAfter": "2025-06-16 22:07:02",  # "Jun 16 22:07:02 2025 GMT",
            "cert.notBefore": "2020-06-16 22:07:02",
            "cert.fingerprints": {
                "sha1": "A8:88:02:00:45:24:52:AD:F1:92:84:7C:DE:C1:33:06:17:20:4D:14",
                "sha256": "39:06:F1:74:72:B9:E1:80:C6:52:61:35:B0:BB:F4:CA:2C:61:87:D2:DC:90:67:80:9F:C0:23:B5:EA:27:62:57",
                "md5": "36:D3:A4:29:48:CF:7C:78:D5:06:60:C9:F4:66:18:B3",
            },
            "cert.authority_key_identifier": "D1:59:01:00:94:B0:A6:2A:DB:AB:E5:4B:23:21:CA:1B:6E:BA:93:E7",
            "cert.issuer_uri": None,
            "pubkey_modulus_md5": "797ba616e62dedcb014a7a37bcde3fdf",
            "key_technology": "RSA",
            "spki_sha256": "BIJayn/eeRw//axzuPUldepZh1PQ+emVGH6FbjRjOSI=",
        },
        "005": {
            "csr": True,
            "csr.subject": "CN=a.example.com",
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
            "key_technology": "RSA",
            "pubkey_modulus_md5": "f4614ec52f34066ce074798cdc494d74",
            "spki_sha256": "vtmS2tVwpJhOpHvhyS8JGDmIi8NILZIG+JHEqCOa0qs=",
        },
    }
    _csr_sets_alt = {
        "001": {
            "directory": "key_technology-ec",
            "file.key": "ec384-1-key.pem",
            "file.csr": "ec384-1.csr",
            "csr": True,
            "csr.subject": "CN=ec384-1.example.com",
            "csr.domains.all": [
                "ec384-1.example.com",
            ],
            "csr.domains.subject": "ec384-1.example.com",
            "csr.domains.san": [],
            "cert": False,
            "pubkey_modulus_md5": "None",
            "key_technology": "EC",
            "spki_sha256": "5zn7AIGGjJe4rA03c2gJdOn87L+h/IuAr92+QvMNHZ0=",
        }
    }

    def test__parse_cert__domains(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__parse_cert__domains
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

    def test__fingerprint_cert(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__fingerprint_cert
        """

        for cert_set in sorted(self._cert_sets.keys()):
            if not self._cert_sets[cert_set]["cert"]:
                continue
            cert_filename = "unit_tests/cert_%s/cert.pem" % cert_set
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)

            # defaults to sha1
            _fingerprint = cert_utils.fingerprint_cert(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
            )
            self.assertEqual(
                _fingerprint, self._cert_sets[cert_set]["cert.fingerprints"]["sha1"]
            )

            # test the supported
            for _alg in ("sha1", "sha256", "md5"):
                _fingerprint = cert_utils.fingerprint_cert(
                    cert_pem=cert_pem,
                    cert_pem_filepath=cert_pem_filepath,
                    algorithm=_alg,
                )
                self.assertEqual(
                    _fingerprint, self._cert_sets[cert_set]["cert.fingerprints"][_alg]
                )

            # test unsupported
            with self.assertRaises(ValueError) as cm:
                _fingerprint = cert_utils.fingerprint_cert(
                    cert_pem=cert_pem,
                    cert_pem_filepath=cert_pem_filepath,
                    algorithm="fake",
                )
            self.assertTrue(
                cm.exception.args[0].startswith("algorithm `fake` not in `('")
            )

    def test__parse_csr_domains(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__parse_csr_domains
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
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__validate_csr
        """

        for cert_set in sorted(self._cert_sets.keys()):
            csr_filename = "unit_tests/cert_%s/csr.pem" % cert_set
            csr_pem_filepath = self._filepath_testfile(csr_filename)
            csr_pem = self._filedata_testfile(csr_filename)
            cert_utils.validate_csr(csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath)

    def test__validate_key(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__validate_key
        """

        for cert_set in sorted(self._cert_sets.keys()):
            key_filename = "unit_tests/cert_%s/privkey.pem" % cert_set
            key_pem_filepath = self._filepath_testfile(key_filename)
            key_pem = self._filedata_testfile(key_filename)
            key_technology = cert_utils.validate_key(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )

        for key_filename in sorted(KEY_SETS.keys()):
            key_pem_filepath = self._filepath_testfile(key_filename)
            key_pem = self._filedata_testfile(key_filename)
            key_technology = cert_utils.validate_key(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )
            self.assertEqual(key_technology, KEY_SETS[key_filename]["key_technology"])

    def test__validate_cert(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__validate_cert
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
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__make_csr
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
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__modulus_md5_key
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

        for key_filename in sorted(KEY_SETS.keys()):
            key_pem_filepath = self._filepath_testfile(key_filename)
            key_pem = self._filedata_testfile(key_filename)
            modulus_md5 = cert_utils.modulus_md5_key(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )
            self.assertEqual(modulus_md5, KEY_SETS[key_filename]["modulus_md5"])

    def test__modulus_md5_csr(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__modulus_md5_csr
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

        # csr sets
        for csr_filename in sorted(CSR_SETS.keys()):
            csr_pem_filepath = self._filepath_testfile(csr_filename)
            csr_pem = self._filedata_testfile(csr_filename)
            modulus_md5 = cert_utils.modulus_md5_csr(
                csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath
            )
            if modulus_md5 is None:
                # TODO: no way of testing this in Pure-python right now
                if self.__class__ == UnitTest_CertUtils:
                    continue
            self.assertEqual(modulus_md5, CSR_SETS[csr_filename]["modulus_md5"])

    def test__modulus_md5_cert(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__modulus_md5_cert
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

        # ca certs
        for cert_filename in sorted(CERT_CA_SETS.keys()):
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)
            modulus_md5 = cert_utils.modulus_md5_cert(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
            )
            self.assertEqual(modulus_md5, CERT_CA_SETS[cert_filename]["modulus_md5"])

    def test__parse_cert__enddate(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__parse_cert__enddate
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
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__parse_cert__startdate
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

    def test__parse_cert(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__parse_cert
        python -m unittest tests.test_unit.UnitTest_CertUtils_fallback.test__parse_cert

        This UnitTest tests the following functions:

            * cert_utils.parse_cert
            * cert_utils.parse_cert__spki_sha256
            * cert_utils.parse_cert__key_technology

        These are run on Signed and CA Certificates
            self._cert_sets
            CERT_CA_SETS
        """

        # normal certs
        for cert_set in sorted(self._cert_sets.keys()):
            if not self._cert_sets[cert_set]["cert"]:
                continue
            cert_filename = "unit_tests/cert_%s/cert.pem" % cert_set
            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)

            # `cert_utils.parse_cert`
            rval = cert_utils.parse_cert(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
            )
            self.assertEqual(
                rval["fingerprint_sha1"],
                self._cert_sets[cert_set]["cert.fingerprints"]["sha1"],
            )
            self.assertEqual(
                rval["spki_sha256"], self._cert_sets[cert_set]["spki_sha256"]
            )
            self.assertEqual(
                rval["issuer_uri"], self._cert_sets[cert_set]["cert.issuer_uri"]
            )
            self.assertEqual(
                rval["authority_key_identifier"],
                self._cert_sets[cert_set]["cert.authority_key_identifier"],
            )

            # `cert_utils.parse_cert__spki_sha256`
            spki_sha256 = cert_utils.parse_cert__spki_sha256(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
            )
            self.assertEqual(spki_sha256, self._cert_sets[cert_set]["spki_sha256"])

            # `cert_utils.parse_cert__key_technology`
            key_technology = cert_utils.parse_cert__key_technology(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
            )
            self.assertEqual(
                key_technology, self._cert_sets[cert_set]["key_technology"]
            )

        # ca certs
        for cert_filename in sorted(CERT_CA_SETS.keys()):

            cert_pem_filepath = self._filepath_testfile(cert_filename)
            cert_pem = self._filedata_testfile(cert_filename)

            # `cert_utils.parse_cert`
            rval = cert_utils.parse_cert(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
            )
            for field in (
                "key_technology",
                "issuer",
                "subject",
                "issuer_uri",
                "authority_key_identifier",
            ):
                self.assertEqual(rval[field], CERT_CA_SETS[cert_filename][field])
            self.assertEqual(
                rval["fingerprint_sha1"],
                CERT_CA_SETS[cert_filename]["cert.fingerprints"]["sha1"],
            )

            # `cert_utils.parse_cert__spki_sha256`
            spki_sha256 = cert_utils.parse_cert__spki_sha256(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
            )
            self.assertEqual(spki_sha256, CERT_CA_SETS[cert_filename]["spki_sha256"])

            # `cert_utils.parse_cert__key_technology`
            key_technology = cert_utils.parse_cert__key_technology(
                cert_pem=cert_pem, cert_pem_filepath=cert_pem_filepath
            )
            self.assertEqual(
                key_technology, CERT_CA_SETS[cert_filename]["key_technology"]
            )

    def test__parse_csr(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__parse_csr

        This UnitTest tests the following functions:

            * cert_utils.parse_csr
            * cert_utils.parse_csr__spki_sha256
            * cert_utils.parse_csr__key_technology

        These are run on Signed and CA Certificates
            self._cert_sets
            CERT_CA_SETS
        """

        # normal certs
        for cert_set in sorted(self._cert_sets.keys()):
            if not self._cert_sets[cert_set]["csr"]:
                raise ValueError("missing csr!")
            csr_filename = "unit_tests/cert_%s/csr.pem" % cert_set
            csr_pem_filepath = self._filepath_testfile(csr_filename)
            csr_pem = self._filedata_testfile(csr_filename)

            # `cert_utils.parse_csr`
            rval = cert_utils.parse_csr(
                csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath
            )
            self.assertEqual(
                rval["key_technology"],
                self._cert_sets[cert_set]["key_technology"],
            )
            self.assertEqual(
                rval["spki_sha256"], self._cert_sets[cert_set]["spki_sha256"]
            )
            self.assertEqual(
                rval["subject"],
                self._cert_sets[cert_set]["csr.subject"],
            )
            self.assertEqual(
                rval["SubjectAlternativeName"],
                self._cert_sets[cert_set]["csr.domains.san"],
            )

            # `cert_utils.parse_csr__spki_sha256`
            spki_sha256 = cert_utils.parse_csr__spki_sha256(
                csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath
            )
            self.assertEqual(spki_sha256, self._cert_sets[cert_set]["spki_sha256"])

            # `cert_utils.parse_csr__key_technology`
            key_technology = cert_utils.parse_csr__key_technology(
                csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath
            )
            self.assertEqual(
                key_technology, self._cert_sets[cert_set]["key_technology"]
            )

        # extended csr
        for csr_set in sorted(self._csr_sets_alt.keys()):
            if not self._csr_sets_alt[csr_set]["csr"]:
                raise ValueError("missing csr!")
            csr_filename = "%s/%s" % (
                self._csr_sets_alt[csr_set]["directory"],
                self._csr_sets_alt[csr_set]["file.csr"],
            )
            csr_pem_filepath = self._filepath_testfile(csr_filename)
            csr_pem = self._filedata_testfile(csr_filename)

            # `cert_utils.parse_csr`
            rval = cert_utils.parse_csr(
                csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath
            )
            self.assertEqual(
                rval["key_technology"],
                self._csr_sets_alt[csr_set]["key_technology"],
            )
            self.assertEqual(
                rval["spki_sha256"], self._csr_sets_alt[csr_set]["spki_sha256"]
            )
            self.assertEqual(
                rval["subject"],
                self._csr_sets_alt[csr_set]["csr.subject"],
            )
            self.assertEqual(
                rval["SubjectAlternativeName"],
                self._csr_sets_alt[csr_set]["csr.domains.san"],
            )

            # `cert_utils.parse_csr__spki_sha256`
            spki_sha256 = cert_utils.parse_csr__spki_sha256(
                csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath
            )
            self.assertEqual(spki_sha256, self._csr_sets_alt[csr_set]["spki_sha256"])

            # `cert_utils.parse_csr__key_technology`
            key_technology = cert_utils.parse_csr__key_technology(
                csr_pem=csr_pem, csr_pem_filepath=csr_pem_filepath
            )
            self.assertEqual(
                key_technology, self._csr_sets_alt[csr_set]["key_technology"]
            )

    def test__parse_key(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__parse_key
        python -m unittest tests.test_unit.UnitTest_CertUtils_fallback.test__parse_key

        This is a debugging display function. The output is not guaranteed across installations.

        This UnitTest tests the following functions:

            * cert_utils.parse_key
            * cert_utils.parse_key__spki_sha256
            * cert_utils.parse_key__technology
        """

        for cert_set in sorted(self._cert_sets.keys()):
            key_filename = "unit_tests/cert_%s/privkey.pem" % cert_set
            key_pem_filepath = self._filepath_testfile(key_filename)
            key_pem = self._filedata_testfile(key_filename)

            # `cert_utils.parse_key`
            rval = cert_utils.parse_key(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )
            self.assertEqual(
                rval["key_technology"], self._cert_sets[cert_set]["key_technology"]
            )
            self.assertEqual(
                rval["modulus_md5"], self._cert_sets[cert_set]["pubkey_modulus_md5"]
            )
            self.assertEqual(
                rval["spki_sha256"], self._cert_sets[cert_set]["spki_sha256"]
            )

            # `cert_utils.parse_key__spki_sha256`
            spki_sha256 = cert_utils.parse_key__spki_sha256(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )
            self.assertEqual(spki_sha256, self._cert_sets[cert_set]["spki_sha256"])

            # `cert_utils.parse_key__technology`
            key_technology = cert_utils.parse_key__technology(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )
            self.assertEqual(
                key_technology, self._cert_sets[cert_set]["key_technology"]
            )

        # this will test against EC+RSA
        for key_filename in sorted(KEY_SETS.keys()):
            key_pem_filepath = self._filepath_testfile(key_filename)
            key_pem = self._filedata_testfile(key_filename)

            # `cert_utils.parse_key`
            rval = cert_utils.parse_key(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )
            self.assertEqual(
                rval["key_technology"], KEY_SETS[key_filename]["key_technology"]
            )
            self.assertEqual(rval["modulus_md5"], KEY_SETS[key_filename]["modulus_md5"])
            self.assertEqual(rval["spki_sha256"], KEY_SETS[key_filename]["spki_sha256"])

            # `cert_utils.parse_key__spki_sha256`
            spki_sha256 = cert_utils.parse_key__spki_sha256(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )
            self.assertEqual(spki_sha256, KEY_SETS[key_filename]["spki_sha256"])

            # `cert_utils.parse_key__technology`
            key_technology = cert_utils.parse_key__technology(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )
            self.assertEqual(key_technology, KEY_SETS[key_filename]["key_technology"])

    def test__cert_and_chain_from_fullchain(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__cert_and_chain_from_fullchain
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

    def test_analyze_chains(self):
        """
        This tests:
        * cert_utils.cert_and_chain_from_fullchain
        * cert_utils.decompose_chain
        * cert_utils.ensure_chain
        """
        # test long chains
        long_chain_tests = [
            "TestA",
        ]
        for _test_id in long_chain_tests:
            _test_dir = "long_chains/%s" % _test_id
            _test_data_filename = "%s/_data.json" % _test_dir
            _test_data_filepath = self._filepath_testfile(_test_data_filename)
            _test_data = self._filedata_testfile(_test_data_filepath)
            _test_data = json.loads(_test_data)
            count_roots = _test_data["roots"]
            count_intermediates = _test_data["intermediates"]

            cert_filename = "%s/cert.pem" % _test_dir
            cert_pem = self._filedata_testfile(cert_filename)

            test_pems = {}
            for i in range(0, count_roots):
                root_filename = "%s/root_%s.pem" % (_test_dir, i)
                root_pem_filepath = self._filepath_testfile(root_filename)
                root_pem = self._filedata_testfile(root_pem_filepath)

                chain_filename = "%s/chain_%s.pem" % (_test_dir, i)
                chain_pem_filepath = self._filepath_testfile(chain_filename)
                chain_pem = self._filedata_testfile(chain_pem_filepath)

                test_pems[i] = {"root": root_pem, "chain": chain_pem}

            for idx in test_pems:
                # create a fullchain
                # cert_pem ends in a "\n"
                fullchain_pem = cert_pem + test_pems[idx]["chain"]

                # decompose a fullchain
                (_cert, _chain) = cert_utils.cert_and_chain_from_fullchain(
                    fullchain_pem
                )
                self.assertEqual(_cert, cert_pem)
                self.assertEqual(_chain, test_pems[idx]["chain"])

                _upstream_certs = cert_utils.decompose_chain(_chain)
                self.assertEqual(len(_upstream_certs), count_intermediates)

                _all_certs = cert_utils.decompose_chain(fullchain_pem)
                self.assertEqual(len(_all_certs), count_intermediates + 1)

                # `ensure_chain` can accept two types of data
                root_pem = test_pems[idx]["root"]
                self.assertTrue(
                    cert_utils.ensure_chain(
                        root_pem=root_pem, chain_pem=_chain, cert_pem=cert_pem
                    )
                )
                self.assertTrue(
                    cert_utils.ensure_chain(
                        root_pem=root_pem, fullchain_pem=fullchain_pem
                    )
                )

                # `ensure_chain` will not accept user error
                # fullchain error
                _error_expected = "If `ensure_chain` is invoked with `fullchain_pem`, do not pass in `chain_pem` or `cert_pem`."
                # invoking `fullchain_pem` with: `chain_pem`
                with self.assertRaises(ValueError) as cm:
                    result = cert_utils.ensure_chain(
                        root_pem=root_pem, fullchain_pem=fullchain_pem, chain_pem=_chain
                    )
                self.assertEqual(cm.exception.args[0], _error_expected)
                # invoking `fullchain_pem` with: `cert_pem`
                with self.assertRaises(ValueError) as cm:
                    result = cert_utils.ensure_chain(
                        root_pem=root_pem,
                        fullchain_pem=fullchain_pem,
                        cert_pem=cert_pem,
                    )
                self.assertEqual(cm.exception.args[0], _error_expected)
                # invoking `fullchain_pem` with: `cert_pem` and `chain_pem`
                with self.assertRaises(ValueError) as cm:
                    result = cert_utils.ensure_chain(
                        root_pem=root_pem,
                        fullchain_pem=fullchain_pem,
                        chain_pem=_chain,
                        cert_pem=cert_pem,
                    )
                self.assertEqual(cm.exception.args[0], _error_expected)
                # NO fullchain error
                _error_expected = "If `ensure_chain` is not invoked with `fullchain_pem`, you must pass in `chain_pem` and `cert_pem`."
                # invoking NO `fullchain_pem` with: `chain_pem`
                with self.assertRaises(ValueError) as cm:
                    result = cert_utils.ensure_chain(
                        root_pem=root_pem, chain_pem=_chain
                    )
                self.assertEqual(cm.exception.args[0], _error_expected)
                # invoking NO `fullchain_pem` with: `cert_pem`
                with self.assertRaises(ValueError) as cm:
                    result = cert_utils.ensure_chain(
                        root_pem=root_pem, cert_pem=cert_pem
                    )


def parse_cert__spki_sha256(
    cert_pem=None,
    cert_pem_filepath=None,
    cryptography_cert=None,
    key_technology=None,
):
    def test__convert_lejson_to_pem(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__convert_lejson_to_pem
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
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__account_key__parse
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
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__account_key__sign
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

    def test__private_key__new(self):
        """
        python -m unittest tests.test_unit.UnitTest_CertUtils.test__private_key__new
        """
        _combinations = (
            (model_utils.KeyTechnology.RSA, 2048, None),
            (model_utils.KeyTechnology.RSA, 3072, None),
            (model_utils.KeyTechnology.RSA, 4096, None),
            (model_utils.KeyTechnology.EC, None, 256),
            (model_utils.KeyTechnology.EC, None, 384),
        )
        for _combo in _combinations:
            key_pem = cert_utils.new_private_key(
                _combo[0], rsa_bits=_combo[1], ec_bits=_combo[2]
            )
            if _combo[0] == model_utils.KeyTechnology.RSA:
                # crypto: -----BEGIN PRIVATE KEY-----
                # openssl fallback: -----BEGIN RSA PRIVATE KEY-----
                self.assertIn(
                    key_pem.split("\n")[0],
                    (
                        "-----BEGIN RSA PRIVATE KEY-----",
                        "-----BEGIN PRIVATE KEY-----",
                    ),
                )
            elif _combo[0] == model_utils.KeyTechnology.RSA:
                self.assertEqual(
                    "-----BEGIN EC PRIVATE KEY-----", key_pem.split("\n")[0]
                )


class UnitTest_OpenSSL(unittest.TestCase, _Mixin_filedata):
    """python -m unittest tests.test_unit.UnitTest_OpenSSL"""

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

        # this will test against EC+RSA
        for key_filename in sorted(KEY_SETS.keys()):
            key_pem_filepath = self._filepath_testfile(key_filename)
            key_pem = self._filedata_testfile(key_filename)
            _computed_modulus_md5 = cert_utils.modulus_md5_key(
                key_pem=key_pem, key_pem_filepath=key_pem_filepath
            )
            _expected_modulus_md5 = KEY_SETS[key_filename]["modulus_md5"]
            assert _computed_modulus_md5 == _expected_modulus_md5


class UnitTest_CertUtils_fallback(_MixinNoCrypto, UnitTest_CertUtils):
    """python -m unittest tests.test_unit.UnitTest_CertUtils_fallback"""

    pass


class UnitTest_OpenSSL_fallback(_MixinNoCrypto, UnitTest_OpenSSL):
    """python -m unittest tests.test_unit.UnitTest_OpenSSL_fallback"""

    pass


class UnitTest_PrivateKeyCycling(AppTest, _MixIn_AcmeAccount):
    """
    uses `AppTest` so we have access to a `self.ctx`

    These tests ensure that PrivateKey cycling for an AcmeAccount works

    It tests `getcreate__PrivateKey_for_AcmeAccount`, which is invoked during AcmeOrder processing

    python -m unittest tests.test_unit.UnitTest_PrivateKeyCycling
    """

    def test__single_certificate(self):
        """
        auto-generate a new key for an account
        """
        dbAcmeAccount = self._makeOne_AcmeAccount(
            private_key_cycle="single_certificate", existing_account_key=True
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
        self.assertEqual(dbPrivateKey_1.private_key_type, "single_certificate")
        self.assertEqual(dbPrivateKey_2.acme_account_id__owner, dbAcmeAccount.id)
        self.assertEqual(dbPrivateKey_2.private_key_source, "generated")
        self.assertEqual(dbPrivateKey_2.private_key_type, "single_certificate")

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

    def _test__single_certificate(self, private_key_technology=None):
        """
        auto-generate a new key for an account
        """
        private_key_technology_expected = (
            private_key_technology or model_utils.KeyTechnology._DEFAULT_AcmeAccount
        )
        dbAcmeAccount = self._makeOne_AcmeAccount(
            private_key_cycle="single_certificate",
            private_key_technology=private_key_technology,
            existing_account_key=False,
            contact="single_certificate-%s-%s@example.com"
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
        self.assertEqual(dbPrivateKey_1.private_key_type, "single_certificate")
        self.assertEqual(dbPrivateKey_2.acme_account_id__owner, dbAcmeAccount.id)
        self.assertEqual(dbPrivateKey_2.private_key_source, "generated")
        self.assertEqual(dbPrivateKey_2.private_key_type, "single_certificate")

    def test__key_technology__none(self):
        """
        python -m unittest tests.test_unit.UnitTest_PrivateKeyCycling_KeyTechnology.test__key_technology__none
        """
        self._test__single_certificate(
            private_key_technology=None,
        )

    def test__key_technology__rsa(self):
        self._test__single_certificate(
            private_key_technology="RSA",
        )

    def test__key_technology__ec(self):
        self._test__single_certificate(
            private_key_technology="EC",
        )


class _MockedFP(object):
    """
    used to mock some objects for tests
    this does nothing but avoid errors!
    """

    def read(self):
        return ""

    def readline(self):
        return ""

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

        message_1 = http_client.HTTPResponse(test.test_httplib.FakeSocket(body_1))
        message_1.begin()

        message_2 = http_client.HTTPResponse(test.test_httplib.FakeSocket(body_2))
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
        message_1 = addinfourl(fp, message_1.msg, "")
        message_2 = addinfourl(fp, message_2.msg, "")

        message_1_alts = acme_v2.get_header_links(message_1.headers, "alternate")
        assert len(message_1_alts) == 0

        message_2_alts = acme_v2.get_header_links(message_2.headers, "alternate")
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

        seen = {
            "url_pem": [],
            "display_name": [],
        }
        for (cert_id, cert_payload) in letsencrypt_info.CERT_CAS_DATA.items():

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
