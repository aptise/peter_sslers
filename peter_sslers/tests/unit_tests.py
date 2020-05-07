from __future__ import print_function

# stdlib
import pdb

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


class UnitTest_OpenSSL(AppTestCore):
    """python -m unittest peter_sslers.tests.unit_tests.UnitTest_OpenSSL"""

    def test_modulus_PrivateKey(self):
        for pkey_set_id, set_data in TEST_FILES["PrivateKey"].items():
            pem_filepath = self._filepath_testfile(set_data["file"])
            _computed_modulus_md5 = cert_utils.modulus_md5_key__pem_filepath(
                pem_filepath
            )
            _expected_modulus_md5 = set_data["key_pem_modulus_md5"]
            assert _computed_modulus_md5 == _expected_modulus_md5
            _computed_md5 = utils.md5_text(self._filedata_testfile(pem_filepath))
            _expected_md5 = set_data["key_pem_md5"]
            assert _computed_md5 == _expected_md5


class UnitTest_PrivateKeyCycling(AppTest):
    """
    uses `AppTest` so we have access to a `self.ctx`
    
    These tests ensure that PrivateKey cycling for an AcmeAccountKey works 
    
    It tests `getcreate__PrivateKey_for_AcmeAccountKey`, which is invoked during AcmeOrder processing
    
    python -m unittest peter_sslers.tests.unit_tests.UnitTest_PrivateKeyCycling
    """

    def _makeOne_AcmeAccountKey(self, private_key_cycle):
        """
        create a new AcmeAccountKey with a given private_key_cycle
        """
        contact = "%s@example.com" % private_key_cycle
        _key_filename = "AcmeAccountKey-cycle-%s.pem" % private_key_cycle
        key_pem = self._filedata_testfile(_key_filename)
        (dbAcmeAccountKey, _is_created) = lib_db_getcreate.getcreate__AcmeAccountKey(
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
        return dbAcmeAccountKey

    def test__single_certificate(self):
        dbAcmeAccountKey = self._makeOne_AcmeAccountKey("single_certificate")
        dbPrivateKey_1 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccountKey(
            self.ctx, dbAcmeAccountKey=dbAcmeAccountKey,
        )
        dbPrivateKey_2 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccountKey(
            self.ctx, dbAcmeAccountKey=dbAcmeAccountKey,
        )
        assert dbPrivateKey_1.id != dbPrivateKey_2.id
        assert dbPrivateKey_1.acme_account_key_id__owner == dbAcmeAccountKey.id
        assert dbPrivateKey_1.private_key_source == "generated"
        assert dbPrivateKey_1.private_key_type == "single_certificate"

        assert dbPrivateKey_2.acme_account_key_id__owner == dbAcmeAccountKey.id
        assert dbPrivateKey_2.private_key_source == "generated"
        assert dbPrivateKey_2.private_key_type == "single_certificate"

    def test__account_weekly(self):
        dbAcmeAccountKey = self._makeOne_AcmeAccountKey("account_weekly")
        dbPrivateKey_1 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccountKey(
            self.ctx, dbAcmeAccountKey=dbAcmeAccountKey,
        )
        dbPrivateKey_2 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccountKey(
            self.ctx, dbAcmeAccountKey=dbAcmeAccountKey,
        )
        assert dbPrivateKey_1.id == dbPrivateKey_2.id
        assert dbPrivateKey_1.acme_account_key_id__owner == dbAcmeAccountKey.id
        assert dbPrivateKey_1.private_key_source == "generated"
        assert dbPrivateKey_1.private_key_type == "account_weekly"

    def test__account_daily(self):
        dbAcmeAccountKey = self._makeOne_AcmeAccountKey("account_daily")
        dbPrivateKey_1 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccountKey(
            self.ctx, dbAcmeAccountKey=dbAcmeAccountKey,
        )
        dbPrivateKey_2 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccountKey(
            self.ctx, dbAcmeAccountKey=dbAcmeAccountKey,
        )
        assert dbPrivateKey_1.id == dbPrivateKey_2.id
        assert dbPrivateKey_1.acme_account_key_id__owner == dbAcmeAccountKey.id
        assert dbPrivateKey_1.private_key_source == "generated"
        assert dbPrivateKey_1.private_key_type == "account_daily"

    def test__global_weekly(self):
        dbAcmeAccountKey = self._makeOne_AcmeAccountKey("global_weekly")
        dbPrivateKey_1 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccountKey(
            self.ctx, dbAcmeAccountKey=dbAcmeAccountKey,
        )
        dbPrivateKey_2 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccountKey(
            self.ctx, dbAcmeAccountKey=dbAcmeAccountKey,
        )
        assert dbPrivateKey_1.id == dbPrivateKey_2.id
        assert dbPrivateKey_1.acme_account_key_id__owner is None
        assert dbPrivateKey_1.private_key_source == "generated"
        assert dbPrivateKey_1.private_key_type == "global_weekly"

    def test__global_daily(self):
        dbAcmeAccountKey = self._makeOne_AcmeAccountKey("global_daily")
        dbPrivateKey_1 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccountKey(
            self.ctx, dbAcmeAccountKey=dbAcmeAccountKey,
        )
        dbPrivateKey_2 = lib_db_getcreate.getcreate__PrivateKey_for_AcmeAccountKey(
            self.ctx, dbAcmeAccountKey=dbAcmeAccountKey,
        )
        assert dbPrivateKey_1.id == dbPrivateKey_2.id
        assert dbPrivateKey_1.acme_account_key_id__owner is None
        assert dbPrivateKey_1.private_key_source == "generated"
        assert dbPrivateKey_1.private_key_type == "global_daily"
