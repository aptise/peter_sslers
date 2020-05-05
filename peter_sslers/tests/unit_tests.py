from __future__ import print_function


from ._utils import AppTestCore
from ._utils import TEST_FILES
from ..lib import cert_utils
from ..lib import utils


# ==============================================================================


class UnitTestOpenSSL(AppTestCore):
    """python -m unittest peter_sslers.tests.UnitTestOpenSSL"""

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
