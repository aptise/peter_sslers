# stdlib
import logging
import json
import os
import subprocess
import time
import unittest

# pypi
import psutil

# local
from ._utils import RUN_API_TESTS__PEBBLE
from ._utils import TEST_INI
from ._utils import under_pebble
from ._utils import under_pebble_alt

# import cert_utils
# from peter_sslers.lib import acme_v2
# from ._utils import AppTest

# ==============================================================================
#
# essentially disable logging for tests
#

log = logging.getLogger()
log.addHandler(logging.StreamHandler())
log.setLevel(logging.CRITICAL)

# ==============================================================================

# ------------------------------------------------------------------------------


class Test_CommandlineScripts(unittest.TestCase):

    @unittest.skip("TODO")
    def test__import_certbot(self):
        pass

    @unittest.skip("TODO")
    def test__initializedb(self):
        pass

    @unittest.skip("TODO")
    def test__routine__renew_expiring(self):
        pass

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @under_pebble_alt
    def test__refresh_pebble_ca_certs(self):
        try:
            with psutil.Popen(
                ["refresh_pebble_ca_certs", TEST_INI],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as proc:
                log.info("Wait 5 seconds...")
                time.sleep(5)
                response, err = proc.communicate()
                if False:
                    print(response)
                    print(err)
                if err:
                    raise ValueError("Exception", err)
        except Exception as exc:  # noqa: F841
            raise

    def test__register_acme_servers(self):
        _export_path = "_data_/_EXPORTED_ACME_SERVERS.json"
        try:
            with psutil.Popen(
                [
                    "register_acme_servers",
                    TEST_INI,
                    "export",
                    _export_path,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as proc:
                log.info("Wait 5 seconds...")
                time.sleep(5)
                response, err = proc.communicate()
                if err:
                    raise ValueError("Exception", err)

            if not os.path.exists(_export_path):
                raise ValueError("Exports file not created")

            # ensure we can read it
            with open(_export_path, "r") as fh:
                from_json = json.loads(fh.read())
                assert from_json

            # roundtrip
            with psutil.Popen(
                [
                    "register_acme_servers",
                    TEST_INI,
                    "register",
                    _export_path,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as proc:
                log.info("Wait 5 seconds...")
                time.sleep(5)
                response, err = proc.communicate()
                if err:
                    raise ValueError("Exception", err)

        except Exception as exc:  # noqa: F841
            raise
        finally:
            if os.path.exists(_export_path):
                os.unlink(_export_path)

    def test__routine__clear_old_ari_checks(self):
        try:
            with psutil.Popen(
                [
                    "routine__clear_old_ari_checks",
                    TEST_INI,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as proc:
                log.info("Wait 5 seconds...")
                time.sleep(5)
                response, err = proc.communicate()
                if err:
                    if "Error" in err:
                        raise ValueError("Exception", err)

        except Exception as exc:  # noqa: F841
            raise

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @under_pebble_alt
    def test__routine__run_ari_checks(self):
        # TODO: check the db state before and after
        # TODO: logged data goes to err, so we always out something here - ugh
        try:
            with psutil.Popen(
                [
                    "routine__run_ari_checks",
                    TEST_INI,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as proc:
                log.info("Wait 5 seconds...")
                time.sleep(5)
                response, err = proc.communicate()
                if err:
                    if "Error" in err:
                        raise ValueError("Exception", err)

        except Exception as exc:  # noqa: F841
            raise
