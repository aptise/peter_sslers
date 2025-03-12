# stdlib
import json
import logging
import os
import subprocess
import time
import unittest

# pypi
import psutil

# local
from ._utils import AppTest
from ._utils import GLOBAL_appsettings
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
# we set this env var to invoke with psutil
# the scripts also import a package to disable
# some random packages are very hard to disable

COMMANDLINE_ENV = os.environ.copy()
COMMANDLINE_ENV["PYTHONWARNINGS"] = "ignore"
COMMANDLINE_ENV["DISABLE_WARNINGS_COMMANDLINE"] = "1"

# ==============================================================================

log = logging.getLogger()

# ------------------------------------------------------------------------------


class AAA_TestingSetup(AppTest):
    """
    This testclass exists to leverage the database setup routines in AppTest
    for CI environments.

    `AAA_TestingSetup` will run before anything else in this package.
    Although `test_passes` does nothing itself, it will cause `AppTest.setUp`
    to run, which will create the sqlite3 database that is necessary for these
    tests.

    If this does not run first, the CI environment can get jammed.
    """

    def test_passes(self):
        pass


class Test_CommandlineScripts(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        sqlite_fpath = os.path.normpath(
            GLOBAL_appsettings.get("sqlalchemy.url", "").replace("sqlite:///", "")
        )
        if os.path.exists(sqlite_fpath):
            # if the db exists, no work to do
            return
        try:
            with psutil.Popen(
                ["initialize_peter_sslers_db", TEST_INI],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=COMMANDLINE_ENV,
            ) as proc:
                log.info("Wait 5 seconds...")
                time.sleep(5)
                response, err = proc.communicate()
                if False:
                    print(response)
                    print(err)
                try:
                    proc.terminate()
                except psutil.NoSuchProcess:
                    pass
                if err:
                    raise ValueError("Exception", err)
        except Exception as exc:  # noqa: F841
            raise

    @unittest.skip("TODO")
    def test__import_certbot(self):
        pass

    def test__initialize_db(self):
        # if the sqlitedb exits, move it to an archived name
        # then move it back in the finally block
        try:
            sqlite_fpath = os.path.normpath(
                GLOBAL_appsettings.get("sqlalchemy.url", "").replace("sqlite:///", "")
            )
            fpath_exists = os.path.exists(sqlite_fpath)
            fpath_archived = "%s-initdb" % sqlite_fpath
            if fpath_exists:
                os.rename(sqlite_fpath, fpath_archived)
            try:
                with psutil.Popen(
                    ["initialize_peter_sslers_db", TEST_INI],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=COMMANDLINE_ENV,
                ) as proc:
                    log.info("Wait 5 seconds...")
                    time.sleep(5)
                    response, err = proc.communicate()
                    if False:
                        print(response)
                        print(err)
                    try:
                        proc.terminate()
                    except psutil.NoSuchProcess:
                        pass
                    if err:
                        raise ValueError("Exception", err)
            except Exception as exc:  # noqa: F841
                raise
        finally:
            if fpath_exists:
                os.unlink(sqlite_fpath)
                os.rename(fpath_archived, sqlite_fpath)

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @under_pebble_alt
    def test__routine__automatic_orders(self):
        # TODO: setup so we actually run orders
        try:
            with psutil.Popen(
                ["routine__automatic_orders", TEST_INI],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=COMMANDLINE_ENV,
            ) as proc:
                log.info("Wait 5 seconds...")
                time.sleep(5)
                response, err = proc.communicate()
                if False:
                    print(response)
                    print(err)
                try:
                    proc.terminate()
                except psutil.NoSuchProcess:
                    pass
                if err:
                    raise ValueError("Exception", err)
        except Exception as exc:  # noqa: F841
            raise

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
                env=COMMANDLINE_ENV,
            ) as proc:
                log.info("Wait 5 seconds...")
                time.sleep(5)
                response, err = proc.communicate()
                if False:
                    print(response)
                    print(err)
                try:
                    proc.terminate()
                except psutil.NoSuchProcess:
                    pass
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
                env=COMMANDLINE_ENV,
            ) as proc:
                log.info("Wait 5 seconds...")
                time.sleep(5)
                response, err = proc.communicate()
                try:
                    proc.terminate()
                except psutil.NoSuchProcess:
                    pass
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
                env=COMMANDLINE_ENV,
            ) as proc:
                log.info("Wait 5 seconds...")
                time.sleep(5)
                response, err = proc.communicate()
                try:
                    proc.terminate()
                except psutil.NoSuchProcess:
                    pass
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
                env=COMMANDLINE_ENV,
            ) as proc:
                log.info("Wait 5 seconds...")
                time.sleep(5)
                response, err = proc.communicate()
                try:
                    proc.terminate()
                except psutil.NoSuchProcess:
                    pass
                if err:
                    if b"Error" in err:
                        raise ValueError("Exception", err)

        except Exception as exc:  # noqa: F841
            raise

    @unittest.skipUnless(RUN_API_TESTS__PEBBLE, "Not Running Against: Pebble API")
    @under_pebble
    @under_pebble_alt
    def test__routine__run_ari_checks(self):
        # TODO: check the db state before and after
        try:
            with psutil.Popen(
                [
                    "routine__run_ari_checks",
                    TEST_INI,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=COMMANDLINE_ENV,
            ) as proc:
                log.info("Wait 5 seconds...")
                time.sleep(5)
                response, err = proc.communicate()
                try:
                    proc.terminate()
                except psutil.NoSuchProcess:
                    pass
                if err:
                    if b"Error" in err:
                        raise ValueError("Exception", err)

        except Exception as exc:  # noqa: F841
            raise
