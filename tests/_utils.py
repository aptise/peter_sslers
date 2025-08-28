# stdlib
import datetime
from functools import wraps
from io import BufferedWriter
from io import open  # overwrite `open` in Python2
import logging
import os
import pdb  # noqa: F401
import pprint  # noqa: F401
import shutil
import sqlite3
import subprocess
import time
import traceback
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import overload
from typing import Tuple
from typing import TYPE_CHECKING
from typing import Union
import unittest
import uuid
import warnings

# pypi
import cert_utils
from cert_utils import letsencrypt_info
from cert_utils.model import AccountKeyData
import packaging.version
import psutil
from pyramid import testing
from pyramid.paster import get_appsettings
from pyramid.router import Router
import requests
import sqlalchemy
from sqlalchemy.orm import close_all_sessions
from sqlalchemy.orm import Session
import transaction
from typing_extensions import Literal
from webtest import TestApp
from webtest import Upload
from webtest.http import StopableWSGIServer

# local
from peter_sslers.lib import acme_v2
from peter_sslers.lib import db
from peter_sslers.lib import errors
from peter_sslers.lib import errors as lib_errors
from peter_sslers.lib import utils
from peter_sslers.lib.config_utils import ApplicationSettings
from peter_sslers.lib.context import ApiContext
from peter_sslers.lib.db import actions as lib_db_actions
from peter_sslers.lib.db import create as lib_db_create
from peter_sslers.lib.db import get as lib_db_get
from peter_sslers.lib.db import getcreate as lib_db_getcreate
from peter_sslers.lib.db import update as lib_db_update
from peter_sslers.lib.db.update import (
    update_AcmeAccount__account_url,
)
from peter_sslers.lib.db.update import update_AcmeOrder_deactivate
from peter_sslers.lib.db.update import (
    update_AcmeOrder_deactivate_AcmeAuthorizationPotentials,
)
from peter_sslers.lib.exports import relative_symlink
from peter_sslers.model import meta as model_meta
from peter_sslers.model import objects as model_objects
from peter_sslers.model import utils as model_utils
from peter_sslers.web import main
from peter_sslers.web.models import get_engine
from peter_sslers.web.models import get_session_factory
from .regex_library import RE_AcmeOrder

if TYPE_CHECKING:
    from webob import Response

# from peter_sslers.lib.utils import RequestCommandline

# ==============================================================================

log = logging.getLogger()
log.setLevel(logging.INFO)

"""
export SSL_RUN_NGINX_TESTS=1
export SSL_RUN_REDIS_TESTS=1
export SSL_RUN_API_TESTS__PEBBLE=1
export SSL_PEBBLE_API_VALIDATES=1
export SSL_TEST_DOMAINS=dev.cliqued.in
export SSL_TEST_PORT=7201
export SSL_BIN_REDIS_SERVER=/path/to
export SSL_CONF_REDIS_SERVER=/path/to

NOTE: SSL_TEST_DOMAINS can be a comma-separated string


export GOPATH=/path/to/go



If running LetsEncrypt tests: you must specify a domain, and make sure to proxy
port80 of that domain to this app, so LetsEncrypt can access it.

see the nginx test config file `testing.conf`
"""

# run tests that expire nginx caches
RUN_NGINX_TESTS = bool(int(os.environ.get("SSL_RUN_NGINX_TESTS", 0)))
# run tests to prime redis
RUN_REDIS_TESTS = bool(int(os.environ.get("SSL_RUN_REDIS_TESTS", 0)))

# use system redis?
USE_SYSTEM_REDIS = bool(int(os.environ.get("SSL_USE_SYSTEM_REDIS", 0)))

# run tests against LE API
RUN_API_TESTS__PEBBLE = bool(int(os.environ.get("SSL_RUN_API_TESTS__PEBBLE", 0)))
# does the LE validation work?  LE must be able to reach this
LETSENCRYPT_API_VALIDATES = bool(
    int(os.environ.get("SSL_LETSENCRYPT_API_VALIDATES", 0))
)

SSL_TEST_DOMAINS = os.environ.get("SSL_TEST_DOMAINS", "example.com")
SSL_TEST_PORT = int(os.environ.get("SSL_TEST_PORT", 7201))

# coordinate the port with `data_testing/config.ini`
SSL_BIN_REDIS_SERVER = os.environ.get("SSL_BIN_REDIS_SERVER", None) or "redis-server"
SSL_CONF_REDIS_SERVER = os.environ.get("SSL_CONF_REDIS_SERVER", None) or None
if not SSL_CONF_REDIS_SERVER:
    SSL_CONF_REDIS_SERVER = "/".join(
        __file__.split("/")[:-1]
        + [
            "test_configuration",
            "redis-server.conf",
        ]
    )

if not os.path.exists(SSL_CONF_REDIS_SERVER):
    raise ValueError(
        "SSL_CONF_REDIS_SERVER (%s) does not exist" % SSL_CONF_REDIS_SERVER
    )


GOPATH = os.environ.get("GOPATH")
PEBBLE_DIR = "%s/bin" % GOPATH
PEBBLE_BIN = None
PEBBLE_CONFIG_DIR = "/".join(
    __file__.split("/")[:-1]
    + [
        "test_configuration",
        "pebble",
    ]
)
PEBBLE_CONFIG_FILE = "/".join(
    PEBBLE_CONFIG_DIR.split("/")
    + [
        "test",
        "config",
        "pebble-config.json",
    ]
)
PEBBLE_ALT_CONFIG_FILE = "/".join(
    PEBBLE_CONFIG_DIR.split("/")
    + [
        "test-alt",
        "config",
        "pebble-config.json",
    ]
)

ACMEDNS_CONFIG_FILE = "/".join(
    __file__.split("/")[:-1]
    + [
        "test_configuration",
        "acme-dns--local.config",
    ]
)


if RUN_API_TESTS__PEBBLE:
    if not GOPATH:
        raise ValueError("GOPATH not defined in environment")
    if not os.path.exists(PEBBLE_DIR):
        raise ValueError("PEBBLE_DIR (%s) does not exist" % PEBBLE_DIR)
    PEBBLE_BIN = "/".join((PEBBLE_DIR, "pebble"))
    if not os.path.exists(PEBBLE_BIN):
        raise ValueError("PEBBLE_BIN (%s) does not exist" % PEBBLE_BIN)

PEBBLE_ENV = os.environ.copy()
PEBBLE_ENV["PEBBLE_VA_ALWAYS_VALID"] = "1"
PEBBLE_ENV["PEBBLE_VA_NOSLEEP"] = "1"
PEBBLE_ENV["PEBBLE_AUTHZREUSE"] = "100"
PEBBLE_ENV["PEBBLE_ALTERNATE_ROOTS"] = "1"
PEBBLE_ENV["PEBBLE_CHAIN_LENGTH"] = "3"

PEBBLE_ENV_STRICT = os.environ.copy()
PEBBLE_ENV_STRICT["PEBBLE_VA_ALWAYS_VALID"] = "0"
PEBBLE_ENV_STRICT["PEBBLE_AUTHZREUSE"] = "0"
PEBBLE_ENV_STRICT["PEBBLE_VA_NOSLEEP"] = "1"
PEBBLE_ENV_STRICT["PEBBLE_ALTERNATE_ROOTS"] = "1"
PEBBLE_ENV_STRICT["PEBBLE_CHAIN_LENGTH"] = "3"


# run tests against ACME_DNS_API
RUN_API_TESTS__ACME_DNS_API = bool(
    int(os.environ.get("SSL_RUN_API_TESTS__ACME_DNS_API", 0))
)
ACME_DNS_API = os.environ.get("SSL_ACME_DNS_API", "http://127.0.0.1:8011")
ACME_DNS_DOMAIN = os.environ.get("SSL_ACME_DNS_API", "dev.2xlp.com")
ACME_DNS_BINARY = os.environ.get("SSL_ACME_DNS_BINARY", "")
ACME_DNS_CONFIG = os.environ.get("SSL_ACME_DNS_CONFIG", "")

if RUN_API_TESTS__ACME_DNS_API:
    if not any((ACME_DNS_BINARY, ACME_DNS_CONFIG)):
        raise ValueError("Must invoke with env vars for acme-dns services")

RUN_API_TESTS__EXTENDED = bool(int(os.environ.get("SSL_RUN_API_TESTS__EXTENDED", 0)))


OPENRESTY_PLUGIN_MINIMUM_VERSION = "0.5.0"
OPENRESTY_PLUGIN_MINIMUM = packaging.version.parse(OPENRESTY_PLUGIN_MINIMUM_VERSION)


# export this for some better debugging
DEBUG_ACMEORDERS = bool(int(os.environ.get("DEBUG_ACMEORDERS", 0)))
DEBUG_DBFREEZE = bool(int(os.environ.get("DEBUG_DBFREEZE", 0)))
DEBUG_DBFREEZE_ARCHIVE = bool(int(os.environ.get("DEBUG_DBFREEZE_ARCHIVE", 0)))
DEBUG_GITHUB_ENV = bool(int(os.environ.get("DEBUG_GITHUB_ENV", 0)))
DEBUG_METRICS = bool(int(os.environ.get("DEBUG_METRICS", 0)))
DEBUG_PEBBLE_REDIS = bool(int(os.environ.get("DEBUG_PEBBLE_REDIS", 0)))
DEBUG_TESTHARNESS = bool(int(os.environ.get("DEBUG_TESTHARNESS", 0)))


DISABLE_WARNINGS = bool(int(os.environ.get("DISABLE_WARNINGS", 0)))
if DISABLE_WARNINGS:
    warnings.filterwarnings("ignore", category=DeprecationWarning)


# override to "test_local.ini" if needed
TEST_INI = os.environ.get("SSL_TEST_INI", "data_testing/config.ini")
if not os.path.exists("data_testing"):
    os.mkdir("data_testing")
if not os.path.exists("data_testing/config.ini"):
    relative_symlink("tests/test_configuration/config.ini", "data_testing/config.ini")

# copy our nginx pem
if not os.path.exists("data_testing/nginx_ca_bundle.pem"):
    relative_symlink(
        "tests/test_configuration/pebble/test/certs/pebble.minica.pem",
        "data_testing/nginx_ca_bundle.pem",
    )

GLOBAL_appsettings: dict = {}


def intialize_appsettings() -> None:
    global GLOBAL_appsettings
    # This is some fancy footwork to update our settings
    GLOBAL_appsettings = get_appsettings(TEST_INI, name="main")
    GLOBAL_appsettings["config_uri"] = TEST_INI
    cert_utils.update_from_appsettings(GLOBAL_appsettings)


intialize_appsettings()

# SEMAPHORE?
PEBBLE_RUNNING = None
PEBBLE_ALT_RUNNING = None
ACMEDNS_RUNNING = None

# RUN_ID
RUN_START = datetime.datetime.now()
RUN_START_STR = RUN_START.strftime("%Y_%m_%d-%H_%M_%S")


# ==============================================================================

# we don't need this directory if we're not tracking metrics
if DEBUG_PEBBLE_REDIS or DEBUG_METRICS:
    if not os.path.exists("X_TESTRUN_DATA"):
        os.mkdir("X_TESTRUN_DATA")
    DIR_TESTRUN = os.path.join("X_TESTRUN_DATA", RUN_START_STR)
    os.mkdir(DIR_TESTRUN)


if DEBUG_ACMEORDERS:
    # lower noise for debugging

    # silence the ACME api
    import peter_sslers.lib.acme_v2

    peter_sslers.lib.acme_v2.log.setLevel(100)
    peter_sslers.lib.acme_v2.log_api.setLevel(100)

    # silence cert_utils
    cert_utils.log.setLevel(100)


if DEBUG_GITHUB_ENV:
    print("ENV VARS:")
    print("RUN_NGINX_TESTS:", RUN_NGINX_TESTS)
    print("RUN_REDIS_TESTS:", RUN_REDIS_TESTS)
    print("RUN_API_TESTS__PEBBLE:", RUN_API_TESTS__PEBBLE)
    print("LETSENCRYPT_API_VALIDATES:", LETSENCRYPT_API_VALIDATES)
    print("SSL_TEST_DOMAINS:", SSL_TEST_DOMAINS)
    print("SSL_TEST_PORT:", SSL_TEST_PORT)
    print("SSL_BIN_REDIS_SERVER:", SSL_BIN_REDIS_SERVER)
    print("SSL_CONF_REDIS_SERVER:", SSL_CONF_REDIS_SERVER)
    print("PEBBLE_DIR:", PEBBLE_DIR)
    print("PEBBLE_BIN:", PEBBLE_BIN)
    print("PEBBLE_CONFIG_FILE:", PEBBLE_CONFIG_FILE)
    print("PEBBLE_ALT_CONFIG_FILE:", PEBBLE_ALT_CONFIG_FILE)
    print("PEBBLE_ENV:", PEBBLE_ENV)
    print("PEBBLE_ENV_STRICT:", PEBBLE_ENV_STRICT)
    print("RUN_API_TESTS__ACME_DNS_API:", RUN_API_TESTS__ACME_DNS_API)
    print("ACME_DNS_API:", ACME_DNS_API)
    print("ACME_DNS_BINARY:", ACME_DNS_BINARY)
    print("ACME_DNS_CONFIG:", ACME_DNS_CONFIG)
    print("DEBUG_ACMEORDERS:", DEBUG_ACMEORDERS)
    print("DEBUG_TESTHARNESS:", DEBUG_TESTHARNESS)
    print("DEBUG_PEBBLE_REDIS:", DEBUG_PEBBLE_REDIS)
    print("DEBUG_METRICS:", DEBUG_METRICS)
    print("DEBUG_DBFREEZE:", DEBUG_DBFREEZE)
    print("DEBUG_DBFREEZE_ARCHIVE:", DEBUG_DBFREEZE_ARCHIVE)
    print("DISABLE_WARNINGS:", DISABLE_WARNINGS)
    print("TEST_INI:", TEST_INI)


# note: ApplicationSettings can be global
GLOBAL_ApplicationSettings = ApplicationSettings(TEST_INI)
GLOBAL_ApplicationSettings.from_settings_dict(GLOBAL_appsettings)


DEBUG_DATABASE_ODDITY = False


class CustomizedTestCase(unittest.TestCase):
    ctx: ApiContext
    testapp: Union[TestApp, StopableWSGIServer]
    __name__: str
    _filepath_testfile: Callable


def _debug_TestHarness(ctx: ApiContext, name: str) -> None:
    """
    This function was designed to debug some test cases.
    invoke this as the first and last line of each function
    to ensure the `AcmeAauthorizationPotential` are disabled

    see:
         IntegratedTests_AcmeServer_AcmeOrder.setUp
         IntegratedTests_AcmeServer_AcmeOrder.tearDown
    """
    # com
    if not DEBUG_TESTHARNESS:
        return
    print(">>" * 40)
    print("_debug_TestHarness:", name)
    dbAcmeOrders = ctx.dbSession.query(model_objects.AcmeOrder).all()
    for _order in dbAcmeOrders:
        print(
            "AcmeOrder[%s]: `%s` `is_processing=%s`"
            % (
                _order.id,
                _order.acme_status_order,
                _order.is_processing,
            )
        )
        print("\t", _order.domains_as_list)
        for _act in _order.acme_authorization_potentials:
            print("\tAcmeAauthorizationPotential", _act.as_json)
        for _toAuthz in _order.to_acme_authorizations:
            print(
                "\tAcmeAuthorization",
                _toAuthz.acme_authorization_id,
                _toAuthz.acme_authorization.acme_status_authorization,
            )
    print("<<" * 40)


class FakeRequest(testing.DummyRequest):

    @property
    def tm(self) -> transaction.manager:
        return transaction.manager

    admin_url: str = ""


def new_test_connections() -> ApiContext:
    """
    Creates a new ApiContext with a dedicated SQLAlchemy Session
    """
    session_factory = get_session_factory(get_engine(GLOBAL_appsettings))
    request = FakeRequest()
    dbSession = session_factory(info={"request": request})

    ctx = ApiContext(
        request=request,
        dbSession=dbSession,
        config_uri=TEST_INI,
        application_settings=GLOBAL_ApplicationSettings,
    )
    return ctx


def process_pebble_roots(
    port_public: int, port_admin: int, env_name: str
) -> Literal[True]:
    """
    Pebble generates new trusted roots on every run
    We need to load them from the pebble server, otherwise we have no idea
    what they are.
    """
    log.info("`process_pebble_roots(%s)`" % str((port_public, port_admin, env_name)))

    # the first root is guaranteed to be live
    # the additional deployments may or may not be

    _pebble_server_root = "%s/%s/certs/pebble.minica.pem" % (
        PEBBLE_CONFIG_DIR,
        env_name,
    )
    assert os.path.exists(_pebble_server_root)
    r0 = requests.get(
        "https://127.0.0.1:%s/roots/0" % port_admin, verify=_pebble_server_root
    )
    if r0.status_code != 200:
        raise ValueError("Could not load first root")
    root_pems = [
        r0.text,
    ]
    alternates = acme_v2.get_header_links(r0.headers, "alternate")
    if alternates:
        for _alt in alternates:
            _r = requests.get(_alt, verify=_pebble_server_root)
            if _r.status_code != 200:
                raise ValueError("Could not load additional root")
            root_pems.append(_r.text)
    ctx = new_test_connections()
    for _root_pem in root_pems:
        (
            _dbChain,
            _is_created,
        ) = db.getcreate.getcreate__X509CertificateTrusted__by_pem_text(
            ctx, _root_pem, display_name="Detected Pebble Root", is_trusted_root=True
        )
        if _is_created is not True:
            log.critical(
                "Detected a previously encountered Pebble root. "
                "This should not be possible"
            )
    ctx.pyramid_transaction_commit()
    ctx.dbSession.close()
    return True


def archive_pebble_data(
    port_public: int, port_admin: int, env_name: str
) -> Literal[True]:
    """
    pebble account urls have a serial that restarts on each load
    this causes issues with tests
    """
    log.info("`archive_pebble_data(%s)`" % str((port_public, port_admin, env_name)))
    ctx = new_test_connections()
    # model_objects.AcmeAccount
    # migration strategy - append a `@{UUID}` to the url, so it will not match
    dbAcmeAccounts = db.get.get__AcmeAccount__paginated(ctx)
    for _dbAcmeAccount in dbAcmeAccounts:
        if _dbAcmeAccount.account_url:
            if "@" not in _dbAcmeAccount.account_url:
                log.debug(
                    "archive_pebble_data: migrating _dbAcmeAccount %s %s",
                    _dbAcmeAccount.id,
                    _dbAcmeAccount.account_url,
                )
                account_url = _dbAcmeAccount.account_url
                account_url_archive = "%s@%s" % (account_url, uuid.uuid4())
                update_AcmeAccount__account_url(
                    ctx, dbAcmeAccount=_dbAcmeAccount, account_url=account_url_archive
                )
                ctx.dbSession.flush(
                    objects=[
                        _dbAcmeAccount,
                    ]
                )
                log.debug(
                    "archive_pebble_data: migrated _dbAcmeAccount %s %s",
                    _dbAcmeAccount.id,
                    _dbAcmeAccount.account_url,
                )
    ctx.pyramid_transaction_commit()
    ctx.dbSession.close()
    return True


def handle_new_pebble(port_public, port_admin, env_name) -> None:
    """
    When pebble starts:
        * we must inspect the new pebble roots
    When pebble restarts
        * the database may have old pebble data
    """
    log.info("`handle_new_pebble(%s)`" % str((port_public, port_admin, env_name)))
    process_pebble_roots(port_public, port_admin, env_name)
    archive_pebble_data(port_public, port_admin, env_name)


# ACME_CHECK_MSG = b"Listening on: 0.0.0.0:14000"
ACME_CHECK_MSG = b"ACME directory available at: https://0.0.0.0:14000/dir"
ACME_CHECK_MSG_ALT = b"ACME directory available at: https://0.0.0.0:14001/dir"


def under_pebble(_function: Callable) -> Callable:
    """
    decorator to spin up an external pebble server
    """
    global PEBBLE_RUNNING

    @wraps(_function)
    def _wrapper(*args, **kwargs):
        log.info("`pebble`: spinning up for `%s`" % _function.__qualname__)
        log.info("`pebble`: PEBBLE_BIN : %s", PEBBLE_BIN)
        log.info("`pebble`: PEBBLE_CONFIG_FILE : %s", PEBBLE_CONFIG_FILE)
        log.info("`pebble`: PEBBLE_CONFIG_DIR : %s", PEBBLE_CONFIG_DIR)
        # log.info("`pebble`: PEBBLE_ENV : %s", PEBBLE_ENV)
        # after layout updates, changing to the CWD will break this from running
        # due to: tests/test_configuration/pebble/test/certs/localhost/cert.pem
        res = None  # scoping
        stdout: Union[int, BufferedWriter] = subprocess.PIPE
        stderr: Union[int, BufferedWriter] = subprocess.PIPE
        if DEBUG_PEBBLE_REDIS:
            fname = (
                (
                    "%s/%s-pebble.txt"
                    % (
                        DIR_TESTRUN,
                        _function.__qualname__,
                    )
                )
                .replace("<", "_")
                .replace(">", "_")
            )
            if "_locals_._wrapped-" in fname:
                fname = fname.replace("_locals_._wrapped", str(uuid.uuid4()))
            stdout = open(fname, "wb")

        with psutil.Popen(
            [PEBBLE_BIN, "-config", PEBBLE_CONFIG_FILE],
            stdin=subprocess.PIPE,
            stdout=stdout,
            stderr=stderr,
            # cwd=PEBBLE_CONFIG_DIR,
            env=PEBBLE_ENV,
        ) as proc:
            # ensure the `pebble` server is running
            ready = False
            _waits = 0
            while not ready:
                log.info("`pebble`: waiting for ready | %s" % _waits)
                _waits += 1
                if _waits >= 30:
                    raise ValueError("`pebble`: ERROR spinning up")
                if DEBUG_PEBBLE_REDIS:
                    with open(fname, "rb") as fh_read:
                        for line in fh_read.readlines():
                            if ACME_CHECK_MSG in line:
                                log.info("`pebble`: ready")
                                ready = True
                                break
                else:
                    for line in iter(proc.stdout.readline, b""):
                        # if b"Listening on: 0.0.0.0:14000" in line:
                        if ACME_CHECK_MSG in line:
                            log.info("`pebble`: ready")
                            ready = True
                            break
                time.sleep(1)
            try:
                PEBBLE_RUNNING = True
                # catch in app_test so we don't recycle the roots
                handle_new_pebble(14000, 15000, "test")
                res = _function(*args, **kwargs)
            finally:
                # explicitly terminate, otherwise it won't exit
                # in a `finally` to ensure we terminate on exceptions
                log.info("`pebble`: finished. terminating")
                proc.terminate()
                PEBBLE_RUNNING = False
        return res

    return _wrapper


def under_pebble_strict(_function: Callable) -> Callable:
    """
    decorator to spin up an external pebble server
    """
    global PEBBLE_RUNNING

    @wraps(_function)
    def _wrapper(*args, **kwargs):
        log.info("`pebble[strict]`: spinning up for `%s`" % _function.__qualname__)
        log.info("`pebble[strict]`: PEBBLE_BIN : %s", PEBBLE_BIN)
        log.info("`pebble[strict]`: PEBBLE_CONFIG_FILE : %s", PEBBLE_CONFIG_FILE)
        log.info("`pebble[strict]`: PEBBLE_CONFIG_DIR : %s", PEBBLE_CONFIG_DIR)
        # log.info("`pebble[strict]`: PEBBLE_ENV_STRICT : %s", PEBBLE_ENV_STRICT)
        # after layout updates, changing to the CWD will break this from running
        # due to: tests/test_configuration/pebble/test/certs/localhost/cert.pem
        res = None  # scoping
        stdout: Union[int, BufferedWriter] = subprocess.PIPE
        stderr: Union[int, BufferedWriter] = subprocess.PIPE
        if DEBUG_PEBBLE_REDIS:
            fname = (
                (
                    "%s/%s-pebble_strict.txt"
                    % (
                        DIR_TESTRUN,
                        _function.__qualname__,
                    )
                )
                .replace("<", "_")
                .replace(">", "_")
            )
            if "_locals_._wrapped-" in fname:
                fname = fname.replace("_locals_._wrapped", str(uuid.uuid4()))
            stdout = open(fname, "wb")
        with psutil.Popen(
            [PEBBLE_BIN, "-config", PEBBLE_CONFIG_FILE],
            stdin=subprocess.PIPE,
            stdout=stdout,
            stderr=stderr,
            # cwd=PEBBLE_CONFIG_DIR,
            env=PEBBLE_ENV_STRICT,
        ) as proc:
            # ensure the `pebble` server is running
            ready = False
            _waits = 0
            while not ready:
                log.info("`pebble[strict]`: waiting for ready | %s" % _waits)
                _waits += 1
                if _waits >= 30:
                    raise ValueError("`pebble[strict]`: ERROR spinning up")
                if DEBUG_PEBBLE_REDIS:
                    with open(fname, "rb") as fh_read:
                        for line in fh_read.readlines():
                            if ACME_CHECK_MSG in line:
                                log.info("`pebble[strict]`: ready")
                                ready = True
                                break
                else:
                    for line in iter(proc.stdout.readline, b""):
                        if ACME_CHECK_MSG in line:
                            log.info("`pebble[strict]`: ready")
                            ready = True
                            break
                time.sleep(1)
            try:
                PEBBLE_RUNNING = True
                # catch in app_test so we don't recycle the roots
                handle_new_pebble(14000, 15000, "test")
                res = _function(*args, **kwargs)
            finally:
                # explicitly terminate, otherwise it won't exit
                # in a `finally` to ensure we terminate on exceptions
                log.info("`pebble[strict]`: finished. terminating")
                proc.terminate()
                PEBBLE_RUNNING = False
        return res

    return _wrapper


def under_pebble_alt(_function: Callable) -> Callable:
    """
    decorator to spin up an external pebble server
    """
    global PEBBLE_ALT_RUNNING

    @wraps(_function)
    def _wrapper(*args, **kwargs):
        log.info("`pebble[alt]`: spinning up for `%s`" % _function.__qualname__)
        log.info("`pebble[alt]`: PEBBLE_BIN : %s", PEBBLE_BIN)
        log.info("`pebble[alt]`: PEBBLE_ALT_CONFIG_FILE : %s", PEBBLE_ALT_CONFIG_FILE)
        log.info("`pebble[alt]`: PEBBLE_CONFIG_DIR : %s", PEBBLE_CONFIG_DIR)
        # log.info("`pebble`: PEBBLE_ENV : %s", PEBBLE_ENV)
        # after layout updates, changing to the CWD will break this from running
        # due to: tests/test_configuration/pebble/test/certs/localhost/cert.pem
        res = None  # scoping
        stdout: Union[int, BufferedWriter] = subprocess.PIPE
        stderr: Union[int, BufferedWriter] = subprocess.PIPE
        if DEBUG_PEBBLE_REDIS:
            fname = (
                (
                    "%s/%s-pebble_alt.txt"
                    % (
                        DIR_TESTRUN,
                        _function.__qualname__,
                    )
                )
                .replace("<", "_")
                .replace(">", "_")
            )
            if "_locals_._wrapped-" in fname:
                fname = fname.replace("_locals_._wrapped", str(uuid.uuid4()))
            stdout = open(fname, "wb")

        with psutil.Popen(
            [PEBBLE_BIN, "-config", PEBBLE_ALT_CONFIG_FILE],
            stdin=subprocess.PIPE,
            stdout=stdout,
            stderr=stderr,
            # cwd=PEBBLE_CONFIG_DIR,
            env=PEBBLE_ENV,
        ) as proc:
            # ensure the `pebble` server is running
            ready = False
            _waits = 0
            while not ready:
                log.info("`pebble[alt]`: waiting for ready | %s" % _waits)
                _waits += 1
                if _waits >= 30:
                    raise ValueError("`pebble[alt]`: ERROR spinning up")
                if DEBUG_PEBBLE_REDIS:
                    with open(fname, "rb") as fh_read:
                        for line in fh_read.readlines():
                            if ACME_CHECK_MSG_ALT in line:
                                log.info("`pebble[alt]`: ready")
                                ready = True
                                break
                else:
                    for line in iter(proc.stdout.readline, b""):
                        # if b"Listening on: 0.0.0.0:14001" in line:
                        if ACME_CHECK_MSG_ALT in line:
                            log.info("`pebble[alt]`: ready")
                            ready = True
                            break
                time.sleep(1)
            try:
                PEBBLE_ALT_RUNNING = True
                # catch in app_test so we don't recycle the roots
                handle_new_pebble(14001, 15001, "test-alt")
                res = _function(*args, **kwargs)
            finally:
                # explicitly terminate, otherwise it won't exit
                # in a `finally` to ensure we terminate on exceptions
                log.info("`pebble[alt]`: finished. terminating")
                proc.terminate()
                PEBBLE_ALT_RUNNING = False
        return res

    return _wrapper


def under_redis(_function: Callable) -> Callable:
    """
    decorator to spin up an external redis server

    $ mkdir /var/lib/redis/peter_sslers_test
    """

    @wraps(_function)
    def _wrapper(*args, **kwargs):
        if USE_SYSTEM_REDIS:
            log.info("`redis`: `USE_SYSTEM_REDIS=1` for `%s`" % _function.__qualname__)
            res = _function(*args, **kwargs)
            return res
        log.info("`redis`: spinning up for `%s`" % _function.__qualname__)
        log.info("`redis`: SSL_BIN_REDIS_SERVER  : %s", SSL_BIN_REDIS_SERVER)
        log.info("`redis`: SSL_CONF_REDIS_SERVER : %s", SSL_CONF_REDIS_SERVER)
        res = None  # scoping
        stdout: Union[int, BufferedWriter] = subprocess.PIPE
        stderr: Union[int, BufferedWriter] = subprocess.PIPE
        if DEBUG_PEBBLE_REDIS:
            fname = (
                (
                    "%s/%s-redis.txt"
                    % (
                        DIR_TESTRUN,
                        _function.__qualname__,
                    )
                )
                .replace("<", "_")
                .replace(">", "_")
            )
            if "_locals_._wrapped-" in fname:
                fname = fname.replace("_locals_._wrapped", str(uuid.uuid4()))
            stdout = open(fname, "wb")
        with psutil.Popen(
            [SSL_BIN_REDIS_SERVER, SSL_CONF_REDIS_SERVER],
            stdin=subprocess.PIPE,
            stdout=stdout,
            stderr=stderr,
        ) as proc:
            # ensure the `redis` server is running
            ready = False
            _waits = 0
            while not ready:
                log.info("`redis`: waiting for ready")
                _waits += 1
                if _waits >= 20:
                    raise ValueError("`redis`: ERROR spinning up")
                if DEBUG_PEBBLE_REDIS:
                    with open(fname, "rb") as fh_read:
                        for line in fh_read.readlines():
                            if b"Can't chdir to" in line:
                                raise ValueError(line)
                            # Redis 5.x
                            if b"Ready to accept connections" in line:
                                log.info("`redis`: ready")
                                ready = True
                                break
                            # Redis2.x
                            if b"The server is now ready to accept connections" in line:
                                log.info("`redis`: ready")
                                ready = True
                                break
                else:
                    for line in iter(proc.stdout.readline, b""):
                        if b"Can't chdir to" in line:
                            raise ValueError(line)
                        # Redis 5.x
                        if b"Ready to accept connections" in line:
                            log.info("`redis`: ready")
                            ready = True
                            break
                        # Redis2.x
                        if b"The server is now ready to accept connections" in line:
                            log.info("`redis`: ready")
                            ready = True
                            break
                time.sleep(1)
            try:
                res = _function(*args, **kwargs)
            finally:
                # explicitly terminate, otherwise it won't exit
                # in a `finally` to ensure we terminate on exceptions
                log.info("`redis`: finished. terminating")
                proc.terminate()
        return res

    return _wrapper


def under_acme_dns(_function: Callable) -> Callable:
    """
    decorator to spin up an external acme_dns server
    """
    global ACMEDNS_RUNNING

    @wraps(_function)
    def _wrapper(*args, **kwargs):
        log.info("`acme-dns`: spinning up for `%s`" % _function.__qualname__)
        log.info("`acme-dns`: ACMEDNS_CONFIG_FILE : %s", ACMEDNS_CONFIG_FILE)
        # log.info("`pebble`: PEBBLE_ENV : %s", PEBBLE_ENV)
        # after layout updates, changing to the CWD will break this from running
        # due to: tests/test_configuration/pebble/test/certs/localhost/cert.pem
        res = None  # scoping
        stdout: Union[int, BufferedWriter] = subprocess.PIPE
        stderr: Union[int, BufferedWriter] = subprocess.PIPE
        if DEBUG_PEBBLE_REDIS:
            fname = (
                (
                    "%s/%s-acme_dns.txt"
                    % (
                        DIR_TESTRUN,
                        _function.__qualname__,
                    )
                )
                .replace("<", "_")
                .replace(">", "_")
            )
            if "_locals_._wrapped-" in fname:
                fname = fname.replace("_locals_._wrapped", str(uuid.uuid4()))
            stdout = open(fname, "wb")
        with psutil.Popen(
            ["sudo", "acme-dns", "-c", ACMEDNS_CONFIG_FILE],
            stdin=subprocess.PIPE,
            stdout=stdout,
            stderr=stderr,
        ) as proc:
            # ensure the `pebble` server is running
            ready = False
            _waits = 0
            while not ready:
                log.info("`acme-dns`: waiting for ready | %s" % _waits)
                _waits += 1
                if _waits >= 30:
                    raise ValueError("`acme-dns`: ERROR spinning up")
                if DEBUG_PEBBLE_REDIS:
                    with open(fname, "rb") as fh_read:
                        for line in fh_read.readlines():
                            if b"Listening HTTP" in line:
                                log.info("`acme-dns`: ready")
                                ready = True
                                break
                else:
                    # acme-dns logs to STDERR, not STDOUT
                    for line in iter(proc.stderr.readline, b""):
                        if b"Listening HTTP" in line:
                            log.info("`acme-dns`: ready")
                            ready = True
                            break
                time.sleep(1)
            try:
                ACMEDNS_RUNNING = True
                res = _function(*args, **kwargs)
            finally:
                # explicitly terminate, otherwise it won't exit
                # in a `finally` to ensure we terminate on exceptions
                log.info("`acme-dns`: finished. terminating")
                proc.terminate()
                ACMEDNS_RUNNING = False
        return res

    return _wrapper


# ==============================================================================


def db_freeze(
    dbSession: Session,
    savepoint: Literal["AppTestCore", "AppTest", "test_pyramid_app-setup_testing_data"],
) -> bool:
    """
    Freezes the current database into a savepoint backup.

    The active dbfile (from the SQLAlchemy Connection String) will be 'backed up'
    into a savepoint file.
    """
    if DEBUG_DBFREEZE:
        print("db_freeze>>>>>%s" % savepoint)
    log.info("db_freeze[%s]", savepoint)
    _connection = dbSession.connection()
    _engine = _connection.engine
    if _engine.url.drivername != "sqlite":
        return False
    if _engine.url.database is None:
        # in-memory sqlite
        return False

    active_filename = _engine.url.database
    # normalize this...
    active_filename = os.path.normpath(active_filename)

    backup_filename = "%s-%s" % (active_filename, savepoint)
    backupDb = sqlite3.connect(backup_filename)
    _connection.connection.backup(backupDb)  # type: ignore[attr-defined]

    return True


def _sqlite_backup_progress(status, remaining, total) -> None:
    """`progress` hook for `sqlite3.backup`"""
    if DEBUG_DBFREEZE:
        print(f"Copied {total - remaining} of {total} pages...")
    return


def _db_unfreeze__actual(
    active_filename: str,
    savepoint: Literal["AppTestCore", "AppTest", "test_pyramid_app-setup_testing_data"],
) -> bool:
    """
    Unfreezes a frozen savepoint backup into the active database file.
    """
    if DEBUG_DBFREEZE:
        print("_db_unfreeze__actual>>>%s" % savepoint)
    log.info("_db_unfreeze__actual[%s]", savepoint)

    backup_filename = "%s-%s" % (active_filename, savepoint)
    if not os.path.exists(backup_filename):
        log.info(
            "_db_unfreeze__actual[%s] | not os.path.exists(%s)"
            % (savepoint, backup_filename)
        )
        return False

    is_failure = False

    try:
        if DEBUG_DBFREEZE:
            print("DEBUG_DBFREEZE: Attempted to clear database")

        # try to clear the database itself
        clearDb = sqlite3.connect(
            active_filename,
            isolation_level="EXCLUSIVE",
        )
        cursor = clearDb.cursor()
        # clear the database
        cursor.execute(("VACUUM;"))
        cursor.execute(("PRAGMA writable_schema = 1;"))
        cursor.execute(("DELETE FROM sqlite_master;"))
        cursor.execute(("PRAGMA writable_schema = 0;"))
        cursor.execute(("VACUUM;"))
        cursor.execute(("PRAGMA integrity_check;"))
        clearDb.close()
    except Exception as excc:
        log.info(
            "_db_unfreeze__actual[%s] | exception clearing old database: %s"
            % (savepoint, active_filename)
        )
        if DEBUG_DBFREEZE:
            print("DEBUG_DBFREEZE: exception clearing old database:", active_filename)
            print(excc)

        # if that doesn't work, log it to an artifact
        if DEBUG_DBFREEZE_ARCHIVE:
            if AppTestCore._currentTest:
                # prefer the name
                failname = "%s-FAIL-%s" % (active_filename, AppTestCore._currentTest)
            else:
                # otherwise, save it do a UUID
                failname = "%s-FAIL-%s" % (active_filename, uuid.uuid4())
            if DEBUG_DBFREEZE:
                print(
                    "DEBUG_DBFREEZE: clear failed; archiving for inspection:", failname
                )
            shutil.copy2(active_filename, failname)
        # instead of raising an exc, just delete it
        # TODO: bugfix how/why this is only breaking in CI on
        if DEBUG_DBFREEZE:
            print("DEBUG_DBFREEZE: unlinking old database for rewrite")
        os.unlink(active_filename)

        # Do not `return` here; as we need to copy the db next...
        is_failure = True

    # Py3.10 and below do not need the cursor+vacuum
    # Py3.13 needs the cursor+vaccume
    if DEBUG_DBFREEZE:
        print("DEBUG_DBFREEZE: Attempted to backup")
    with sqlite3.connect(
        active_filename,
        isolation_level="EXCLUSIVE",
    ) as activeDb:
        with sqlite3.connect(
            backup_filename,
            isolation_level="EXCLUSIVE",
        ) as backupDb:
            cursor = backupDb.cursor()
            cursor.execute(("VACUUM;"))
            backupDb.backup(activeDb, pages=-1, progress=_sqlite_backup_progress)
    if DEBUG_DBFREEZE:
        print("DEBUG_DBFREEZE: backup successful")

    if is_failure:
        pass

    return True


def db_unfreeze(
    dbSession: Session,
    savepoint: Literal["AppTestCore", "AppTest", "test_pyramid_app-setup_testing_data"],
    testCase: Optional[CustomizedTestCase] = None,
) -> Optional[bool]:
    """
    pass in the testCase to ensure we close those database connections
    those lingering pooled connections may have been the database issue all along
    """

    if DEBUG_DBFREEZE:
        print("db_unfreeze>>>%s" % savepoint)
    log.info("db_unfreeze[%s]", savepoint)
    _connection = dbSession.connection()
    _engine = _connection.engine
    if _engine.url.drivername != "sqlite":
        log.info(
            "db_unfreeze[%s]: _engine.url.drivername != sqlite | `%s`"
            % (savepoint, _engine.url.drivername)
        )
        return False
    if _engine.url.database is None:
        log.info("db_unfreeze[%s]: _engine.url.database is None", savepoint)
        # in-memory sqlite
        return False
    active_filename = _engine.url.database
    # normalize this...
    active_filename = os.path.normpath(active_filename)

    # # close the connection
    # # while many options will work to close it,
    # # they can create issues afterwards.
    # # `Engine.dispose` works the best
    # _connection.connection.close()
    # _connection.connection.detach()
    # _connection.connection.invalidate()
    # _connection.close()
    # _connection.detach()
    # _connection.invalidate()
    # _engine.dispose()
    _engine.pool.dispose()
    _engine.dispose()

    # drop the embedded app as well
    if testCase:
        if hasattr(testCase, "_pyramid_app") and testCase._pyramid_app:
            # testCase._pyramid_app.registry["dbSession_factory"].close_all()
            close_all_sessions()

    unfreeze_result = _db_unfreeze__actual(active_filename, savepoint)
    log.info("db_unfreeze[%s]: _db_unfreeze__actual: %s" % (savepoint, unfreeze_result))
    return unfreeze_result


# !!!: TEST_FILES


TEST_FILES: Dict = {
    "AcmeAccount": {
        "1": {
            "key": "key_technology-rsa/acme_account_1.key",
            "provider": "pebble",
            "order_default_private_key_cycle": "single_use",
            "order_default_private_key_technology": "RSA_2048",
            "contact": "contact.a@example.com",
            "private_key_technology": "RSA_2048",
        },
        "2": {
            "key": "key_technology-rsa/acme_account_2.key",
            "provider": "pebble",
            "order_default_private_key_cycle": "single_use",
            "order_default_private_key_technology": "RSA_2048",
            "contact": "contact.b@example.com",
            "private_key_technology": "RSA_2048",
        },
        "3": {
            "key": "key_technology-rsa/acme_account_3.key",
            "provider": "pebble",
            "order_default_private_key_cycle": "single_use",
            "order_default_private_key_technology": "RSA_2048",
            "contact": "contact.c@example.com",
            "private_key_technology": "RSA_2048",
        },
        "4": {
            "key": "key_technology-rsa/acme_account_4.key",
            "provider": "pebble_alt",
            "order_default_private_key_cycle": "single_use",
            "order_default_private_key_technology": "RSA_2048",
            "contact": "contact.d@example.com",
            "private_key_technology": "RSA_2048",
        },
        "5": {
            "key": "key_technology-rsa/acme_account_5.key",
            "provider": "pebble_alt",
            "order_default_private_key_cycle": "single_use",
            "order_default_private_key_technology": "RSA_2048",
            "contact": "contact.e@example.com",
            "private_key_technology": "RSA_2048",
        },
    },
    "AcmeDnsServer": {
        "1": {
            "api_url": ACME_DNS_API,
            "domain": ACME_DNS_DOMAIN,
        },
        "2": {
            "api_url": "https://acme-dns.example.com",
            "domain": "acme-dns.example.com",
        },
        "3": {
            "api_url": "https://acme-dns-alt.example.com",
            "domain": "acme-dns-alt.example.com",
        },
        "4": {
            "api_url": "https://acme-dns-alt-2.example.com",
            "domain": "acme-dns-alt-2.example.com",
        },
    },
    "AcmeDnsServerAccount": {
        "1": {
            "AcmeDnsServer": "2",
            "domain": "example.com",
            "username": "username",
            "password": "password",
            "fulldomain": "fulldomain",
            "subdomain": "subdomain",
            "allowfrom": "[]",
        },
        "test-new-via-Domain": {
            "html": {
                "AcmeDnsServer.id": 1,
                "Domain": "test-new-via-domain-html.example.com",
            },
            "json": {
                "AcmeDnsServer.id": 1,
                "Domain": "test-new-via-domain-json.example.com",
            },
        },
    },
    "AcmeOrder": {
        "test-extended_html": {
            "acme-order/new/freeform#1": {
                "account_key_option": "account_key_file",
                "acme_server_id": "1",
                "account_key_file_pem": "key_technology-rsa/AcmeAccountKey-1.pem",
                "account__contact": "AcmeAccountKey-1@example.com",
                "private_key_cycle__primary": "account_daily",
                "private_key_option__primary": "account_default",
                "domain_names_http01": [
                    "new-freeform-1-a.example.com",
                    "new-freeform-1-b.example.com",
                ],
                "processing_strategy": "create_order",
            },
            "acme-order/new/freeform#2": {
                "account_key_option": "account_key_file",
                "acme_server_id": "1",
                "account_key_file_pem": "key_technology-rsa/AcmeAccountKey-1.pem",
                "account__contact": "AcmeAccountKey-1@example.com",
                "private_key_cycle__primary": "account_daily",
                "private_key_option__primary": "account_default",
                "domain_names_http01": [
                    "new-freeform-1-c.example.com",
                    "new-freeform-1-d.example.com",
                ],
                "processing_strategy": "create_order",
            },
        },
    },
    "X509CertificateTrusteds": {
        "order": (
            "trustid_root_x3",
            "isrg_root_x1",
            "isrg_root_x1_cross",
            "isrg_root_x2",
            "isrg_root_x2_cross",
            "letsencrypt_ocsp_root_x1",
            "letsencrypt_intermediate_e1",
            "letsencrypt_intermediate_e2",
            "letsencrypt_intermediate_r3",
            "letsencrypt_intermediate_r4",
            "letsencrypt_intermediate_x1",
            "letsencrypt_intermediate_x2",
            "letsencrypt_intermediate_x3",
            "letsencrypt_intermediate_x4",
            "letsencrypt_intermediate_x1_cross",
            "letsencrypt_intermediate_x2_cross",
            "letsencrypt_intermediate_x3_cross",
            "letsencrypt_intermediate_x4_cross",
        ),
        "cert": {
            "trustid_root_x3": "letsencrypt-certs/trustid-x3-root.pem",
            "isrg_root_x1": "letsencrypt-certs/isrgrootx1.pem",
            "isrg_root_x1_cross": "letsencrypt-certs/isrg-root-x1-cross-signed.pem",
            "isrg_root_x2": "letsencrypt-certs/isrg-root-x2.pem",
            "isrg_root_x2_cross": "letsencrypt-certs/isrg-root-x2-cross-signed.pem",
            "letsencrypt_ocsp_root_x1": "letsencrypt-certs/isrg-root-ocsp-x1.pem",
            "letsencrypt_intermediate_x1": "letsencrypt-certs/letsencryptauthorityx1.pem",
            "letsencrypt_intermediate_x2": "letsencrypt-certs/letsencryptauthorityx2.pem",
            "letsencrypt_intermediate_x3": "letsencrypt-certs/letsencryptauthorityx3.pem",
            "letsencrypt_intermediate_x4": "letsencrypt-certs/letsencryptauthorityx4.pem",
            "letsencrypt_intermediate_r3": "letsencrypt-certs/lets-encrypt-r3.pem",
            "letsencrypt_intermediate_r4": "letsencrypt-certs/lets-encrypt-r4.pem",
            "letsencrypt_intermediate_e1": "letsencrypt-certs/lets-encrypt-e1.pem",
            "letsencrypt_intermediate_e2": "letsencrypt-certs/lets-encrypt-e2.pem",
            "letsencrypt_intermediate_x1_cross": "letsencrypt-certs/lets-encrypt-x1-cross-signed.pem",
            "letsencrypt_intermediate_x2_cross": "letsencrypt-certs/lets-encrypt-x2-cross-signed.pem",
            "letsencrypt_intermediate_x3_cross": "letsencrypt-certs/lets-encrypt-x3-cross-signed.pem",
            "letsencrypt_intermediate_x4_cross": "letsencrypt-certs/lets-encrypt-x4-cross-signed.pem",
            "letsencrypt_intermediate_r3_cross": "letsencrypt-certs/lets-encrypt-r3-cross-signed.pem",
            "letsencrypt_intermediate_r4_cross": "letsencrypt-certs/lets-encrypt-r4-cross-signed.pem",
        },
    },
    "Domains": {
        "AcmeDnsServer": {
            "1": {
                "ensure-domains.html": "ensure1-html.example.com, ensure2-html.example.com, ensure1.example.com",
                "ensure-domains.json": "ensure1-json.example.com, ensure2-json.example.com, ensure1.example.com",
                "import-domain.html": {
                    "payload": {
                        "domain_name": "import1-html.example.com",
                        "username": "xxusernamexx",
                        "password": "xxpasswordxx",
                        "fulldomain": "html.fqdn.acmedns.example.com",
                        "subdomain": "html.fqdn",
                        "allowfrom": "[]",
                    }
                },
                "import-domain.json": {
                    "payload": {
                        "domain_name": "import1-json.example.com",
                        "username": "xxusernameyy",
                        "password": "xxpasswordyy",
                        "fulldomain": "json.fqdn.acmedns.example.com",
                        "subdomain": "json.fqdn",
                        "allowfrom": "[]",
                    }
                },
            },
        },
    },
    "X509CertificateRequests": {
        "1": {
            "domains": "foo.example.com, bar.example.com",
            "account_key": "key_technology-rsa/account_1.key",
            "private_key": "key_technology-rsa/private_1.key",
        },
        "acme_test": {
            "domains": SSL_TEST_DOMAINS,
            "account_key": "key_technology-rsa/account_2.key",
            "private_key": "key_technology-rsa/private_2.key",
        },
    },
    # the certificates are a tuple of: (CommonName, crt, csr, key)
    "X509Certificates": {
        "SelfSigned": {
            "1": {
                "domain": "selfsigned-1.example.com",
                "cert": "key_technology-rsa/selfsigned_1-server.crt",
                "csr": "key_technology-rsa/selfsigned_1-server.csr",
                "pkey": "key_technology-rsa/selfsigned_1-server.key",
            },
            "2": {
                "domain": "selfsigned-2.example.com",
                "cert": "key_technology-rsa/selfsigned_2-server.crt",
                "csr": "key_technology-rsa/selfsigned_2-server.csr",
                "pkey": "key_technology-rsa/selfsigned_2-server.key",
            },
            "3": {
                "domain": "selfsigned-3.example.com",
                "cert": "key_technology-rsa/selfsigned_3-server.crt",
                "csr": "key_technology-rsa/selfsigned_3-server.csr",
                "pkey": "key_technology-rsa/selfsigned_3-server.key",
            },
            "4": {
                "domain": "selfsigned-4.example.com",
                "cert": "key_technology-rsa/selfsigned_4-server.crt",
                "csr": "key_technology-rsa/selfsigned_4-server.csr",
                "pkey": "key_technology-rsa/selfsigned_4-server.key",
            },
            "5": {
                "domain": "selfsigned-5.example.com",
                "cert": "key_technology-rsa/selfsigned_5-server.crt",
                "csr": "key_technology-rsa/selfsigned_5-server.csr",
                "pkey": "key_technology-rsa/selfsigned_5-server.key",
            },
        },
        "Pebble": {
            # these use `FormatA` and can be setup using `_setUp_X509Certificates_FormatA`
            "1": {
                "domain": "a.example.com",
                "cert": "cert1.pem",
                "chain": "chain1.pem",
                "pkey": "privkey1.pem",
            },
            "2": {
                "domain": "b.example.com",
                "cert": "cert2.pem",
                "chain": "chain2.pem",
                "pkey": "privkey2.pem",
            },
            "3": {
                "domain": "c.example.com",
                "cert": "cert3.pem",
                "chain": "chain3.pem",
                "pkey": "privkey3.pem",
            },
            "4": {
                "domain": "d.example.com",
                "cert": "cert4.pem",
                "chain": "chain4.pem",
                "pkey": "privkey4.pem",
            },
            "5": {
                "domain": "e.example.com",
                "cert": "cert5.pem",
                "chain": "chain5.pem",
                "pkey": "privkey5.pem",
            },
        },
        "AlternateChains": {
            # these use `FormatA` and can be setup using `_setUp_X509Certificates_FormatA`
            "1": {
                # reseved for `FunctionalTests_AlternateChains`
                "domain": "example.com",
                "cert": "cert.pem",
                "chain": "chain.pem",
                "pkey": "privkey.pem",
                "alternate_chains": {
                    "1": {
                        "chain": "chain.pem",
                    },
                    "2": {
                        "chain": "chain.pem",
                    },
                },
            },
        },
    },
    "PrivateKey": {
        "1": {
            "file": "key_technology-rsa/private_1.key",
            "key_pem_md5": "462dc10731254d7f5fa7f0e99cbece73",
        },
        "2": {
            "file": "key_technology-rsa/private_2.key",
            "key_pem_md5": "cdde9325bdbfe03018e4119549c3a7eb",
        },
        "3": {
            "file": "key_technology-rsa/private_3.key",
            "key_pem_md5": "399236401eb91c168762da425669ad06",
        },
        "4": {
            "file": "key_technology-rsa/private_4.key",
            "key_pem_md5": "6867998790e09f18432a702251bb0e11",
        },
        "5": {
            "file": "key_technology-rsa/private_5.key",
            "key_pem_md5": "1b13814854d8cee8c64732a2e2f7e73e",
        },
    },
}


CERT_CA_SETS = {
    "letsencrypt-certs/trustid-x3-root.pem": {
        "key_technology": "RSA",
        "spki_sha256": "563B3CAF8CFEF34C2335CAF560A7A95906E8488462EB75AC59784830DF9E5B2B",
        "spki_sha256.b64": "Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys=",
        "cert.fingerprints": {
            "sha1": "DAC9024F54D8F6DF94935FB1732638CA6AD77C13",
        },
        "subject": "O=Digital Signature Trust Co.\nCN=DST Root CA X3",
        "issuer": "O=Digital Signature Trust Co.\nCN=DST Root CA X3",
        "issuer_uri": None,
        "authority_key_identifier": None,
    },
    "letsencrypt-certs/isrgrootx1.pem": {
        "key_technology": "RSA",
        "spki_sha256": "0B9FA5A59EED715C26C1020C711B4F6EC42D58B0015E14337A39DAD301C5AFC3",
        "spki_sha256.b64": "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=",
        "cert.fingerprints": {
            "sha1": "CABD2A79A1076A31F21D253635CB039D4329A5E8",
        },
        "subject": "C=US\nO=Internet Security Research Group\nCN=ISRG Root X1",
        "issuer": "C=US\nO=Internet Security Research Group\nCN=ISRG Root X1",
        "issuer_uri": None,
        "authority_key_identifier": None,
    },
    "letsencrypt-certs/isrg-root-x1-cross-signed.pem": {
        "key_technology": "RSA",
        "spki_sha256": "0B9FA5A59EED715C26C1020C711B4F6EC42D58B0015E14337A39DAD301C5AFC3",
        "spki_sha256.b64": "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=",
        "cert.fingerprints": {
            "sha1": "933C6DDEE95C9C41A40F9F50493D82BE03AD87BF",
        },
        "subject": "C=US\nO=Internet Security Research Group\nCN=ISRG Root X1",
        "issuer": "O=Digital Signature Trust Co.\nCN=DST Root CA X3",
        "issuer_uri": "http://apps.identrust.com/roots/dstrootcax3.p7c",
        "authority_key_identifier": "C4A7B1A47B2C71FADBE14B9075FFC41560858910",
    },
    "letsencrypt-certs/isrg-root-x2.pem": {
        "key_technology": "EC",
        "spki_sha256": "762195C225586EE6C0237456E2107DC54F1EFC21F61A792EBD515913CCE68332",
        "spki_sha256.b64": "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=",
        "cert.fingerprints": {
            "sha1": "BDB1B93CD5978D45C6261455F8DB95C75AD153AF",
        },
        "subject": "C=US\nO=Internet Security Research Group\nCN=ISRG Root X2",
        "issuer": "C=US\nO=Internet Security Research Group\nCN=ISRG Root X2",
        "issuer_uri": None,
        "authority_key_identifier": None,
    },
    "letsencrypt-certs/isrg-root-x2-cross-signed.pem": {
        "key_technology": "EC",
        "spki_sha256": "762195C225586EE6C0237456E2107DC54F1EFC21F61A792EBD515913CCE68332",
        "spki_sha256.b64": "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=",
        "cert.fingerprints": {
            "sha1": "151682F5218C0A511C28F4060A73B9CA78CE9A53",
        },
        "subject": "C=US\nO=Internet Security Research Group\nCN=ISRG Root X2",
        "issuer": "C=US\nO=Internet Security Research Group\nCN=ISRG Root X1",
        "issuer_uri": "http://x1.i.lencr.org/",
        "authority_key_identifier": "79B459E67BB6E5E40173800888C81A58F6E99B6E",
    },
    "letsencrypt-certs/lets-encrypt-r3-cross-signed.pem": {
        "key_technology": "RSA",
        "spki_sha256": "8D02536C887482BC34FF54E41D2BA659BF85B341A0A20AFADB5813DCFBCF286D",
        "spki_sha256.b64": "jQJTbIh0grw0/1TkHSumWb+Fs0Ggogr621gT3PvPKG0=",
        "cert.fingerprints": {
            "sha1": "48504E974C0DAC5B5CD476C8202274B24C8C7172",
        },
        "subject": "C=US\nO=Let's Encrypt\nCN=R3",
        "issuer": "O=Digital Signature Trust Co.\nCN=DST Root CA X3",
        "issuer_uri": "http://apps.identrust.com/roots/dstrootcax3.p7c",
        "authority_key_identifier": "C4A7B1A47B2C71FADBE14B9075FFC41560858910",
    },
}


CSR_SETS = {
    "key_technology-ec/ec384-1.csr": {
        "key_private": {
            "file": "key_technology-ec/ec384-1-key.pem",
            "key_technology": "EC",
        },
    },
    "key_technology-rsa/selfsigned_1-server.csr": {
        "key_private": {
            "file": "key_technology-rsa/selfsigned_1-server.csr",
            "key_technology": "RSA",
        },
    },
}


KEY_SETS = {
    "key_technology-rsa/acme_account_1.key": {
        "key_technology": "RSA",
        "spki_sha256": "E70DCB45009DF3F79FC708B46888609E34A3D8D19AEAFA566389718A29140782",
        "spki_sha256.b64": "5w3LRQCd8/efxwi0aIhgnjSj2NGa6vpWY4lxiikUB4I=",
    },
    "key_technology-ec/ec384-1-key.pem": {
        "key_technology": "EC",
        "spki_sha256": "E739FB0081868C97B8AC0D3773680974E9FCECBFA1FC8B80AFDDBE42F30D1D9D",
        "spki_sha256.b64": "5zn7AIGGjJe4rA03c2gJdOn87L+h/IuAr92+QvMNHZ0=",
    },
}


# ==============================================================================


_ROUTES_TESTED = {}


def routes_tested(*args) -> Callable:
    """
    `@routes_tested` is a decorator
    when writing/editing a test, declare what routes the test covers, like such:

        @routes_tested(("foo", "bar"))
        def test_foo_bar(self):
            ...

    this will populate a global variable `_ROUTES_TESTED` with the name of the
    tested routes.

    invoking the Audit test:

        python -m unittest tests.test_pyramid_app.FunctionalTests_AuditRoutes

    will ensure all routes in Pyramid have test coverage
    """
    _routes = args[0]
    if isinstance(_routes, (list, tuple)):
        for _r in _routes:
            _ROUTES_TESTED[_r] = True
    else:
        _ROUTES_TESTED[_routes] = True

    def _decorator(_function: Callable) -> Callable:
        @wraps(_function)
        def _wrapper(*args, **kwargs):
            return _function(*args, **kwargs)

        return _wrapper

    return _decorator


# =====


def do__AcmeServers_sync__api(
    testCase: CustomizedTestCase,
    sync_primary: bool = True,
    sync_backup: bool = True,
) -> Literal[True]:
    """
    Hits the `/acme-server/%s/check` endpoint for all configured policies
    This is used to ensure PeterSSLers knows the current directory and profiles
    """
    acme_server_ids: List[int] = []
    policy_names = (
        "global",
        "autocert",
        "certificate-if-needed",
    )
    for _pname in policy_names:
        dbSystemConfiguration = lib_db_get.get__SystemConfiguration__by_name(
            testCase.ctx, _pname
        )
        assert dbSystemConfiguration
        if dbSystemConfiguration.is_configured:
            if (
                dbSystemConfiguration.acme_account__primary.acme_server_id
                not in acme_server_ids
            ):
                if sync_primary:
                    acme_server_ids.append(
                        dbSystemConfiguration.acme_account__primary.acme_server_id
                    )
            if dbSystemConfiguration.acme_account__backup:
                assert dbSystemConfiguration.acme_account__backup.acme_server
                if (
                    dbSystemConfiguration.acme_account__backup.acme_server_id
                    not in acme_server_ids
                ):
                    if sync_backup:
                        acme_server_ids.append(
                            dbSystemConfiguration.acme_account__backup.acme_server_id
                        )
        else:
            if _pname == "global":
                raise ValueError("SystemConfiguration[global] not configured")

    for _acme_server_id in acme_server_ids:
        res = testCase.testapp.get(
            "/.well-known/peter_sslers/acme-server/%s" % _acme_server_id,
            status=200,
        )
        form = res.forms["form-check_support"]
        res2 = form.submit()
        assert res2.status_code == 303
        assert (
            "/.well-known/peter_sslers/acme-server/%s?result=success&operation=check-support&check-support=True"
            % _acme_server_id
        ) in res2.location

    return True


@routes_tested("admin:acme_account:new|json")
def make_one__AcmeAccount__random__api(
    testCase: CustomizedTestCase,
    acme_server_id: int = 1,
) -> Tuple[model_objects.AcmeAccount, int]:
    """
    Creates an AcmeAccount using the json API
    """
    form = {
        "acme_server_id": acme_server_id,
        "account__contact": generate_random_emailaddress(),
        "account__private_key_technology": "EC_P256",
        "account__order_default_private_key_cycle": "single_use",
        "account__order_default_private_key_technology": "EC_P256",
    }
    res4 = testCase.testapp.post(
        "/.well-known/peter_sslers/acme-account/new.json", form
    )
    assert res4.json["result"] == "success"
    assert "AcmeAccount" in res4.json
    focus_item = (
        testCase.ctx.dbSession.query(model_objects.AcmeAccount)
        .filter(model_objects.AcmeAccount.id == res4.json["AcmeAccount"]["id"])
        .filter(model_objects.AcmeAccount.is_active.is_(True))
        .filter(model_objects.AcmeAccount.acme_server_id == 1)
        .first()
    )
    assert focus_item is not None
    return (focus_item, focus_item.id)


@routes_tested("admin:acme_account:upload|json")
def make_one__AcmeAccount__pem__api(
    testCase: CustomizedTestCase,
    account__contact: str,
    pem_file_name: str,
    expect_failure: bool = False,
    acme_server_id: int = 1,
) -> Tuple[model_objects.AcmeAccount, int]:
    """
    Creates an AcmeAccount using the json API
    """
    form = {
        "account_key_option": "account_key_file",
        "account_key_file_pem": Upload(testCase._filepath_testfile(pem_file_name)),
        "acme_server_id": acme_server_id,
        "account__contact": account__contact,
        "account__order_default_private_key_cycle": "account_daily",
        "account__order_default_private_key_technology": "EC_P256",
    }
    res = testCase.testapp.post(
        "/.well-known/peter_sslers/acme-account/upload.json", form
    )
    if expect_failure:
        raise ResponseFailureOkay(res)

    assert res.json["result"] == "success"
    assert "AcmeAccount" in res.json
    focus_item = (
        testCase.ctx.dbSession.query(model_objects.AcmeAccount)
        .filter(model_objects.AcmeAccount.id == res.json["AcmeAccount"]["id"])
        .filter(model_objects.AcmeAccount.is_active.is_(True))
        .filter(model_objects.AcmeAccount.acme_server_id == 1)
        .first()
    )
    assert focus_item is not None
    return (focus_item, focus_item.id)


@routes_tested("admin:acme_order:new:freeform|json")
def make_one__AcmeOrder__api(
    testCase: CustomizedTestCase,
    domain_names_http01: Optional[str] = None,
    domain_names_dns01: Optional[str] = None,
    account_key_option__backup: Optional[str] = None,
    acme_profile__primary: Optional[str] = None,
    acme_profile__backup: Optional[str] = None,
    private_key_option: Literal[
        "account_default", "private_key_generate"
    ] = "account_default",
    private_key_cycle__primary: Literal[
        "account_default", "single_use__reuse_1_year"
    ] = "account_default",
    processing_strategy: Literal["create_order", "process_single"] = "create_order",
) -> model_objects.AcmeOrder:
    """
    Creates an AcmeOrder using the html API based on specified domain names
    the `account_key_global__primary` is used
    """

    # pebble loses state, so:
    # ensure_AcmeAccount_auth(testCase=testCase)

    res = testCase.testapp.get(
        "/.well-known/peter_sslers/acme-order/new/freeform", status=200
    )
    form = res.form
    _form_fields = form.fields.keys()
    assert "account_key_option__primary" in _form_fields
    form["account_key_option__primary"].force_value("account_key_global__primary")
    form["private_key_cycle__primary"] = private_key_cycle__primary
    form["private_key_option__primary"] = private_key_option
    if domain_names_http01:
        form["domain_names_http01"] = domain_names_http01
    if domain_names_dns01:
        form["domain_names_dns01"] = domain_names_dns01
    if acme_profile__primary:
        form["acme_profile__primary"] = acme_profile__primary
    if acme_profile__backup:
        form["acme_profile__backup"] = acme_profile__backup
    if account_key_option__backup:
        form["account_key_option__backup"].force_value(account_key_option__backup)
    form["processing_strategy"].force_value(processing_strategy)
    res2 = form.submit()

    assert res2.status_code == 303
    matched = RE_AcmeOrder.match(res2.location)
    assert matched
    obj_id = matched.groups()[0]

    dbAcmeOrder = testCase.ctx.dbSession.query(model_objects.AcmeOrder).get(obj_id)
    assert dbAcmeOrder
    return dbAcmeOrder


@routes_tested("admin:acme_order:new:freeform|json")
def make_one__AcmeOrder__random__api(
    testCase: CustomizedTestCase,
    processing_strategy: Literal["create_order"] = "create_order",
    ensure_useraccount: bool = True,
) -> model_objects.AcmeOrder:
    """
    Creates an AcmeOrder invoking `make_one__AcmeOrder__api` with a random
    domain name for the http01 challenge
    """
    domain_names_http01 = generate_random_domain(testCase=testCase)
    dbAcmeOrder = make_one__AcmeOrder__api(
        testCase=testCase,
        domain_names_http01=domain_names_http01,
        processing_strategy=processing_strategy,
    )
    assert dbAcmeOrder
    return dbAcmeOrder


def make_one__DomainBlocklisted__database(
    testCase: CustomizedTestCase,
    domain_name: str,
) -> model_objects.DomainBlocklisted:
    """
    Inserts a domain name into the blocklist; raw sql manipulation
    """
    dbDomainBlocklisted = model_objects.DomainBlocklisted()
    dbDomainBlocklisted.domain_name = domain_name
    testCase.ctx.dbSession.add(dbDomainBlocklisted)
    testCase.ctx.dbSession.flush(
        objects=[
            dbDomainBlocklisted,
        ]
    )
    testCase.ctx.pyramid_transaction_commit()
    dbDomainBlocklisted = testCase.ctx.dbSession.merge(dbDomainBlocklisted)
    return dbDomainBlocklisted


def make_one__RenewalConfiguration__api(
    testCase: CustomizedTestCase,
    dbAcmeAccount: model_objects.AcmeAccount,
    domain_names_http01: str,
    private_key_cycle: Optional[str] = "account_default",
    key_technology: Optional[str] = "account_default",
) -> model_objects.RenewalConfiguration:
    """
    Create a RenewalConfiguration using the json api
    """
    res = testCase.testapp.get(
        "/.well-known/peter_sslers/renewal-configuration/new.json", status=200
    )
    assert "form_fields" in res.json

    form: Dict[str, Optional[str]] = {}
    form["account_key_option__primary"] = "account_key_existing"
    form["account_key_existing__primary"] = dbAcmeAccount.acme_account_key.key_pem_md5
    form["private_key_cycle__primary"] = private_key_cycle
    form["private_key_technology__primary"] = key_technology
    form["domain_names_http01"] = domain_names_http01

    res2 = testCase.testapp.post(
        "/.well-known/peter_sslers/renewal-configuration/new.json",
        form,
    )
    assert res2.json["result"] == "success"
    assert "RenewalConfiguration" in res2.json

    dbRenewalConfiguration = (
        testCase.ctx.dbSession.query(model_objects.RenewalConfiguration)
        .filter(
            model_objects.RenewalConfiguration.id
            == res2.json["RenewalConfiguration"]["id"]
        )
        .first()
    )
    assert dbRenewalConfiguration
    return dbRenewalConfiguration


def setup_SystemConfiguration__api(
    testCase: CustomizedTestCase,
    policy_name: Literal["autocert", "certificate-if-needed"],
    ensure_auth: bool = True,
) -> model_objects.AcmeOrder:
    """
    Uses the json API to copy the global configuration onto another specified policy
    """

    if policy_name == "global":
        raise ValueError("`global` is not supported")

    res = testCase.testapp.get(
        "/.well-known/peter_sslers/system-configuration/%s/edit.json" % policy_name,
        status=200,
    )
    assert "form_fields" in res.json

    dbSystemConfiguration_global = lib_db_get.get__SystemConfiguration__by_name(
        testCase.ctx, "global"
    )
    assert dbSystemConfiguration_global
    assert dbSystemConfiguration_global.is_configured

    form: Dict[str, Union[int, str, None]] = {}
    form["acme_account_id__backup"] = (
        dbSystemConfiguration_global.acme_account_id__backup
    )
    form["acme_account_id__primary"] = (
        dbSystemConfiguration_global.acme_account_id__primary
    )
    form["acme_profile__backup"] = dbSystemConfiguration_global.acme_profile__backup
    form["acme_profile__primary"] = dbSystemConfiguration_global.acme_profile__primary
    form["private_key_cycle__backup"] = (
        dbSystemConfiguration_global.private_key_cycle__backup
    )
    form["private_key_cycle__primary"] = (
        dbSystemConfiguration_global.private_key_cycle__primary
    )
    form["private_key_technology__backup"] = (
        dbSystemConfiguration_global.private_key_technology__backup
    )
    form["private_key_technology__primary"] = (
        dbSystemConfiguration_global.private_key_technology__primary
    )
    form["force_reconciliation"] = 1

    res2 = testCase.testapp.post(
        "/.well-known/peter_sslers/system-configuration/%s/edit.json" % policy_name,
        form,
    )
    assert res2.json["result"] == "success"
    assert "SystemConfiguration" in res2.json

    dbSystemConfiguration = lib_db_get.get__SystemConfiguration__by_name(
        testCase.ctx, policy_name
    )
    assert dbSystemConfiguration
    if not dbSystemConfiguration.is_configured:
        print("Why is this happening?")
        # this does not use `get`; it should be a fresh load
        testCase.ctx.dbSession.expire(dbSystemConfiguration)

    assert dbSystemConfiguration
    assert dbSystemConfiguration.is_configured

    if ensure_auth:
        # ensure auth/reg
        # pebble loses state across tests
        ensure_AcmeAccount_auth(
            testCase=testCase,
            acme_account_id=dbSystemConfiguration_global.acme_account_id__primary,
        )
        if dbSystemConfiguration_global.acme_account_id__backup:
            ensure_AcmeAccount_auth(
                testCase=testCase,
                acme_account_id=dbSystemConfiguration_global.acme_account_id__backup,
            )

    return dbSystemConfiguration


def ensure_AcmeAccount_auth(
    testCase: CustomizedTestCase,
    acme_account_id: Optional[int] = None,
):
    """
    Instructs the PeterSSLers app to authenticate/register the acme_account_id
    against the ACME server
    This is necessary because pebble loses state.

    If `acme_account_id` is not specified, will operate on the primary global account
    """
    if not acme_account_id:
        dbSystemConfiguration_global = lib_db_get.get__SystemConfiguration__by_name(
            testCase.ctx, "global"
        )
        if not dbSystemConfiguration_global:
            raise ValueError("missing `SystemConfiguration::global")
        if not dbSystemConfiguration_global.is_configured:
            raise ValueError("not `SystemConfiguration::global.is_configured`")
        if not dbSystemConfiguration_global.acme_account_id__primary:
            raise ValueError(
                "not `SystemConfiguration::global.acme_account_id__primary`"
            )
        acme_account_id = dbSystemConfiguration_global.acme_account_id__primary

    # authenticate will register; check will not
    # during test-runs, the pebble server will lose state so check will fail
    _resCheck = testCase.testapp.post(
        "/.well-known/peter_sslers/acme-account/%s/acme-server/authenticate"
        % acme_account_id,
        {},
    )
    assert _resCheck.location.endswith(
        "?result=success&operation=acme-server--authenticate&is_authenticated=True"
    )


def auth_SystemConfiguration_accounts__api(
    testCase: CustomizedTestCase,
    dbSystemConfiguration: model_objects.SystemConfiguration,
    auth_only: Optional[Literal["primary", "backup"]] = None,
    only_required: bool = False,
) -> bool:
    """
    Instructs the PeterSSLers app to authenticate/register the acme_account_id
    against the ACME server
    This is necessary because pebble loses state.

    This function calculates the necessary acme_accounts, then invokes
    `ensure_AcmeAccount_auth` to authenticate/register
    """
    _did_authenticate = False
    account_ids: List[int] = []
    if only_required and auth_only is None:
        _needs_primary = False
        _needs_backup = False
        if (
            # not authenticated
            (not dbSystemConfiguration.acme_account__primary.account_url)
            or
            # this is a migrated account; reauthenticate
            ("@" in dbSystemConfiguration.acme_account__primary.account_url)
        ):
            _needs_primary = True
        if dbSystemConfiguration.acme_account_id__backup and (
            # not authenticated
            (not dbSystemConfiguration.acme_account__backup.account_url)
            or
            # this is a migrated account; reauthenticate
            ("@" in dbSystemConfiguration.acme_account__backup.account_url)
        ):
            _needs_backup = True
        if not any((_needs_primary, _needs_backup)):
            return _did_authenticate
        if _needs_primary and not _needs_backup:
            auth_only = "primary"
        elif not _needs_primary and _needs_backup:
            auth_only = "backup"
    if auth_only == "primary":
        account_ids = [
            dbSystemConfiguration.acme_account_id__primary,
        ]
    elif auth_only == "backup":
        account_ids = (
            [
                dbSystemConfiguration.acme_account_id__backup,
            ]
            if dbSystemConfiguration.acme_account_id__backup
            else []
        )
    else:
        account_ids = [
            i
            for i in [
                dbSystemConfiguration.acme_account_id__primary,
                dbSystemConfiguration.acme_account_id__backup,
            ]
            if i
        ]

    if DEBUG_DATABASE_ODDITY:
        _resPre = testCase.testapp.get("/.well-known/peter_sslers/debug")
        print("PRE AUTH")
        pprint.pprint(_resPre.json)

    # return True if we authenticate for either account
    for _acme_account_id in account_ids:
        ensure_AcmeAccount_auth(testCase=testCase, acme_account_id=_acme_account_id)
        _did_authenticate = True

    if DEBUG_DATABASE_ODDITY:
        _resPost = testCase.testapp.get("/.well-known/peter_sslers/debug")
        print("POST AUTH")
        pprint.pprint(_resPost.json)

    testCase.ctx.dbSession.refresh(dbSystemConfiguration)
    return _did_authenticate


def ensure_RateLimited__database(
    testCase: CustomizedTestCase,
    acme_account_id: int = 1,
    domain_name: str = "example.com",
) -> Literal[True]:
    dbAcmeAccount = lib_db_get.get__AcmeAccount__by_id(testCase.ctx, acme_account_id)
    dbDomain, _created = lib_db_getcreate.getcreate__Domain__by_domainName(
        testCase.ctx, domain_name
    )
    dbUniqueFQDNSet, _created = (
        lib_db_getcreate.getcreate__UniqueFQDNSet__by_domainObjects(
            testCase.ctx, [dbDomain]
        )
    )
    if TYPE_CHECKING:
        assert dbAcmeAccount
        assert dbDomain
        assert dbUniqueFQDNSet
    # this mocks BuyPass
    for i in range(0, 5):
        rl = lib_db_create.create__RateLimited(  # noqa: F841
            ctx=testCase.ctx,
            dbAcmeServer=dbAcmeAccount.acme_server,
            dbAcmeAccount=dbAcmeAccount,
            dbUniqueFQDNSet=dbUniqueFQDNSet,
            server_response_body={
                "type": "urn:ietf:params:acme:error:rateLimited",
                "title": "Too Many Requests",
                "status": 429,
                "detail": "Too many certificates issued already for requested domains",
                "instance": "/acme/new-order",
            },
            server_response_headers={},
        )
    testCase.ctx.pyramid_transaction_commit()
    return True


def ensure_SystemConfiguration__database(
    testCase: CustomizedTestCase,
    policy_name: Literal["autocert", "certificate-if-needed"],
) -> model_objects.SystemConfiguration:
    """
    NOTE:
        `unset_testing_data__AppTest` will set dbSystemConfiguration.is_configured to False
        but everything else will remain configured
        this is just to accomodate tests that flow through the setup
    """
    dbSystemConfiguration = lib_db_get.get__SystemConfiguration__by_name(
        testCase.ctx, policy_name
    )
    assert dbSystemConfiguration
    if not dbSystemConfiguration.is_configured:
        _sysconfigGlobal = lib_db_get.get__SystemConfiguration__by_name(
            testCase.ctx, "global"
        )
        assert _sysconfigGlobal
        _updated = lib_db_update.update_SystemConfiguration(
            ctx=testCase.ctx,
            dbSystemConfiguration=dbSystemConfiguration,
            acme_account_id__primary=_sysconfigGlobal.acme_account_id__primary,
            private_key_cycle__primary=_sysconfigGlobal.private_key_cycle__primary,
            private_key_technology__primary=_sysconfigGlobal.private_key_technology__primary,
            acme_profile__primary=_sysconfigGlobal.acme_profile__primary,
            acme_account_id__backup=_sysconfigGlobal.acme_account_id__backup,
            private_key_cycle__backup=_sysconfigGlobal.private_key_cycle__backup,
            private_key_technology__backup=_sysconfigGlobal.private_key_technology__backup,
            acme_profile__backup=_sysconfigGlobal.acme_profile__backup,
            force_reconciliation=True,
        )
        testCase.ctx.pyramid_transaction_commit()
        dbSystemConfiguration = testCase.ctx.dbSession.merge(dbSystemConfiguration)
        assert dbSystemConfiguration.is_configured
    return dbSystemConfiguration


def check_error_AcmeDnsServerError(
    response_type: Literal["html", "json"],
    response: "Response",
) -> None:
    """
    checks response for acme-dns errors; raises an exception if found
    """
    search_message = "Error communicating with the acme-dns server."
    if response_type == "html":
        if response.status_code == 200:
            if search_message in response.text:
                raise lib_errors.AcmeDnsServerError()
    elif response_type == "json":
        if response.json["result"] == "error":
            if "form_errors" in response.json:
                if search_message in response.json["form_errors"]["Error_Main"]:
                    raise lib_errors.AcmeDnsServerError()
            elif "error" in response.json:
                if response.json["error"] == search_message:
                    raise lib_errors.AcmeDnsServerError()


def unset_testing_data__AppTest_Class(testCase: CustomizedTestCase) -> Literal[True]:
    """
    invoked by AppTest.tearDownClass
    """
    prefix = testcaseClass_to_prefix(testCase)
    ctx = new_test_connections()
    domains = (
        ctx.dbSession.query(model_objects.Domain)
        .filter(model_objects.Domain.domain_name.istartswith(prefix))
        .all()
    )
    for domain in domains:
        for aap in domain.acme_authorization_potentials:
            if aap.acme_order.is_processing in (True, None):
                update_AcmeOrder_deactivate(ctx, aap.acme_order)
            update_AcmeOrder_deactivate_AcmeAuthorizationPotentials(ctx, aap.acme_order)
            ctx.pyramid_transaction_commit()
    return True


def unset_testing_data__AppTest(testCase: CustomizedTestCase) -> Literal[True]:
    """
    invoked by AppTest.setUp & AppTest.tearDown
    """
    testCase.ctx.pyramid_transaction_commit()
    # note: deactivate AcmeOrders
    dbAcmeOrders = (
        testCase.ctx.dbSession.query(model_objects.AcmeOrder)
        .order_by(model_objects.AcmeOrder.id.asc())
        .filter(model_objects.AcmeOrder.is_processing.is_(True))
        .all()
    )
    for _dbAcmeOrder in dbAcmeOrders:
        result = lib_db_update.update_AcmeOrder_deactivate(testCase.ctx, _dbAcmeOrder)

    # note: delete RateLimited
    stmt = sqlalchemy.delete(model_objects.RateLimited)
    executed = testCase.ctx.dbSession.execute(stmt)

    # note: deactivate RenewalConfigurations
    dbRenewalConfigurations = (
        testCase.ctx.dbSession.query(model_objects.RenewalConfiguration)
        .order_by(model_objects.RenewalConfiguration.id.asc())
        .filter(model_objects.RenewalConfiguration.is_active.is_(True))
        .all()
    )
    for _dbRenewalConfiguration in dbRenewalConfigurations:
        _result = lib_db_update.update_RenewalConfiguration__unset_active(
            testCase.ctx, _dbRenewalConfiguration
        )
    # note: unset SystemConfigurations
    dbSystemConfigurations = (
        testCase.ctx.dbSession.query(model_objects.SystemConfiguration)
        .filter(
            model_objects.SystemConfiguration.name != "global",
            model_objects.SystemConfiguration.is_configured.is_(True),
        )
        .all()
    )
    for dbSystemConfiguration in dbSystemConfigurations:
        dbSystemConfiguration.is_configured = False

    # make sure every acme-account will not use a cache and sync on the next test
    lib_db_actions.unset_acme_server_caches(testCase.ctx, transaction_commit=True)

    testCase.ctx.pyramid_transaction_commit()
    return True


class ResponseFailureOkay(Exception):
    """
    used to catch a response failure
    args[0] should be the response
    """

    pass


class FakeAccountKeyData(AccountKeyData):
    """
    implements minimum amount of `cert_utils.model.AccountKeyData`
    """

    def __init__(self, thumbprint: str) -> None:
        self.thumbprint = thumbprint


class FakeAuthenticatedUser(object):
    """
    implements minimum amount of `acme_v2.AuthenticatedUser`
    """

    accountKeyData = None  # an instance conforming to `AccountKeyData`
    ctx = None  # ApiContext

    def __init__(self, accountkey_thumbprint: str) -> None:
        self.accountKeyData = FakeAccountKeyData(thumbprint=accountkey_thumbprint)


class _Mixin_filedata(object):
    """
    mixin used to make certain filepaths easily accessible
    """

    _data_root = os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data")
    _data_root_letsencrypt = os.path.join(
        os.path.dirname(os.path.realpath(cert_utils.__file__)),
        "letsencrypt-certs",
    )

    def _filepath_testfile(self, filename: str) -> str:
        if filename.startswith("letsencrypt-certs/"):
            filename = filename[18:]
            return os.path.join(self._data_root_letsencrypt, filename)
        return os.path.join(self._data_root, filename)

    @overload
    def _filedata_testfile(  # noqa: E704
        self,
        filename: str,
        is_binary: Literal[False] = False,
    ) -> str: ...

    @overload
    def _filedata_testfile(  # noqa: E704
        self,
        filename: str,
        is_binary: Literal[True] = True,
    ) -> bytes: ...

    def _filedata_testfile(
        self,
        filename: str,
        is_binary: Literal[False, True] = False,
    ) -> Union[str, bytes]:
        _data_root = self._data_root
        if filename.startswith("letsencrypt-certs/"):
            filename = filename[18:]
            _data_root = self._data_root_letsencrypt
        if is_binary:
            with open(os.path.join(_data_root, filename), "rb") as f:
                data_b = f.read()
            return data_b
        with open(os.path.join(_data_root, filename), "rt", encoding="utf-8") as f:
            data_s = f.read()
        return data_s


class AppTestCore(CustomizedTestCase, _Mixin_filedata):
    """
    AppTestCore provides the main support for testing.

    It should never be used directly, but instead subclassed.

    When subclassing Follow a wrapper style ingress/egress:

        def setUp(self):
            AppTestCore.setUp(self)
            # subclass work

        def tearDown(self):
            # subclass work
            AppTestCore.tearDown(self)
    """

    _testapp: Optional[TestApp] = None
    _testapp_wsgi: Optional[StopableWSGIServer] = None
    _pyramid_app: Router
    _session_factory = None
    _settings: Dict
    _currentTest: Optional[str] = None

    # AppTestCore Class Variable
    _DB_INTIALIZED = False

    @property
    def testapp(self) -> Union[TestApp, StopableWSGIServer]:
        if self._testapp:
            return self._testapp
        elif self._testapp_wsgi:
            return self._testapp_wsgi
        raise RuntimeError("no testapp configured")

    def setUp(self) -> None:
        print("AppTestCore.setUp")
        log.critical(
            "%s.%s | AppTestCore.setUp"
            % (self.__class__.__name__, self._testMethodName)
        )
        AppTestCore._currentTest = "%s.%s" % (
            self.__class__.__name__,
            self._testMethodName,
        )
        self._settings = GLOBAL_appsettings

        # sqlalchemy.url = sqlite:///%(here)s/example_ssl_minnow_test.sqlite
        # settings["sqlalchemy.url"] = "sqlite://"

        self._session_factory = get_session_factory(get_engine(GLOBAL_appsettings))
        engine = self._session_factory().bind
        assert isinstance(engine, sqlalchemy.engine.base.Engine)
        assert engine.driver == "pysqlite"

        # have we initialized the database?
        # IMPORTANT: we can't connect first, even just to vacuum
        # that will trigger these checks to pass
        dbfile = engine.url.database
        if TYPE_CHECKING:
            assert isinstance(dbfile, str)
        dbfile = os.path.normpath(dbfile)
        if os.path.exists(dbfile):
            if os.path.getsize(dbfile):
                AppTestCore._DB_INTIALIZED = True

        print(
            "AppTestCore.setUp | AppTestCore._DB_INTIALIZED==",
            AppTestCore._DB_INTIALIZED,
        )
        if not AppTestCore._DB_INTIALIZED:
            print("AppTestCore.setUp | initialize db")
            model_meta.Base.metadata.drop_all(engine)
            with engine.begin() as connection:
                connection.execute(sqlalchemy.text("VACUUM"))
            model_meta.Base.metadata.create_all(engine)
            request = FakeRequest()
            dbSession = self._session_factory(info={"request": request})
            if db_unfreeze(dbSession, "AppTestCore", testCase=self):
                print("AppTestCore.setUp | using frozen database")
            else:
                print("AppTestCore.setUp | recreating the database")

                request = FakeRequest()
                ctx = ApiContext(
                    dbSession=dbSession,
                    request=request,
                    config_uri=TEST_INI,
                    application_settings=GLOBAL_ApplicationSettings,
                )
                # this would have been invoked by `initializedb`
                db._setup.initialize_database(ctx)
                ctx.pyramid_transaction_commit()
                dbSession.close()
                db_freeze(dbSession, "AppTestCore")
        else:
            with engine.begin() as connection:
                connection.execute(sqlalchemy.text("VACUUM"))
        self._pyramid_app = app = main(global_config=None, **GLOBAL_appsettings)
        self._testapp = TestApp(
            app,
            extra_environ={
                "HTTP_HOST": "peter-sslers.example.com",
            },
        )
        AppTestCore._DB_INTIALIZED = True
        if DEBUG_METRICS:
            self._db_filename = self.ctx.dbSession.connection().engine.url.database
            if TYPE_CHECKING:
                assert self._db_filename
            self._db_filesize = {
                "setUp": os.path.getsize(self._db_filename),
            }
            self._wrapped_start = time.time()

    def tearDown(self) -> None:
        if DEBUG_METRICS:
            """
            The filegrowth of the db is due to how Pebble wraps each run
            """
            testname = "%s.%s" % (self.__class__.__name__, self._testMethodName)
            count_acme_order = self.ctx.dbSession.query(model_objects.AcmeOrder).count()
            count_x509_certificate_trusted = self.ctx.dbSession.query(  # Pebble certs
                model_objects.X509CertificateTrusted
            ).count()
            if TYPE_CHECKING:
                assert self._db_filename
            self._db_filesize["tearDown"] = os.path.getsize(self._db_filename)
            self._wrapped_end = time.time()

            fname = "%s/_METRICS.txt" % DIR_TESTRUN
            if not os.path.exists(fname):
                with open(fname, "w") as fh:
                    fh.write(
                        "TestName\tCount[AcmeOrder]\tCount[X509CertificateTrusted]\tDBFilesize[setUp]\tDBFilesize[tearDown]\tWrappedTiming\n"
                    )
            with open(fname, "a") as fh:
                fh.write(
                    "%s\t%s\t%s\t%s\t%s\t%s\n"
                    % (
                        testname,
                        count_acme_order,
                        count_x509_certificate_trusted,
                        self._db_filesize["setUp"],
                        self._db_filesize["tearDown"],
                        (self._wrapped_end - self._wrapped_start),
                    )
                )
        self._session_factory = None
        self._turnoff_items()

    _ctx: Optional[ApiContext] = None

    @property
    def ctx(self) -> ApiContext:
        """
        originally in `AppTest`, not `AppTestCore` but some functions here need it
        """
        if self._ctx is None:
            dbSession_factory = self._pyramid_app.registry["dbSession_factory"]
            request = FakeRequest()

            self._ctx = ApiContext(
                request=request,
                dbSession=dbSession_factory(info={"request": request}),
                config_uri=TEST_INI,
                application_settings=GLOBAL_ApplicationSettings,
            )
            # merge in the settings
            if TYPE_CHECKING:
                assert self._ctx.request is not None
            self._ctx.request.registry.settings = self._pyramid_app.registry.settings
        return self._ctx

    def _turnoff_items(self) -> None:
        """when running multiple tests, ensure we turn off blocking items"""
        _query = self.ctx.dbSession.query(model_objects.AcmeOrder).filter(
            model_objects.AcmeOrder.acme_status_order_id.in_(
                model_utils.Acme_Status_Order.IDS_BLOCKING
            ),
        )
        _changed = None
        _orders = _query.all()
        for _order in _orders:
            _acme_status_order_id = model_utils.Acme_Status_Order.X_410_X
            if _order.acme_status_order_id != _acme_status_order_id:
                _order.acme_status_order_id = _acme_status_order_id
                _order.timestamp_updated = self.ctx.timestamp
                _changed = True
            try:
                _changed = db.update.update_AcmeOrder_deactivate(self.ctx, _order)
            except errors.InvalidTransition as exc:
                # don't fret on this having an invalid
                pass
        if _changed:
            self.ctx.pyramid_transaction_commit()

    def _has_active_challenges(self) -> List[model_objects.AcmeChallenge]:
        """
        utility function for debugging, not used by code
        modified version of `lib.db.get.get__AcmeChallenges__by_DomainId__active`
        """
        query = (
            self.ctx.dbSession.query(model_objects.AcmeChallenge)
            # Path1: AcmeChallenge>AcmeAuthorization>AcmeOrder2AcmeAuthorization>AcmeOrder
            .join(
                model_objects.AcmeAuthorization,
                model_objects.AcmeChallenge.acme_authorization_id
                == model_objects.AcmeAuthorization.id,
                isouter=True,
            )
            .join(
                model_objects.AcmeOrder2AcmeAuthorization,
                model_objects.AcmeAuthorization.id
                == model_objects.AcmeOrder2AcmeAuthorization.acme_order_id,
                isouter=True,
            )
            .join(
                model_objects.AcmeOrder,
                model_objects.AcmeOrder2AcmeAuthorization.acme_order_id
                == model_objects.AcmeOrder.id,
                isouter=True,
            )
            # shared filters
            .join(
                model_objects.Domain,
                model_objects.AcmeChallenge.domain_id == model_objects.Domain.id,
            )
            .filter(
                model_objects.Domain.domain_name.notin_(("selfsigned-1.example.com",)),
                sqlalchemy.or_(
                    # Path1 - Order Based Authorizations
                    sqlalchemy.and_(
                        model_objects.AcmeChallenge.acme_authorization_id.is_not(None),
                        model_objects.AcmeChallenge.acme_status_challenge_id.in_(
                            model_utils.Acme_Status_Challenge.IDS_POSSIBLY_ACTIVE
                        ),
                        model_objects.AcmeAuthorization.acme_status_authorization_id.in_(
                            model_utils.Acme_Status_Authorization.IDS_POSSIBLY_PENDING
                        ),
                        model_objects.AcmeOrder.acme_status_order_id.in_(
                            model_utils.Acme_Status_Order.IDS_BLOCKING
                        ),
                    ),
                ),
            )
        )
        res = query.all()
        return res


# ==============================================================================


class AppTest(AppTestCore):
    """
    The main Testing class
    """

    # AppTest Class Variable
    _DB_SETUP_RECORDS = False

    def _setUp_X509Certificates_FormatA(
        self, payload_section: str, payload_key: str
    ) -> None:
        filename_template = None
        if payload_section == "AlternateChains":
            filename_template = "alternate_chains/%s/%%s" % payload_key
        elif payload_section == "Pebble":
            filename_template = "pebble-certs/%s"
        else:
            raise ValueError("invalid payload_section")
        _pkey_filename = (
            filename_template
            % TEST_FILES["X509Certificates"][payload_section][payload_key]["pkey"]
        )
        _pkey_pem = self._filedata_testfile(_pkey_filename)
        (
            _dbPrivateKey,
            _is_created,
        ) = db.getcreate.getcreate__PrivateKey__by_pem_text(
            self.ctx,
            _pkey_pem,
            private_key_source_id=model_utils.PrivateKeySource.IMPORTED,
            private_key_type_id=model_utils.PrivateKeyType.STANDARD,
        )
        _chain_filename = (
            filename_template
            % TEST_FILES["X509Certificates"][payload_section][payload_key]["chain"]
        )
        _chain_pem = self._filedata_testfile(_chain_filename)
        (
            _dbChain,
            _is_created,
        ) = db.getcreate.getcreate__X509CertificateTrustChain__by_pem_text(
            self.ctx, _chain_pem, display_name=_chain_filename
        )

        dbX509CertificateTrustChains_alt = None
        if (
            "alternate_chains"
            in TEST_FILES["X509Certificates"][payload_section][payload_key]
        ):
            dbX509CertificateTrustChains_alt = []
            for _chain_index in TEST_FILES["X509Certificates"][payload_section][
                payload_key
            ]["alternate_chains"]:
                _chain_subpath = "alternate_chains/%s/%s" % (
                    payload_key,
                    TEST_FILES["X509Certificates"][payload_section][payload_key][
                        "alternate_chains"
                    ][_chain_index]["chain"],
                )
                _chain_filename = filename_template % _chain_subpath
                _chain_pem = self._filedata_testfile(_chain_filename)
                (
                    _dbChainAlternate,
                    _is_created,
                ) = db.getcreate.getcreate__X509CertificateTrustChain__by_pem_text(
                    self.ctx, _chain_pem, display_name=_chain_filename
                )
                dbX509CertificateTrustChains_alt.append(_dbChainAlternate)

        _cert_filename = (
            filename_template
            % TEST_FILES["X509Certificates"][payload_section][payload_key]["cert"]
        )
        _cert_domains_expected = [
            TEST_FILES["X509Certificates"][payload_section][payload_key]["domain"],
        ]
        (
            _dbUniqueFQDNSet,
            _is_created,
        ) = db.getcreate.getcreate__UniqueFQDNSet__by_domains(
            self.ctx,
            _cert_domains_expected,
        )
        _cert_pem = self._filedata_testfile(_cert_filename)

        (
            _dbX509Certificate,
            _is_created,
        ) = db.getcreate.getcreate__X509Certificate(
            self.ctx,
            _cert_pem,
            cert_domains_expected=_cert_domains_expected,
            dbX509CertificateTrustChain=_dbChain,
            dbPrivateKey=_dbPrivateKey,
            certificate_type_id=model_utils.CertificateType.RAW_IMPORTED,
            # optionals
            dbX509CertificateTrustChains_alt=dbX509CertificateTrustChains_alt,
            dbUniqueFQDNSet=_dbUniqueFQDNSet,
            is_active=True,
        )

        # commit this!
        self.ctx.pyramid_transaction_commit()

    def setUp(self) -> None:
        print("AppTest.setUp")
        log.critical(
            "%s.%s | AppTest.setUp" % (self.__class__.__name__, self._testMethodName)
        )
        AppTestCore.setUp(self)
        print("AppTest.setUp | AppTest._DB_SETUP_RECORDS==", AppTest._DB_SETUP_RECORDS)
        if not AppTest._DB_SETUP_RECORDS:
            # Freezepoint- AppTest
            # This freezepoint wraps the core system setup data
            unfrozen = db_unfreeze(self.ctx.dbSession, "AppTest", testCase=self)
            print("unfrozen?", unfrozen)
            if unfrozen:
                print("AppTest.setUp | using frozen database")
            else:
                print("AppTest.setUp | setup sample db records")
                try:
                    """
                    This setup pre-populates the DB with some mocked objects needed for routes to work:

                        AccountKey:
                            account_1.key
                        X509CertificateTrusteds:
                            isrgrootx1.pem
                            selfsigned_1-server.crt
                        PrivateKey
                            selfsigned_1-server.key
                        AcmeEventLog
                        AcmeOrder
                    """
                    # note: pre-populate AcmeAccount
                    # this should create `/acme-account/1`

                    _dbAcmeServer_1 = db.get.get__AcmeServer__by_name(
                        self.ctx, "pebble"
                    )
                    if not _dbAcmeServer_1:
                        raise ValueError(
                            "get__AcmeServer__by_name(pebble) not configured"
                        )
                    _dbAcmeServer_2 = db.get.get__AcmeServer__by_name(
                        self.ctx, "pebble-alt"
                    )
                    if not _dbAcmeServer_2:
                        raise ValueError(
                            "get__AcmeServer__by_name(pebble-alt) not configured"
                        )

                    _dbAcmeAccount_1: model_objects.AcmeAccount
                    _dbAcmeAccount_2: model_objects.AcmeAccount
                    for _id in TEST_FILES["AcmeAccount"]:
                        _key_filename = TEST_FILES["AcmeAccount"][_id]["key"]
                        _order_default_private_key_cycle = TEST_FILES["AcmeAccount"][
                            _id
                        ]["order_default_private_key_cycle"]
                        _order_default_private_key_technology = TEST_FILES[
                            "AcmeAccount"
                        ][_id]["order_default_private_key_technology"]
                        key_pem = self._filedata_testfile(_key_filename)
                        (
                            _dbAcmeAccount,
                            _is_created,
                        ) = db.getcreate.getcreate__AcmeAccount(
                            self.ctx,
                            acme_account_key_source_id=model_utils.AcmeAccountKeySource.IMPORTED,
                            key_pem=key_pem,
                            contact=TEST_FILES["AcmeAccount"][_id]["contact"],
                            acme_server_id=(
                                _dbAcmeServer_1.id
                                if TEST_FILES["AcmeAccount"][_id]["provider"]
                                == "pebble"
                                else _dbAcmeServer_2.id
                            ),
                            event_type="AcmeAccount__insert",
                            order_default_private_key_cycle_id=model_utils.PrivateKeyCycle.from_string(
                                _order_default_private_key_cycle
                            ),
                            order_default_private_key_technology_id=model_utils.KeyTechnology.from_string(
                                _order_default_private_key_technology
                            ),
                        )
                        # print(_dbAcmeAccount_1, _is_created)
                        # self.ctx.pyramid_transaction_commit()

                        if _id == "1":
                            _dbAcmeAccount_1 = _dbAcmeAccount
                        elif _id == "5":
                            # 11 is same as 1, but on `pebble_alt`
                            _dbAcmeAccount_2 = _dbAcmeAccount
                        self.ctx.pyramid_transaction_commit()

                    dbSystemConfiguration_global = (
                        lib_db_get.get__SystemConfiguration__by_name(self.ctx, "global")
                    )
                    assert dbSystemConfiguration_global

                    _updated = lib_db_update.update_SystemConfiguration(
                        ctx=self.ctx,
                        dbSystemConfiguration=dbSystemConfiguration_global,
                        acme_account_id__primary=_dbAcmeAccount_1.id,
                        private_key_cycle__primary=dbSystemConfiguration_global.private_key_cycle__primary,
                        private_key_technology__primary=dbSystemConfiguration_global.private_key_technology__primary,
                        acme_profile__primary=dbSystemConfiguration_global.acme_profile__primary,
                        acme_account_id__backup=_dbAcmeAccount_2.id,
                        private_key_cycle__backup=dbSystemConfiguration_global.private_key_cycle__backup,
                        private_key_technology__backup=dbSystemConfiguration_global.private_key_technology__backup,
                        acme_profile__backup=dbSystemConfiguration_global.acme_profile__backup,
                        force_reconciliation=True,
                    )

                    # note: pre-populate X509CertificateTrusted
                    # this should create `/certificate-ca/1`
                    #
                    _cert_ca_id = "isrg_root_x1"
                    _cert_ca_filename = TEST_FILES["X509CertificateTrusteds"]["cert"][
                        _cert_ca_id
                    ]
                    _display_name = letsencrypt_info.CERT_CAS_DATA[_cert_ca_id][
                        "display_name"
                    ]

                    cert_ca_pem = self._filedata_testfile(_cert_ca_filename)
                    (
                        _cert_ca_1,
                        _is_created,
                    ) = db.getcreate.getcreate__X509CertificateTrusted__by_pem_text(
                        self.ctx,
                        cert_ca_pem,
                        display_name=_display_name,
                    )
                    # print(_cert_ca_1, _is_created)
                    # self.ctx.pyramid_transaction_commit()

                    # we need a few PrivateKeys, because we'll turn them off
                    for pkey_id in TEST_FILES["PrivateKey"].keys():
                        _pkey_filename = TEST_FILES["PrivateKey"][pkey_id]["file"]
                        _pkey_pem = self._filedata_testfile(_pkey_filename)
                        (
                            _dbPrivateKey_alt,
                            _is_created,
                        ) = db.getcreate.getcreate__PrivateKey__by_pem_text(
                            self.ctx,
                            _pkey_pem,
                            private_key_source_id=model_utils.PrivateKeySource.IMPORTED,
                            private_key_type_id=model_utils.PrivateKeyType.STANDARD,
                        )

                        if pkey_id == "5":
                            # make a CoverageAssuranceEvent
                            _event_type_id = (
                                model_utils.OperationsEventType.from_string(
                                    "PrivateKey__revoke"
                                )
                            )
                            _event_payload_dict = utils.new_event_payload_dict()
                            _event_payload_dict["private_key.id"] = _dbPrivateKey_alt.id
                            _event_payload_dict["action"] = "compromised"
                            # ALWAYS log PrivateKeyCompromised
                            _dbOperationsEvent = db.logger.log__OperationsEvent(
                                self.ctx, _event_type_id, _event_payload_dict
                            )
                            _event_status = (
                                db.update.update_PrivateKey__set_compromised(
                                    self.ctx, _dbPrivateKey_alt, _dbOperationsEvent
                                )
                            )

                    # note: pre-populate X509Certificate 1-5
                    # this should create `/x509-certificate/1`
                    #
                    _dbAcmeOrder = None
                    _dbX509Certificate_1 = None
                    _dbX509Certificate_2 = None
                    _dbX509Certificate_3 = None
                    _dbX509Certificate_4 = None
                    _dbX509Certificate_5 = None
                    _dbPrivateKey_1 = None
                    _dbRenewalConfiguration = None
                    _dbUniqueFQDNSet_1: model_objects.UniqueFQDNSet
                    for _id in TEST_FILES["X509Certificates"]["SelfSigned"].keys():
                        # note: pre-populate PrivateKey
                        # this should create `/private-key/1`
                        _pkey_filename = TEST_FILES["X509Certificates"]["SelfSigned"][
                            _id
                        ]["pkey"]
                        pkey_pem = self._filedata_testfile(_pkey_filename)
                        (
                            _dbPrivateKey,
                            _is_created,
                        ) = db.getcreate.getcreate__PrivateKey__by_pem_text(
                            self.ctx,
                            pkey_pem,
                            private_key_source_id=model_utils.PrivateKeySource.IMPORTED,
                            private_key_type_id=model_utils.PrivateKeyType.STANDARD,
                        )
                        # print(_dbPrivateKey, _is_created)
                        # self.ctx.pyramid_transaction_commit()

                        # note: pre-populate X509CertificateTrusted - self-signed
                        # this should create `/certificate-ca/2`
                        #
                        _cert_ca_filename = TEST_FILES["X509Certificates"][
                            "SelfSigned"
                        ][_id]["cert"]
                        chain_pem = self._filedata_testfile(_cert_ca_filename)
                        (
                            _dbX509CertificateTrustChain_SelfSigned,
                            _is_created,
                        ) = db.getcreate.getcreate__X509CertificateTrustChain__by_pem_text(
                            self.ctx, chain_pem, display_name=_cert_ca_filename
                        )
                        # print(_dbX509CertificateTrustChain_SelfSigned, _is_created)
                        # self.ctx.pyramid_transaction_commit()

                        _cert_filename = TEST_FILES["X509Certificates"]["SelfSigned"][
                            _id
                        ]["cert"]
                        _cert_domains_expected = [
                            TEST_FILES["X509Certificates"]["SelfSigned"][_id]["domain"],
                        ]
                        (
                            _dbUniqueFQDNSet,
                            _is_created,
                        ) = db.getcreate.getcreate__UniqueFQDNSet__by_domains(
                            self.ctx,
                            _cert_domains_expected,
                        )

                        cert_pem = self._filedata_testfile(_cert_filename)
                        (
                            _dbX509Certificate,
                            _is_created,
                        ) = db.getcreate.getcreate__X509Certificate(
                            self.ctx,
                            cert_pem,
                            cert_domains_expected=_cert_domains_expected,
                            dbX509CertificateTrustChain=_dbX509CertificateTrustChain_SelfSigned,
                            certificate_type_id=model_utils.CertificateType.RAW_IMPORTED,
                            dbPrivateKey=_dbPrivateKey,
                            # optionals
                            dbUniqueFQDNSet=_dbUniqueFQDNSet,
                            is_active=True,
                        )
                        # print(_dbX509Certificate_1, _is_created)
                        # self.ctx.pyramid_transaction_commit()

                        if _id == "1":
                            _dbPrivateKey_1 = _dbPrivateKey
                            _dbUniqueFQDNSet_1 = _dbUniqueFQDNSet
                            _dbX509Certificate_1 = _dbX509Certificate
                        elif _id == "2":
                            _dbX509Certificate_2 = _dbX509Certificate
                        elif _id == "3":
                            _dbX509Certificate_3 = _dbX509Certificate
                        elif _id == "4":
                            _dbX509Certificate_4 = _dbX509Certificate
                        elif _id == "5":
                            _dbX509Certificate_5 = _dbX509Certificate

                    if _dbPrivateKey_1 is None:
                        raise ValueError(
                            "`_dbPrivateKey_1` should have been set on first iteration"
                        )

                    # note: pre-populate Domain
                    # ensure we have domains?
                    domains = db.get.get__Domain__paginated(self.ctx)
                    domain_names = [d.domain_name for d in domains]
                    assert (
                        TEST_FILES["X509Certificates"]["SelfSigned"]["1"][
                            "domain"
                        ].lower()
                        in domain_names
                    )

                    # note: pre-populate X509CertificateRequest
                    _csr_filename = TEST_FILES["X509Certificates"]["SelfSigned"]["1"][
                        "csr"
                    ]
                    csr_pem = self._filedata_testfile(_csr_filename)
                    (
                        _dbX509CertificateRequest_1,
                        _is_created,
                    ) = db.getcreate.getcreate__X509CertificateRequest__by_pem_text(
                        self.ctx,
                        csr_pem,
                        x509_certificate_request_source_id=model_utils.X509CertificateRequestSource.IMPORTED,
                        dbPrivateKey=_dbPrivateKey_1,
                        domain_names=[
                            TEST_FILES["X509Certificates"]["SelfSigned"]["1"]["domain"],
                        ],  # make it an iterable
                    )

                    # note: pre-populate X509CertificateRequest 6-10, via "Pebble"
                    for _id in TEST_FILES["X509Certificates"]["Pebble"].keys():
                        self._setUp_X509Certificates_FormatA("Pebble", _id)

                    # self.ctx.pyramid_transaction_commit()

                    # note: pre-populate AcmeOrder

                    # merge these items in
                    _dbAcmeAccount_1 = self.ctx.dbSession.merge(
                        _dbAcmeAccount_1, load=False
                    )
                    _dbAcmeAccount_2 = self.ctx.dbSession.merge(
                        _dbAcmeAccount_2, load=False
                    )
                    _dbPrivateKey_1 = self.ctx.dbSession.merge(
                        _dbPrivateKey_1, load=False
                    )
                    _dbUniqueFQDNSet_1 = self.ctx.dbSession.merge(
                        _dbUniqueFQDNSet_1, load=False
                    )

                    # pre-populate AcmeOrder/AcmeChallenge
                    _acme_order_response = {
                        "status": "pending",
                        "expires": "2047-01-01T14:09:07.99Z",
                        "authorizations": [
                            "https://example.com/acme/authz/acmeOrder-1--authz-1",
                        ],
                        "finalize": "https://example.com/acme/authz/acmeOrder-1--finalize",
                        "identifiers": [
                            {"type": "dns", "value": "selfsigned-1.example.com"}
                        ],
                    }
                    _acme_order_type_id = (
                        model_utils.AcmeOrderType.ACME_ORDER_NEW_FREEFORM
                    )
                    _acme_order_processing_status_id = (
                        model_utils.AcmeOrder_ProcessingStatus.created_acme
                    )
                    _acme_order_processing_strategy_id = (
                        model_utils.AcmeOrder_ProcessingStrategy.create_order
                    )
                    _private_key_cycle_id__renewal = (
                        model_utils.PrivateKeyCycle.SINGLE_USE
                    )
                    _private_key_strategy_id__requested = (
                        model_utils.PrivateKeyStrategy.SPECIFIED
                    )
                    key_technology_id = model_utils.KeyTechnology.RSA_2048
                    _acme_event_id = model_utils.AcmeEvent.from_string("v2|newOrder")

                    _dbAcmeEventLog = model_objects.AcmeEventLog()
                    _dbAcmeEventLog.acme_event_id = _acme_event_id
                    _dbAcmeEventLog.timestamp_event = datetime.datetime.now(
                        datetime.timezone.utc
                    )
                    _dbAcmeEventLog.acme_account_id = _dbAcmeAccount_1.id
                    _dbAcmeEventLog.unique_fqdn_set_id = _dbUniqueFQDNSet_1.id
                    self.ctx.dbSession.add(_dbAcmeEventLog)
                    self.ctx.dbSession.flush()

                    _authenticatedUser = FakeAuthenticatedUser(
                        accountkey_thumbprint="accountkey_thumbprint"
                    )

                    _domains_challenged = model_utils.DomainsChallenged.new_http01(
                        _dbUniqueFQDNSet_1.domains_as_list
                    )

                    _dbRenewalConfiguration = db.create.create__RenewalConfiguration(
                        self.ctx,
                        domains_challenged=_domains_challenged,
                        dbAcmeAccount__primary=_dbAcmeAccount_1,
                        private_key_cycle_id__primary=_private_key_cycle_id__renewal,
                        private_key_technology_id__primary=_dbPrivateKey_1.key_technology_id,
                        note="setUp",
                    )

                    _private_key_deferred_id = (
                        model_utils.PrivateKeyDeferred.NOT_DEFERRED
                    )
                    _dbAcmeOrder = db.create.create__AcmeOrder(
                        self.ctx,
                        acme_order_rfc__original=_acme_order_response,
                        acme_order_type_id=_acme_order_type_id,
                        acme_order_processing_status_id=_acme_order_processing_status_id,
                        acme_order_processing_strategy_id=_acme_order_processing_strategy_id,
                        domains_challenged=_domains_challenged,
                        order_url="https://example.com/acme/order/acmeOrder-1",
                        certificate_type_id=model_utils.CertificateType.MANAGED_PRIMARY,
                        dbAcmeAccount=_dbAcmeAccount_1,
                        dbUniqueFQDNSet=_dbUniqueFQDNSet_1,
                        dbEventLogged=_dbAcmeEventLog,
                        dbRenewalConfiguration=_dbRenewalConfiguration,
                        dbPrivateKey=_dbPrivateKey_1,
                        private_key_cycle_id=_private_key_cycle_id__renewal,
                        private_key_strategy_id__requested=_private_key_strategy_id__requested,
                        private_key_deferred_id=_private_key_deferred_id,
                        transaction_commit=True,
                        is_save_alternate_chains=_dbRenewalConfiguration.is_save_alternate_chains,
                    )

                    # merge these items back in, as the session was commited
                    _dbAcmeOrder = self.ctx.dbSession.merge(_dbAcmeOrder, load=False)

                    _authorization_response = {
                        "status": "pending",
                        "expires": "2047-01-01T14:09:07.99Z",
                        "identifier": {
                            "type": "dns",
                            "value": "selfsigned-1.example.com",
                        },
                        "challenges": [
                            {
                                "url": "https://example.com/acme/chall/acmeOrder-1--authz-1--chall-1",
                                "type": "http-01",
                                "status": "pending",
                                "token": "TokenTokenToken",
                                "validated": None,
                            },
                        ],
                        "wildcard": False,
                    }

                    (
                        _dbAcmeAuthorization,
                        _is_created,
                    ) = db.getcreate.getcreate__AcmeAuthorization(
                        self.ctx,
                        authorization_url=_acme_order_response["authorizations"][0],
                        authorization_payload=_authorization_response,
                        authenticatedUser=_authenticatedUser,
                        dbAcmeOrder=_dbAcmeOrder,
                        transaction_commit=True,
                    )

                    # merge this back in
                    _dbAcmeOrder = self.ctx.dbSession.merge(_dbAcmeOrder)
                    _dbAcmeAuthorization = self.ctx.dbSession.merge(
                        _dbAcmeAuthorization
                    )

                    # ensure we created a challenge
                    assert _dbAcmeAuthorization.acme_challenge_http_01 is not None

                    _db__AcmeChallengePoll = db.create.create__AcmeChallengePoll(
                        self.ctx,
                        dbAcmeChallenge=_dbAcmeAuthorization.acme_challenge_http_01,
                        remote_ip_address="127.1.1.1",
                    )
                    _db__AcmeChallengeUnknownPoll = (
                        db.create.create__AcmeChallengeUnknownPoll(
                            self.ctx,
                            domain="unknown.example.com",
                            challenge="bar.foo",
                            remote_ip_address="127.1.1.2",
                        )
                    )

                    # note: pre-populate AcmeDnsServer
                    (dbAcmeDnsServer, _x) = db.getcreate.getcreate__AcmeDnsServer(
                        self.ctx,
                        api_url=ACME_DNS_API,
                        domain=ACME_DNS_DOMAIN,
                        is_global_default=True,
                    )

                    dbAcmeDnsServer_2: Optional[model_objects.AcmeDnsServer] = None
                    assert self.ctx.application_settings
                    _acme_dns_support = self.ctx.application_settings[
                        "acme_dns_support"
                    ]
                    try:
                        (dbAcmeDnsServer_2, _x) = db.getcreate.getcreate__AcmeDnsServer(
                            self.ctx,
                            api_url=TEST_FILES["AcmeDnsServer"]["2"]["api_url"],
                            domain=TEST_FILES["AcmeDnsServer"]["2"]["domain"],
                        )
                        if _acme_dns_support == "basic":
                            raise ValueError(
                                "we should not be able to add a second acme-dns server"
                            )
                    except ValueError as exc:
                        if exc.args[0] == "An acme-dns server already exists.":
                            # this is expected in basic
                            if _acme_dns_support != "basic":
                                raise exc

                    (
                        _dbAcmeDnsServerAccount_domain,
                        _x,
                    ) = db.getcreate.getcreate__Domain__by_domainName(
                        self.ctx,
                        domain_name=TEST_FILES["AcmeDnsServerAccount"]["1"]["domain"],
                    )
                    # use the second server if possible
                    dbAcmeDnsServerAccount = db.create.create__AcmeDnsServerAccount(
                        self.ctx,
                        dbAcmeDnsServer=(dbAcmeDnsServer_2 or dbAcmeDnsServer),
                        dbDomain=_dbAcmeDnsServerAccount_domain,
                        username=TEST_FILES["AcmeDnsServerAccount"]["1"]["username"],
                        password=TEST_FILES["AcmeDnsServerAccount"]["1"]["password"],
                        fulldomain=TEST_FILES["AcmeDnsServerAccount"]["1"][
                            "fulldomain"
                        ],
                        subdomain=TEST_FILES["AcmeDnsServerAccount"]["1"]["subdomain"],
                        allowfrom=TEST_FILES["AcmeDnsServerAccount"]["1"]["allowfrom"],
                    )

                    self.ctx.pyramid_transaction_commit()

                    # Turn of the AcmeOrder and RenewalConfiguration
                    _dbAcmeOrder = self.ctx.dbSession.merge(_dbAcmeOrder)
                    db.update.update_RenewalConfiguration__unset_active(
                        self.ctx, _dbAcmeOrder.renewal_configuration
                    )
                    _result = db.actions_acme.updated_AcmeOrder_status(
                        self.ctx,
                        _dbAcmeOrder,
                        {
                            "status": "invalid",
                        },
                        transaction_commit=True,
                    )

                    self.ctx.pyramid_transaction_commit()

                    _dbAcmePolling_error = db.create.create__AcmePollingError(
                        self.ctx,
                        acme_polling_error_endpoint_id=model_utils.AcmePollingErrorEndpoint.ACME_ORDER_FINALIZE,
                        acme_order_id=_dbAcmeOrder.id,
                    )
                    self.ctx.pyramid_transaction_commit()

                    db_freeze(self.ctx.dbSession, "AppTest")

                except Exception as exc:
                    print("")
                    print("")
                    print("")
                    print("EXCEPTION IN SETUP")
                    print("")
                    print(exc)
                    traceback.print_exc()

                    print("")
                    print("")
                    print("")
                    self.ctx.pyramid_transaction_rollback()
                    raise
            print("AppTest: DB INITIALIZED")
            AppTest._DB_SETUP_RECORDS = True
        _debug_TestHarness(
            self.ctx, "%s.%s|setUp" % (self.__class__.__name__, self._testMethodName)
        )
        unset_testing_data__AppTest(self)

    def tearDown(self) -> None:
        _debug_TestHarness(
            self.ctx, "%s.%s|tearDown" % (self.__class__.__name__, self._testMethodName)
        )
        if self._ctx is not None:
            self.ctx.pyramid_transaction_commit()
            self._ctx.dbSession.close()
        unset_testing_data__AppTest(self)
        AppTestCore.tearDown(self)

    @classmethod
    def tearDownClass(cls) -> None:
        """
        the test data created by `_ensure_one` can persist; it must be removed
        """
        unset_testing_data__AppTest_Class(cls)


# ==============================================================================


class AppTestWSGI(AppTest, _Mixin_filedata):
    """
    A support testing class to `AppTest`

    These tests EXPOSE the PeterSSLers application by also mounting it to a
    `StopableWSGIServer` instance running on port 5002.

    5002 is the default high port pebble uses to authenticate against;

    This may require an nginx/other block to route the ports:

        location /.well-known/acme-challenge/ {
            proxy_pass  http://127.0.0.1:5002;
            proxy_set_header   Host $host;
            proxy_set_header   X-Real-IP $remote_addr;
            proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Host $server_name;
        }
    """

    # Inherited from AppTest:
    # * _testapp
    # * _testapp_wsgi
    # * _session_factory
    # * _DB_INTIALIZED

    _testapp_wsgi: Optional[StopableWSGIServer] = None

    def setUp(self) -> None:
        log.critical(
            "%s.%s | AppTestWSGI.setUp"
            % (self.__class__.__name__, self._testMethodName)
        )
        AppTest.setUp(self)
        # app = main(global_config=None, **self._settings)
        # load this on the side to RESPOND
        log.critical("StopableWSGIServer: create [%s]" % time.time())
        self._testapp_wsgi = StopableWSGIServer.create(
            self._pyramid_app,  # we can mount the existing app
            host="peter-sslers.example.com",  # /etc/hosts maps this to localhost
            port=5002,  # this corresponts to pebble-config.json `"httpPort": 5002`
        )
        log.critical("StopableWSGIServer: created; wait [%s]" % time.time())
        self._testapp_wsgi.wait()
        log.critical("StopableWSGIServer: waited [%s]" % time.time())

    def tearDown(self) -> None:
        log.critical(
            "%s.%s | AppTestWSGI.tearDown"
            % (self.__class__.__name__, self._testMethodName)
        )
        if self._testapp_wsgi is not None:
            log.critical("StopableWSGIServer: shutting down [%s]" % time.time())
            result = self._testapp_wsgi.shutdown()
            log.critical("StopableWSGIServer: shutdown complete [%s]" % time.time())
            assert result is True
            # sleep for 5 seconds, because I don't trust this
            time.sleep(5)
        AppTest.tearDown(self)


# ==============================================================================


def testcase_to_prefix(testCase: CustomizedTestCase) -> str:
    """generates a DNS-label based on a testcase name"""
    prefix = "%s.%s" % (testCase.__class__.__name__, testCase._testMethodName)
    prefix = prefix.replace("_", "-")
    return prefix


def testcaseClass_to_prefix(testCase: CustomizedTestCase) -> str:
    """generates a DNS-label based on a testcase class"""
    prefix = "%s." % testCase.__name__
    prefix = prefix.replace("_", "-")
    return prefix


def generate_random_emailaddress(template="%s@example.com") -> str:
    """generates a random email address"""
    return template % uuid.uuid4()


def generate_random_domain(
    template="%s.example.com",
    testCase: Optional[CustomizedTestCase] = None,
) -> str:
    """generates a random domain name"""
    # optionally provide a testcase to insert into the generated names
    # this is useful for debugging test creation
    if testCase:
        prefix = testcase_to_prefix(testCase)
        template = "%s.%%s.example.com" % prefix
    domain = template % uuid.uuid4()
    # if testCase:
    #    _seen = lib_db_get.get__Domain__by_name(testCase.ctx, domain)
    #    if _seen:
    #        raise ValueError("RANDOM SEEN AGAIN?!?!")
    #        domain = generate_random_domain(template=template, testCase=testCase)
    return domain
