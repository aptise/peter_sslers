from __future__ import print_function

import logging

log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)

# stdlib
import datetime
import os
import pdb
import subprocess
import unittest
import time
from io import open  # overwrite `open` in Python2
from functools import wraps

# pyramid
from pyramid import testing
from pyramid.paster import get_appsettings

# pypi
import psutil
import transaction
from webtest import TestApp
from webtest.http import StopableWSGIServer

# local
from ..web import main
from ..web.models import get_engine
from ..web.models import get_session_factory
from ..model import objects as model_objects
from ..model import utils as model_utils
from ..model import meta as model_meta
from ..lib import db
from ..lib import utils


# ==============================================================================

"""
export SSL_RUN_NGINX_TESTS=1
export SSL_RUN_REDIS_TESTS=1
export SSL_RUN_API_TESTS__PEBBLE=1
export SSL_PEBBLE_API_VALIDATES=1
export SSL_TEST_DOMAINS=dev.cliqued.in  # can be a comma-separated string
export SSL_TEST_PORT=7201
export SSL_TEST_PORT=7201
export SSL_BIN_REDIS_SERVER=/path/to
export SSL_CONF_REDIS_SERVER=/path/to

if running letsencrypt tests, you need to specify a domain and make sure to proxy to this app so letsencrypt can access it

see the nginx test config file `testing.conf`

"""

# run tests that expire nginx caches
RUN_NGINX_TESTS = bool(int(os.environ.get("SSL_RUN_NGINX_TESTS", 0)))
# run tests to prime redis
RUN_REDIS_TESTS = bool(int(os.environ.get("SSL_RUN_REDIS_TESTS", 0)))
# run tests against LE API
RUN_API_TESTS__PEBBLE = bool(int(os.environ.get("SSL_RUN_API_TESTS__PEBBLE", 0)))
# does the LE validation work?  LE must be able to reach this
LETSENCRYPT_API_VALIDATES = bool(int(os.environ.get("SSL_PEBBLE_API_VALIDATES", 0)))

SSL_TEST_DOMAINS = os.environ.get("SSL_TEST_DOMAINS", "example.com")
SSL_TEST_PORT = int(os.environ.get("SSL_TEST_PORT", 7201))

# coordinate the port with `test.ini`
SSL_BIN_REDIS_SERVER = os.environ.get("SSL_BIN_REDIS_SERVER", None) or "redis-server"
SSL_CONF_REDIS_SERVER = os.environ.get("SSL_CONF_REDIS_SERVER", None) or None
if SSL_CONF_REDIS_SERVER is None:
    SSL_CONF_REDIS_SERVER = "/".join(__file__.split("/")[:-1] + ["redis-server.conf",])

PEBBLE_CONFIG = (
    "%s/src/github.com/letsencrypt/pebble/test/config/pebble-config.json"
    % os.environ.get("GOPATH")
)
PEBBLE_DIR = "%s/src/github.com/letsencrypt/pebble" % os.environ.get("GOPATH")
PEBBLE_ENV = os.environ.copy()
PEBBLE_ENV["PEBBLE_VA_ALWAYS_VALID"] = "1"
PEBBLE_ENV["PEBBLE_AUTHZREUSE"] = "100"
PEBBLE_ENV["PEBBLE_VA_NOSLEEP"] = "1"

PEBBLE_ENV_STRICT = os.environ.copy()
PEBBLE_ENV_STRICT["PEBBLE_VA_ALWAYS_VALID"] = "0"
PEBBLE_ENV_STRICT["PEBBLE_AUTHZREUSE"] = "0"
PEBBLE_ENV_STRICT["PEBBLE_VA_NOSLEEP"] = "1"


# ==============================================================================


class FakeRequest(testing.DummyRequest):
    @property
    def tm(self):
        return transaction.manager


def under_pebble(_function):
    """
    decorator to spin up an external pebble server
    """

    @wraps(_function)
    def _wrapper(*args, **kwargs):
        log.info("++ spinning up `pebble`")
        res = None  # scoping
        with psutil.Popen(
            ["pebble", "-config", PEBBLE_CONFIG],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=PEBBLE_DIR,
            env=PEBBLE_ENV,
        ) as proc:
            # ensure the `pebble` server is running
            ready = False
            while not ready:
                log.info("waiting for `pebble` to be ready")
                for line in iter(proc.stdout.readline, b""):
                    if b"Listening on: 0.0.0.0:14000" in line:
                        ready = True
                        break
                time.sleep(1)
            try:
                res = _function(*args, **kwargs)
            finally:
                # explicitly terminate, otherwise it won't exit
                # in a `finally` to ensure we terminate on exceptions
                log.info("xx terminating `pebble`")
                proc.terminate()
        return res

    return _wrapper


def under_pebble_strict(_function):
    """
    decorator to spin up an external pebble server
    """

    @wraps(_function)
    def _wrapper(*args, **kwargs):
        log.info("++ spinning up `pebble`")
        res = None  # scoping
        with psutil.Popen(
            ["pebble", "-config", PEBBLE_CONFIG],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=PEBBLE_DIR,
            env=PEBBLE_ENV_STRICT,
        ) as proc:
            # ensure the `pebble` server is running
            ready = False
            while not ready:
                log.info("waiting for `pebble` to be ready")
                for line in iter(proc.stdout.readline, b""):
                    if b"Listening on: 0.0.0.0:14000" in line:
                        ready = True
                        break
                time.sleep(1)
            try:
                res = _function(*args, **kwargs)
            finally:
                # explicitly terminate, otherwise it won't exit
                # in a `finally` to ensure we terminate on exceptions
                log.info("xx terminating `pebble`")
                proc.terminate()
        return res

    return _wrapper


def under_redis(_function):
    """
    decorator to spin up an external redis server
    """

    @wraps(_function)
    def _wrapper(*args, **kwargs):
        log.info("++ spinning up `pebble`")
        res = None  # scoping
        # /usr/local/Cellar/redis/3.0.7/bin/redis-server /Users/jvanasco/webserver/sites/CliquedInDeploy/trunk/config/environments/development/redis/redis-server--6379.conf
        with psutil.Popen(
            [SSL_BIN_REDIS_SERVER, SSL_CONF_REDIS_SERVER],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            # ensure the `pebble` server is running
            ready = False
            while not ready:
                log.info("waiting for `redis` to be ready")
                for line in iter(proc.stdout.readline, b""):
                    if b"Can't chdir to" in line:
                        raise ValueError(line)
                    if b"The server is now ready to accept connections on port" in line:
                        ready = True
                        break
                time.sleep(1)
            try:
                res = _function(*args, **kwargs)
            finally:
                # explicitly terminate, otherwise it won't exit
                # in a `finally` to ensure we terminate on exceptions
                log.info("xx terminating `redis`")
                proc.terminate()
        return res

    return _wrapper


# ==============================================================================


# !!!: TEST_FILES

TEST_FILES = {
    "AcmeOrderless": {
        "new-1": {
            "domains": ["acme-orderless-1.example.com", "acme-orderless-2.example.com"],
            "AcmeAccountKey": None,
        },
        "new-2": {
            "domains": ["acme-orderless-1.example.com", "acme-orderless-2.example.com"],
            "AcmeAccountKey": {
                "type": "upload",
                "private_key_cycling": "single_certificate",
                "acme_account_provider_id": "1",
                "account_key_file_pem": "acme_account_1.key",
            },
        },
    },
    "AcmeOrder": {
        "test-extended_html": {
            "acme-order/new/automated#1": {
                "account_key_option": "account_key_file",
                "acme_account_provider_id": "1",
                "account_key_file_pem": "AcmeAccountKey-1.pem",
                "private_key_cycle": "account_daily",
                "private_key_option": "private_key_for_account_key",
                "domain_names": [
                    "new-automated-1-a.example.com",
                    "new-automated-1-b.example.com",
                ],
                "private_key_cycle__renewal": "account_key_default",
                "processing_strategy": "create_order",
            },
            "acme-order/new/automated#2": {
                "account_key_option": "account_key_file",
                "acme_account_provider_id": "1",
                "account_key_file_pem": "AcmeAccountKey-1.pem",
                "private_key_cycle": "account_daily",
                "private_key_option": "private_key_for_account_key",
                "domain_names": [
                    "new-automated-1-c.example.com",
                    "new-automated-1-d.example.com",
                ],
                "private_key_cycle__renewal": "account_key_default",
                "processing_strategy": "create_order",
            },
        },
    },
    "AcmeAccountKey": {
        "1": {
            "key": "acme_account_1.key",
            "provider": "pebble",
            "private_key_cycle": "single_certificate",
            "contact": "contact.a@example.com",
        },
        "2": {
            "key": "acme_account_2.key",
            "provider": "pebble",
            "private_key_cycle": "single_certificate",
            "contact": "contact.b@example.com",
        },
        "3": {
            "key": "acme_account_3.key",
            "provider": "pebble",
            "private_key_cycle": "single_certificate",
            "contact": "contact.c@example.com",
        },
        "4": {
            "key": "acme_account_4.key",
            "provider": "pebble",
            "private_key_cycle": "single_certificate",
            "contact": "contact.d@example.com",
        },
        "5": {
            "key": "acme_account_5.key",
            "provider": "pebble",
            "private_key_cycle": "single_certificate",
            "contact": "contact.e@example.com",
        },
    },
    "CACertificates": {
        "order": (
            "isrgrootx1",
            "le_x1_auth",
            "le_x2_auth",
            "le_x1_cross_signed",
            "le_x2_cross_signed",
            "le_x3_cross_signed",
            "le_x4_cross_signed",
        ),
        "cert": {
            "isrgrootx1": "isrgrootx1.pem.txt",
            "le_x1_auth": "letsencryptauthorityx1.pem.txt",
            "le_x2_auth": "letsencryptauthorityx2.pem.txt",
            "le_x1_cross_signed": "lets-encrypt-x1-cross-signed.pem.txt",
            "le_x2_cross_signed": "lets-encrypt-x2-cross-signed.pem.txt",
            "le_x3_cross_signed": "lets-encrypt-x3-cross-signed.pem.txt",
            "le_x4_cross_signed": "lets-encrypt-x4-cross-signed.pem.txt",
        },
    },
    "CertificateRequests": {
        "1": {
            "domains": "foo.example.com, bar.example.com",
            "account_key": "account_1.key",
            "private_key": "private_1.key",
        },
        "acme_test": {
            "domains": SSL_TEST_DOMAINS,
            "account_key": "account_2.key",
            "private_key": "private_2.key",
        },
    },
    "Domains": {
        "Queue": {
            "1": {
                "add": "qadd1.example.com, qadd2.example.com, qadd3.example.com",
                "add.json": "qaddjson1.example.com, qaddjson2.example.com, qaddjson3.example.com",
            },
        }
    },
    "PrivateKey": {
        "1": {
            "file": "private_1.key",
            "key_pem_md5": "462dc10731254d7f5fa7f0e99cbece73",
            "key_pem_modulus_md5": "5d0f596ace3ea1a9ce40dc9b087759a1",
        },
        "2": {
            "file": "private_2.key",
            "key_pem_md5": "cdde9325bdbfe03018e4119549c3a7eb",
            "key_pem_modulus_md5": "db45c5dce9fffbe21fc82a5e26b0bf8e",
        },
        "3": {
            "file": "private_3.key",
            "key_pem_md5": "399236401eb91c168762da425669ad06",
            "key_pem_modulus_md5": "c2b3abfb8fa471977b6df77aafd30bee",
        },
        "4": {
            "file": "private_4.key",
            "key_pem_md5": "6867998790e09f18432a702251bb0e11",
            "key_pem_modulus_md5": "e33389025a223c8a36958dc56de08840",
        },
        "5": {
            "file": "private_5.key",
            "key_pem_md5": "1b13814854d8cee8c64732a2e2f7e73e",
            "key_pem_modulus_md5": "a2ea95b3aa5f5b337ac981c2024bcb3a",
        },
    },
    # the certificates are a tuple of: (CommonName, crt, csr, key)
    "ServerCertificates": {
        "SelfSigned": {
            "1": {
                "domain": "selfsigned-1.example.com",
                "cert": "selfsigned_1-server.crt",
                "csr": "selfsigned_1-server.csr",
                "pkey": "selfsigned_1-server.key",
            },
            "2": {
                "domain": "selfsigned-2.example.com",
                "cert": "selfsigned_2-server.crt",
                "csr": "selfsigned_2-server.csr",
                "pkey": "selfsigned_2-server.key",
            },
            "3": {
                "domain": "selfsigned-3.example.com",
                "cert": "selfsigned_3-server.crt",
                "csr": "selfsigned_3-server.csr",
                "pkey": "selfsigned_3-server.key",
            },
            "4": {
                "domain": "selfsigned-4.example.com",
                "cert": "selfsigned_4-server.crt",
                "csr": "selfsigned_4-server.csr",
                "pkey": "selfsigned_4-server.key",
            },
            "5": {
                "domain": "selfsigned-5.example.com",
                "cert": "selfsigned_5-server.crt",
                "csr": "selfsigned_5-server.csr",
                "pkey": "selfsigned_5-server.key",
            },
        },
        "LetsEncrypt": {},
    },
}


# ==============================================================================


class FakeAuthenticatedUser(object):
    accountkey_thumbprint = None

    def __init__(self, accountkey_thumbprint=None):
        self.accountkey_thumbprint = accountkey_thumbprint


class AppTestCore(unittest.TestCase):
    _data_root = None
    testapp = None
    testapp_http = None
    _session_factory = None
    _DB_INTIALIZED = False
    _settings = None

    def _filepath_testfile(self, filename):
        return os.path.join(self._data_root, filename)

    def _filedata_testfile(self, filename):
        with open(os.path.join(self._data_root, filename), "rt", encoding="utf-8") as f:
            data = f.read()
        return data

    def setUp(self):
        self._settings = settings = get_appsettings(
            "test.ini", name="main"
        )  # this can cause an unclosed resource

        # sqlalchemy.url = sqlite:///%(here)s/example_ssl_minnow_test.sqlite
        if False:
            settings["sqlalchemy.url"] = "sqlite://"

        self._session_factory = get_session_factory(get_engine(settings))
        if not AppTestCore._DB_INTIALIZED:
            print("---------------")
            print("AppTestCore.setUp | initialize db")
            engine = self._session_factory().bind
            model_meta.Base.metadata.drop_all(engine)
            engine.execute("VACUUM")
            model_meta.Base.metadata.create_all(engine)

            dbSession = self._session_factory()
            # this would have been invoked by `initialize_database`
            db._setup.initialize_AcmeAccountProviders(dbSession)
            db._setup.initialize_DomainBlacklisted(dbSession)
            dbSession.commit()
            dbSession.close()

        app = main(global_config=None, **settings)
        self.testapp = TestApp(
            app, extra_environ={"HTTP_HOST": "peter-sslers.example.com",}
        )
        self._data_root = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "test_data"
        )
        AppTestCore._DB_INTIALIZED = True

    def tearDown(self):
        if self.testapp is not None:
            pass
        self._session_factory = None


# ==============================================================================


class AppTest(AppTestCore):

    _ctx = None
    _DB_SETUP_RECORDS = False

    def setUp(self):
        AppTestCore.setUp(self)
        if not AppTest._DB_SETUP_RECORDS:
            print("---------------")
            print("AppTest.setUp | setup sample db records")

            try:
                """
                This setup pre-populates the DB with some objects needed for routes to work:

                    AccountKey:
                        account_1.key
                    CACertificates:
                        isrgrootx1.pem.txt
                        selfsigned_1-server.crt
                    PrivateKey
                        selfsigned_1-server.key

                    AcmeEventLog
                """
                # note: pre-populate AcmeAccountKey
                # this should create `/acme-account-key/1`
                _dbAcmeAccountKey_1 = None
                for _id in TEST_FILES["AcmeAccountKey"]:
                    _key_filename = TEST_FILES["AcmeAccountKey"][_id]["key"]
                    _private_key_cycle = TEST_FILES["AcmeAccountKey"][_id][
                        "private_key_cycle"
                    ]
                    key_pem = self._filedata_testfile(_key_filename)
                    (
                        _dbAcmeAccountKey,
                        _is_created,
                    ) = db.getcreate.getcreate__AcmeAccountKey(
                        self.ctx,
                        key_pem,
                        acme_account_provider_id=1,  # acme_account_provider_id(1) == pebble
                        acme_account_key_source_id=model_utils.AcmeAccountKeySource.from_string(
                            "imported"
                        ),
                        event_type="AcmeAccountKey__insert",
                        private_key_cycle_id=model_utils.PrivateKeyCycle.from_string(
                            _private_key_cycle
                        ),
                    )
                    # print(_dbAcmeAccountKey_1, _is_created)
                    # self.ctx.pyramid_transaction_commit()
                    if _id == "1":
                        _dbAcmeAccountKey_1 = _dbAcmeAccountKey
                        db.update.update_AcmeAccountKey__set_global_default(
                            self.ctx, _dbAcmeAccountKey
                        )
                        self.ctx.pyramid_transaction_commit()

                # note: pre-populate CACertificate
                # this should create `/ca-certificate/1`
                #
                _ca_cert_id = "isrgrootx1"
                _ca_cert_filename = TEST_FILES["CACertificates"]["cert"][_ca_cert_id]
                ca_cert_pem = self._filedata_testfile(_ca_cert_filename)
                (
                    _ca_cert_1,
                    _is_created,
                ) = db.getcreate.getcreate__CACertificate__by_pem_text(
                    self.ctx,
                    ca_cert_pem,
                    ca_chain_name="ISRG Root",
                    le_authority_name="ISRG ROOT",
                    is_authority_certificate=True,
                    is_cross_signed_authority_certificate=False,
                )
                # print(_ca_cert_1, _is_created)
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
                        private_key_source_id=model_utils.PrivateKeySource.from_string(
                            "imported"
                        ),
                        private_key_type_id=model_utils.PrivateKeyType.from_string(
                            "standard"
                        ),
                    )

                # note: pre-populate ServerCertificate 1-5
                # this should create `/server-certificate/1`
                #
                _dbServerCertificate_1 = None
                _dbPrivateKey_1 = None
                _dbUniqueFQDNSet_1 = None
                for _id in TEST_FILES["ServerCertificates"]["SelfSigned"].keys():
                    # note: pre-populate PrivateKey
                    # this should create `/private-key/1`
                    _pkey_filename = TEST_FILES["ServerCertificates"]["SelfSigned"][
                        _id
                    ]["pkey"]
                    pkey_pem = self._filedata_testfile(_pkey_filename)
                    (
                        _dbPrivateKey,
                        _is_created,
                    ) = db.getcreate.getcreate__PrivateKey__by_pem_text(
                        self.ctx,
                        pkey_pem,
                        private_key_source_id=model_utils.PrivateKeySource.from_string(
                            "imported"
                        ),
                        private_key_type_id=model_utils.PrivateKeyType.from_string(
                            "standard"
                        ),
                    )
                    # print(_dbPrivateKey, _is_created)
                    # self.ctx.pyramid_transaction_commit()

                    # note: pre-populate CACertificate - self-signed
                    # this should create `/ca-certificate/2`
                    #
                    _ca_cert_filename = TEST_FILES["ServerCertificates"]["SelfSigned"][
                        _id
                    ]["cert"]
                    ca_cert_pem = self._filedata_testfile(_ca_cert_filename)
                    (
                        _dbCACertificate_SelfSigned,
                        _is_created,
                    ) = db.getcreate.getcreate__CACertificate__by_pem_text(
                        self.ctx, ca_cert_pem, ca_chain_name=_ca_cert_filename
                    )
                    # print(_dbCACertificate_SelfSigned, _is_created)
                    # self.ctx.pyramid_transaction_commit()

                    _cert_filename = TEST_FILES["ServerCertificates"]["SelfSigned"][
                        _id
                    ]["cert"]
                    _cert_domains_expected = [
                        TEST_FILES["ServerCertificates"]["SelfSigned"][_id]["domain"],
                    ]
                    (
                        _dbUniqueFQDNSet,
                        _is_created,
                    ) = db.getcreate.getcreate__UniqueFQDNSet__by_domains(
                        self.ctx, _cert_domains_expected,
                    )

                    cert_pem = self._filedata_testfile(_cert_filename)
                    (
                        _dbServerCertificate,
                        _is_created,
                    ) = db.getcreate.getcreate__ServerCertificate(
                        self.ctx,
                        cert_pem,
                        cert_domains_expected=_cert_domains_expected,
                        dbCACertificate=_dbCACertificate_SelfSigned,
                        dbUniqueFQDNSet=_dbUniqueFQDNSet,
                        dbPrivateKey=_dbPrivateKey,
                    )
                    # print(_dbServerCertificate_1, _is_created)
                    # self.ctx.pyramid_transaction_commit()

                    if _id == "1":
                        _dbServerCertificate_1 = _dbServerCertificate
                        _dbPrivateKey_1 = _dbPrivateKey
                        _dbUniqueFQDNSet_1 = _dbUniqueFQDNSet

                # note: pre-populate Domain
                # ensure we have domains?
                domains = db.get.get__Domain__paginated(self.ctx)
                domain_names = [d.domain_name for d in domains]
                assert (
                    TEST_FILES["ServerCertificates"]["SelfSigned"]["1"][
                        "domain"
                    ].lower()
                    in domain_names
                )

                # note: pre-populate CertificateRequest
                _csr_filename = TEST_FILES["ServerCertificates"]["SelfSigned"]["1"][
                    "csr"
                ]
                csr_pem = self._filedata_testfile(_csr_filename)
                (
                    _dbCertificateRequest_1,
                    _is_created,
                ) = db.getcreate.getcreate__CertificateRequest__by_pem_text(
                    self.ctx,
                    csr_pem,
                    certificate_request_source_id=model_utils.CertificateRequestSource.IMPORTED,
                    dbPrivateKey=_dbPrivateKey_1,
                    domain_names=[
                        TEST_FILES["ServerCertificates"]["SelfSigned"]["1"]["domain"],
                    ],  # make it an iterable
                )
                # self.ctx.pyramid_transaction_commit()

                # note: pre-populate QueueDomain
                # queue a domain
                # this MUST be a new domain to add to the queue
                # if it is existing, a domain will not be added
                db.queues.queue_domains__add(self.ctx, ["queue.example.com"])
                # self.ctx.pyramid_transaction_commit()

                # note: pre-populate QueueCertificate
                # renew a csr
                # this MUST be a new domain to add to the queue
                # if it is existing, a domain will not be added
                event_type = model_utils.OperationsEventType.from_string(
                    "QueueCertificate__update"
                )
                event_payload_dict = utils.new_event_payload_dict()
                dbOperationsEvent = db.logger.log__OperationsEvent(
                    self.ctx, event_type, event_payload_dict
                )
                dbQueue = db.create.create__QueueCertificate(
                    self.ctx,
                    dbAcmeAccountKey=_dbAcmeAccountKey_1,
                    dbPrivateKey=_dbPrivateKey_1,
                    dbServerCertificate=_dbServerCertificate_1,
                )
                # self.ctx.pyramid_transaction_commit()

                # TODO: the dbSessions don't seem to be the same
                #       to get around this, commit now
                self.ctx.pyramid_transaction_commit()

                # note: pre-populate AcmeOrder

                # merge these items in
                _dbAcmeAccountKey_1 = self.ctx.dbSession.merge(
                    _dbAcmeAccountKey_1, load=False
                )
                _dbPrivateKey_1 = self.ctx.dbSession.merge(_dbPrivateKey_1, load=False)
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
                _acme_order_type_id = model_utils.AcmeOrderType.ACME_AUTOMATED_NEW
                _acme_order_processing_status_id = (
                    model_utils.AcmeOrder_ProcessingStatus.created_acme
                )
                _acme_order_processing_strategy_id = (
                    model_utils.AcmeOrder_ProcessingStrategy.create_order
                )
                _private_key_cycle_id__renewal = model_utils.PrivateKeyCycle.from_string(
                    "single_certificate"
                )
                _private_key_strategy_id__requested = model_utils.PrivateKeyStrategy.from_string(
                    "specified"
                )
                _acme_event_id = model_utils.AcmeEvent.from_string("v2|newOrder")
                _dbAcmeEventLog = model_objects.AcmeEventLog()
                _dbAcmeEventLog.acme_event_id = _acme_event_id
                _dbAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
                _dbAcmeEventLog.acme_account_key_id = _dbAcmeAccountKey_1.id
                _dbAcmeEventLog.unique_fqdn_set_id = _dbUniqueFQDNSet_1.id
                self.ctx.dbSession.add(_dbAcmeEventLog)
                self.ctx.dbSession.flush()

                _authenticatedUser = FakeAuthenticatedUser(
                    accountkey_thumbprint="accountkey_thumbprint"
                )

                _dbAcmeOrder_1 = db.create.create__AcmeOrder(
                    self.ctx,
                    acme_order_response=_acme_order_response,
                    acme_order_type_id=_acme_order_type_id,
                    acme_order_processing_status_id=_acme_order_processing_status_id,
                    acme_order_processing_strategy_id=_acme_order_processing_strategy_id,
                    private_key_cycle_id__renewal=_private_key_cycle_id__renewal,
                    private_key_strategy_id__requested=_private_key_strategy_id__requested,
                    order_url="https://example.com/acme/order/acmeOrder-1",
                    dbAcmeAccountKey=_dbAcmeAccountKey_1,
                    dbEventLogged=_dbAcmeEventLog,
                    dbPrivateKey=_dbPrivateKey_1,
                    dbUniqueFQDNSet=_dbUniqueFQDNSet_1,
                    transaction_commit=True,
                )

                # merge these items in
                _dbAcmeOrder_1 = self.ctx.dbSession.merge(_dbAcmeOrder_1, load=False)

                _authorization_response = {
                    "status": "pending",
                    "expires": "2047-01-01T14:09:07.99Z",
                    "identifier": {"type": "dns", "value": "selfsigned-1.example.com"},
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
                    _dbAcmeAuthorization_1,
                    _is_created,
                ) = db.getcreate.getcreate__AcmeAuthorization(
                    self.ctx,
                    authorization_url=_acme_order_response["authorizations"][0],
                    authorization_payload=_authorization_response,
                    authenticatedUser=_authenticatedUser,
                    dbAcmeOrder=_dbAcmeOrder_1,
                    transaction_commit=True,
                )

                # merge this back in
                _dbAcmeAuthorization_1 = self.ctx.dbSession.merge(
                    _dbAcmeAuthorization_1, load=False
                )

                # ensure we created a challenge
                assert _dbAcmeAuthorization_1.acme_challenge_http01 is not None

                _db__AcmeChallengePoll = db.create.create__AcmeChallengePoll(
                    self.ctx,
                    dbAcmeChallenge=_dbAcmeAuthorization_1.acme_challenge_http01,
                    remote_ip_address="127.1.1.1",
                )
                _db__AcmeChallengeUnknownPoll = db.create.create__AcmeChallengeUnknownPoll(
                    self.ctx,
                    domain="unknown.example.com",
                    challenge="bar.foo",
                    remote_ip_address="127.1.1.2",
                )

                # note: pre-populate AcmeOrderless
                dbAcmeOrderless = db.create.create__AcmeOrderless(
                    self.ctx,
                    domain_names=("acme-orderless.example.com",),
                    dbAcmeAccountKey=None,
                )

                self.ctx.pyramid_transaction_commit()

            except Exception as exc:
                print("")
                print("")
                print("")
                print("EXCEPTION IN SETUP")
                print("")
                print(exc)

                print("")
                print("")
                print("")
                self.ctx.pyramid_transaction_rollback()
                raise
            print("DB INITIALIZED")
            AppTest._DB_SETUP_RECORDS = True

    def tearDown(self):
        AppTestCore.tearDown(self)
        if self._ctx is not None:
            self._ctx.dbSession.commit()
            self._ctx.dbSession.close()

    @property
    def ctx(self):
        if self._ctx is None:
            dbSession_factory = self.testapp.app.registry["dbSession_factory"]
            self._ctx = utils.ApiContext(
                request=FakeRequest(),
                dbSession=dbSession_factory(),
                timestamp=datetime.datetime.utcnow(),
            )
        return self._ctx


# ==============================================================================


class AppTestWSGI(AppTest):
    _data_root = None
    testapp = None
    testapp_http = None
    _session_factory = None
    _DB_INTIALIZED = False

    def _filepath_testfile(self, filename):
        return os.path.join(self._data_root, filename)

    def _filedata_testfile(self, filename):
        with open(os.path.join(self._data_root, filename), "rt", encoding="utf-8") as f:
            data = f.read()
        return data

    def setUp(self):
        AppTest.setUp(self)
        app = main(global_config=None, **self._settings)
        self.testapp_wsgi = StopableWSGIServer.create(
            app, host="peter-sslers.example.com", port=5002
        )

    def tearDown(self):
        AppTest.tearDown(self)
        if self.testapp_wsgi is not None:
            self.testapp_wsgi.shutdown()


# ==============================================================================
