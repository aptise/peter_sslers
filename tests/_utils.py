from __future__ import print_function

import logging

log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)

# stdlib
import datetime
import os
import packaging.version
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
import sqlalchemy

# local
from peter_sslers.web import main
from peter_sslers.web.models import get_engine
from peter_sslers.web.models import get_session_factory
from peter_sslers.model import objects as model_objects
from peter_sslers.model import utils as model_utils
from peter_sslers.model import meta as model_meta
from peter_sslers.lib import db
from peter_sslers.lib import errors
from peter_sslers.lib import utils


# ==============================================================================

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

If running LetsEncrypt tests: you must specify a domain, and make sure to proxy
port80 of that domain to this app, so LetsEncrypt can access it.

see the nginx test config file `testing.conf`

"""

# run tests that expire nginx caches
RUN_NGINX_TESTS = bool(int(os.environ.get("SSL_RUN_NGINX_TESTS", 0)))
# run tests to prime redis
RUN_REDIS_TESTS = bool(int(os.environ.get("SSL_RUN_REDIS_TESTS", 0)))

# run tests against LE API
RUN_API_TESTS__PEBBLE = bool(int(os.environ.get("SSL_RUN_API_TESTS__PEBBLE", 0)))
# does the LE validation work?  LE must be able to reach this
LETSENCRYPT_API_VALIDATES = bool(
    int(os.environ.get("SSL_LETSENCRYPT_API_VALIDATES", 0))
)

SSL_TEST_DOMAINS = os.environ.get("SSL_TEST_DOMAINS", "example.com")
SSL_TEST_PORT = int(os.environ.get("SSL_TEST_PORT", 7201))

# coordinate the port with `test.ini`
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

PEBBLE_CONFIG = (
    "%s/src/github.com/letsencrypt/pebble/test/config/pebble-config.json" % GOPATH
)
PEBBLE_DIR = "%s/src/github.com/letsencrypt/pebble" % GOPATH

if RUN_API_TESTS__PEBBLE:
    if not GOPATH:
        raise ValueError("GOPATH not defined in environment")
    if not os.path.exists(PEBBLE_DIR):
        raise ValueError("PEBBLE_DIR (%s) does not exist" % PEBBLE_DIR)

PEBBLE_ENV = os.environ.copy()
PEBBLE_ENV["PEBBLE_VA_ALWAYS_VALID"] = "1"
PEBBLE_ENV["PEBBLE_AUTHZREUSE"] = "100"
PEBBLE_ENV["PEBBLE_VA_NOSLEEP"] = "1"

PEBBLE_ENV_STRICT = os.environ.copy()
PEBBLE_ENV_STRICT["PEBBLE_VA_ALWAYS_VALID"] = "0"
PEBBLE_ENV_STRICT["PEBBLE_AUTHZREUSE"] = "0"
PEBBLE_ENV_STRICT["PEBBLE_VA_NOSLEEP"] = "1"


# run tests against ACME_DNS_API
RUN_API_TESTS__ACME_DNS_API = bool(
    int(os.environ.get("SSL_RUN_API_TESTS__ACME_DNS_API", 0))
)
ACME_DNS_API = os.environ.get("SSL_ACME_DNS_API", "http://127.0.0.1:8011")
ACME_DNS_BINARY = os.environ.get("SSL_ACME_DNS_BINARY", "")
ACME_DNS_CONFIG = os.environ.get("SSL_ACME_DNS_CONFIG", "")

if RUN_API_TESTS__ACME_DNS_API:
    if not any((ACME_DNS_BINARY, ACME_DNS_CONFIG)):
        raise ValueError("Must invoke with env vars for acme-dns services")


OPENRESTY_PLUGIN_MINIMUM_VERSION = "0.4.1"
OPENRESTY_PLUGIN_MINIMUM = packaging.version.parse(OPENRESTY_PLUGIN_MINIMUM_VERSION)


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
        log.info("`pebble`: spinning up")
        log.info("`pebble`: PEBBLE_CONFIG : %s", PEBBLE_CONFIG)
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
            _waits = 0
            while not ready:
                log.info("`pebble`: waiting for ready")
                for line in iter(proc.stdout.readline, b""):
                    if b"Listening on: 0.0.0.0:14000" in line:
                        log.info("`pebble`: ready")
                        ready = True
                        break
                _waits += 1
                if _waits >= 5:
                    raise ValueError("`pebble`: ERROR spinning up")
                time.sleep(1)
            try:
                res = _function(*args, **kwargs)
            finally:
                # explicitly terminate, otherwise it won't exit
                # in a `finally` to ensure we terminate on exceptions
                log.info("`pebble`: finished. terminating")
                proc.terminate()
        return res

    return _wrapper


def under_pebble_strict(_function):
    """
    decorator to spin up an external pebble server
    """

    @wraps(_function)
    def _wrapper(*args, **kwargs):
        log.info("`pebble[strict]`: spinning up")
        log.info("`pebble[strict]`: PEBBLE_CONFIG : %s", PEBBLE_CONFIG)
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
            _waits = 0
            while not ready:
                log.info("`pebble[strict]`: waiting for ready")
                for line in iter(proc.stdout.readline, b""):
                    if b"Listening on: 0.0.0.0:14000" in line:
                        log.info("`pebble[strict]`: ready")
                        ready = True
                        break
                _waits += 1
                if _waits >= 5:
                    raise ValueError("`pebble[strict]`: ERROR spinning up")
                time.sleep(1)
            try:
                res = _function(*args, **kwargs)
            finally:
                # explicitly terminate, otherwise it won't exit
                # in a `finally` to ensure we terminate on exceptions
                log.info("`pebble[strict]`: finished. terminating")
                proc.terminate()
        return res

    return _wrapper


def under_redis(_function):
    """
    decorator to spin up an external redis server
    """

    @wraps(_function)
    def _wrapper(*args, **kwargs):
        log.info("`redis`: spinning up")
        log.info("`redis`: SSL_BIN_REDIS_SERVER  : %s", SSL_BIN_REDIS_SERVER)
        log.info("`redis`: SSL_CONF_REDIS_SERVER : %s", SSL_CONF_REDIS_SERVER)
        res = None  # scoping
        with psutil.Popen(
            [SSL_BIN_REDIS_SERVER, SSL_CONF_REDIS_SERVER],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            # ensure the `redis` server is running
            ready = False
            _waits = 0
            while not ready:
                log.info("`redis`: waiting for ready")
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
                _waits += 1
                if _waits >= 5:
                    raise ValueError("`redis`: ERROR spinning up")
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


# ==============================================================================


# !!!: TEST_FILES


TEST_FILES = {
    "AcmeDnsServer": {
        "1": {
            "root_url": ACME_DNS_API,
        },
        "2": {
            "root_url": "https://acme-dns.example.com",
        },
        "3": {
            "root_url": "https://acme-dns-alt.example.com",
        },
        "4": {
            "root_url": "https://acme-dns-alt-2.example.com",
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
            "allowfrom": "allowfrom",
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
    "AcmeOrderless": {
        "new-1": {
            "domain_names_http01": [
                "acme-orderless-1.example.com",
                "acme-orderless-2.example.com",
            ],
            "AcmeAccount": None,
        },
        "new-2": {
            "domain_names_http01": [
                "acme-orderless-1.example.com",
                "acme-orderless-2.example.com",
            ],
            "AcmeAccount": {
                "type": "upload",
                "private_key_cycling": "single_certificate",
                "acme_account_provider_id": "1",
                "account_key_file_pem": "key_technology-rsa/acme_account_1.key",
            },
        },
    },
    "AcmeOrder": {
        "test-extended_html": {
            "acme-order/new/freeform#1": {
                "account_key_option": "account_key_file",
                "acme_account_provider_id": "1",
                "account_key_file_pem": "key_technology-rsa/AcmeAccountKey-1.pem",
                "account__contact": "AcmeAccountKey-1@example.com",
                "private_key_cycle": "account_daily",
                "private_key_option": "private_key_for_account_key",
                "domain_names_http01": [
                    "new-freeform-1-a.example.com",
                    "new-freeform-1-b.example.com",
                ],
                "private_key_cycle__renewal": "account_key_default",
                "processing_strategy": "create_order",
            },
            "acme-order/new/freeform#2": {
                "account_key_option": "account_key_file",
                "acme_account_provider_id": "1",
                "account_key_file_pem": "key_technology-rsa/AcmeAccountKey-1.pem",
                "account__contact": "AcmeAccountKey-1@example.com",
                "private_key_cycle": "account_daily",
                "private_key_option": "private_key_for_account_key",
                "domain_names_http01": [
                    "new-freeform-1-c.example.com",
                    "new-freeform-1-d.example.com",
                ],
                "private_key_cycle__renewal": "account_key_default",
                "processing_strategy": "create_order",
            },
        },
    },
    "AcmeAccount": {
        "1": {
            "key": "key_technology-rsa/acme_account_1.key",
            "provider": "pebble",
            "private_key_cycle": "single_certificate",
            "contact": "contact.a@example.com",
        },
        "2": {
            "key": "key_technology-rsa/acme_account_2.key",
            "provider": "pebble",
            "private_key_cycle": "single_certificate",
            "contact": "contact.b@example.com",
        },
        "3": {
            "key": "key_technology-rsa/acme_account_3.key",
            "provider": "pebble",
            "private_key_cycle": "single_certificate",
            "contact": "contact.c@example.com",
        },
        "4": {
            "key": "key_technology-rsa/acme_account_4.key",
            "provider": "pebble",
            "private_key_cycle": "single_certificate",
            "contact": "contact.d@example.com",
        },
        "5": {
            "key": "key_technology-rsa/acme_account_5.key",
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
            "le_x3_auth",
            "le_x4_auth",
            "le_x1_cross_signed",
            "le_x2_cross_signed",
            "le_x3_cross_signed",
            "le_x4_cross_signed",
        ),
        "cert": {
            "isrgrootx1": "letsencrypt-certs/isrgrootx1.pem",
            "le_x1_auth": "letsencrypt-certs/letsencryptauthorityx1.pem",
            "le_x2_auth": "letsencrypt-certs/letsencryptauthorityx2.pem",
            "le_x3_auth": "letsencrypt-certs/letsencryptauthorityx3.pem",
            "le_x4_auth": "letsencrypt-certs/letsencryptauthorityx4.pem",
            "le_x1_cross_signed": "letsencrypt-certs/lets-encrypt-x1-cross-signed.pem",
            "le_x2_cross_signed": "letsencrypt-certs/lets-encrypt-x2-cross-signed.pem",
            "le_x3_cross_signed": "letsencrypt-certs/lets-encrypt-x3-cross-signed.pem",
            "le_x4_cross_signed": "letsencrypt-certs/lets-encrypt-x4-cross-signed.pem",
        },
    },
    "CertificateRequests": {
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
    "Domains": {
        "Queue": {
            "1": {
                "add": "qadd1.example.com, qadd2.example.com, qadd3.example.com",
                "add.json": "qaddjson1.example.com, qaddjson2.example.com, qaddjson3.example.com",
            },
        },
        "AcmeDnsServer": {
            "1": {
                "ensure-domains.html": "ensure1-html.example.com, ensure2-html.example.com, ensure1.example.com",
                "ensure-domains.json": "ensure1-json.example.com, ensure2-json.example.com, ensure1.example.com",
            },
        },
    },
    "PrivateKey": {
        "1": {
            "file": "key_technology-rsa/private_1.key",
            "key_pem_md5": "462dc10731254d7f5fa7f0e99cbece73",
            "key_pem_modulus_md5": "fc1a6c569cba199eb5341c0c423fb768",
        },
        "2": {
            "file": "key_technology-rsa/private_2.key",
            "key_pem_md5": "cdde9325bdbfe03018e4119549c3a7eb",
            "key_pem_modulus_md5": "397282f3cd67d33b2b018b61fdd3f4aa",
        },
        "3": {
            "file": "key_technology-rsa/private_3.key",
            "key_pem_md5": "399236401eb91c168762da425669ad06",
            "key_pem_modulus_md5": "112d2db5daba540f8ff26fcaaa052707",
        },
        "4": {
            "file": "key_technology-rsa/private_4.key",
            "key_pem_md5": "6867998790e09f18432a702251bb0e11",
            "key_pem_modulus_md5": "687f3a3659cd423c48c50ed78a75eba0",
        },
        "5": {
            "file": "key_technology-rsa/private_5.key",
            "key_pem_md5": "1b13814854d8cee8c64732a2e2f7e73e",
            "key_pem_modulus_md5": "1eee27c04e912ff24614911abd2f0f8b",
        },
    },
    # the certificates are a tuple of: (CommonName, crt, csr, key)
    "ServerCertificates": {
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
            # these use `FormatA` and can be setup using `_setUp_ServerCertificates_FormatA`
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
            # these use `FormatA` and can be setup using `_setUp_ServerCertificates_FormatA`
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
}


CA_CERT_SETS = {
    "letsencrypt-certs/isrgrootx1.pem": {
        "key_technology": "RSA",
        "modulus_md5": "9454972e3730ac131def33e045ab19df",
    },
    "letsencrypt-certs/isrg-root-x2.pem": {"key_technology": "EC", "modulus_md5": None},
}


CSR_SETS = {
    "key_technology-ec/ec384-1.csr": {
        "key_private": {
            "file": "key_technology-ec/ec384-1-key.pem",
            "key_technology": "EC",
            "modulus_md5": None,
        },
        "modulus_md5": "e69f1df0d5a5c7c63e81a83c4f5411a7",
    },
    "key_technology-rsa/selfsigned_1-server.csr": {
        "key_private": {
            "file": "key_technology-rsa/selfsigned_1-server.csr",
            "key_technology": "RSA",
            "modulus_md5": "e0d99ec6424d5182755315d56398f658",
        },
        "modulus_md5": "e0d99ec6424d5182755315d56398f658",
    },
}


KEY_SETS = {
    "key_technology-rsa/acme_account_1.key": {
        "key_technology": "RSA",
        "modulus_md5": "ceec56ad4caba2cd70ee90c7d80fbb74",
    },
    "key_technology-ec/ec384-1-key.pem": {
        "key_technology": "EC",
        "modulus_md5": None,
    },
}


# ==============================================================================


class FakeAuthenticatedUser(object):
    accountkey_thumbprint = None

    def __init__(self, accountkey_thumbprint=None):
        self.accountkey_thumbprint = accountkey_thumbprint


class _Mixin_filedata(object):

    _data_root = os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data")

    def _filepath_testfile(self, filename):
        return os.path.join(self._data_root, filename)

    def _filedata_testfile(self, filename):
        with open(os.path.join(self._data_root, filename), "rt", encoding="utf-8") as f:
            data = f.read()
        return data


class AppTestCore(unittest.TestCase, _Mixin_filedata):
    testapp = None
    testapp_http = None
    _session_factory = None
    _DB_INTIALIZED = False
    _settings = None

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
            db._setup.initialize_DomainBlocklisted(dbSession)
            dbSession.commit()
            dbSession.close()

        app = main(global_config=None, **settings)
        self.testapp = TestApp(
            app,
            extra_environ={
                "HTTP_HOST": "peter-sslers.example.com",
            },
        )
        AppTestCore._DB_INTIALIZED = True

    def tearDown(self):
        if self.testapp is not None:
            pass
        self._session_factory = None

        self._turnoff_items()

    def _turnoff_items(self):
        """when running multiple tests, ensure we turn off blocking items"""
        _query = self.ctx.dbSession.query(model_objects.AcmeOrder).filter(
            model_objects.AcmeOrder.acme_status_order_id.in_(
                model_utils.Acme_Status_Order.IDS_BLOCKING
            ),
        )
        _changed = None
        _orders = _query.all()
        for _order in _orders:
            _acme_status_order_id = model_utils.Acme_Status_Order.from_string("*410*")
            if _order.acme_status_order_id != _acme_status_order_id:
                _order.acme_status_order_id = _acme_status_order_id
                _order.timestamp_updated = self.ctx.timestamp
                _changed = True
            try:
                _order = db.update.update_AcmeOrder_deactivate(self.ctx, _order)
                _changed = True
            except errors.InvalidTransition as exc:
                # don't fret on this having an invalid
                pass
        if _changed:
            self.ctx.dbSession.commit()

    def _has_active_challenges(self):
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
            # Path2: AcmeChallenge>AcmeOrderless
            .join(
                model_objects.AcmeOrderless,
                model_objects.AcmeChallenge.acme_orderless_id
                == model_objects.AcmeOrderless.id,
                isouter=True,
            )
            # shared filters
            .join(
                model_objects.Domain,
                model_objects.AcmeChallenge.domain_id == model_objects.Domain.id,
            )
            .filter(
                model_objects.Domain.domain_name.notin_(
                    ("selfsigned-1.example.com", "acme-orderless.example.com")
                ),
                sqlalchemy.or_(
                    # Path1 - Order Based Authorizations
                    sqlalchemy.and_(
                        model_objects.AcmeChallenge.acme_authorization_id.op("IS NOT")(
                            None
                        ),
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
                    # Path2 - Orderless
                    sqlalchemy.and_(
                        model_objects.AcmeChallenge.acme_orderless_id.op("IS NOT")(
                            None
                        ),
                        model_objects.AcmeOrderless.is_processing.op("IS")(True),
                    ),
                ),
            )
        )
        res = query.all()
        return res


# ==============================================================================


class AppTest(AppTestCore):

    _ctx = None
    _DB_SETUP_RECORDS = False

    def _setUp_ServerCertificates_FormatA(self, payload_section, payload_key):
        filename_template = None
        if payload_section == "AlternateChains":
            filename_template = "alternate_chains/%s/%%s" % payload_key
        elif payload_section == "Pebble":
            filename_template = "pebble-certs/%s"
        else:
            raise ValueError("invalid payload_section")
        _pkey_filename = (
            filename_template
            % TEST_FILES["ServerCertificates"][payload_section][payload_key]["pkey"]
        )
        _pkey_pem = self._filedata_testfile(_pkey_filename)
        (_dbPrivateKey, _is_created,) = db.getcreate.getcreate__PrivateKey__by_pem_text(
            self.ctx,
            _pkey_pem,
            private_key_source_id=model_utils.PrivateKeySource.from_string("imported"),
            private_key_type_id=model_utils.PrivateKeyType.from_string("standard"),
        )
        _chain_filename = (
            filename_template
            % TEST_FILES["ServerCertificates"][payload_section][payload_key]["chain"]
        )
        _chain_pem = self._filedata_testfile(_chain_filename)
        (_dbChain, _is_created,) = db.getcreate.getcreate__CACertificate__by_pem_text(
            self.ctx, _chain_pem, ca_chain_name=_chain_filename
        )

        dbCACertificates_alt = None
        if (
            "alternate_chains"
            in TEST_FILES["ServerCertificates"][payload_section][payload_key]
        ):
            dbCACertificates_alt = []
            for _chain_index in TEST_FILES["ServerCertificates"][payload_section][
                payload_key
            ]["alternate_chains"]:
                _chain_subpath = "alternate_chains/%s/%s" % (
                    payload_key,
                    TEST_FILES["ServerCertificates"][payload_section][payload_key][
                        "alternate_chains"
                    ][_chain_index]["chain"],
                )
                _chain_filename = filename_template % _chain_subpath
                _chain_pem = self._filedata_testfile(_chain_filename)
                (
                    _dbChainAlternate,
                    _is_created,
                ) = db.getcreate.getcreate__CACertificate__by_pem_text(
                    self.ctx, _chain_pem, ca_chain_name=_chain_filename
                )
                dbCACertificates_alt.append(_dbChainAlternate)

        _cert_filename = (
            filename_template
            % TEST_FILES["ServerCertificates"][payload_section][payload_key]["cert"]
        )
        _cert_domains_expected = [
            TEST_FILES["ServerCertificates"][payload_section][payload_key]["domain"],
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
            _dbServerCertificate,
            _is_created,
        ) = db.getcreate.getcreate__ServerCertificate(
            self.ctx,
            _cert_pem,
            cert_domains_expected=_cert_domains_expected,
            dbCACertificate=_dbChain,
            dbCACertificates_alt=dbCACertificates_alt,
            dbUniqueFQDNSet=_dbUniqueFQDNSet,
            dbPrivateKey=_dbPrivateKey,
        )

        # commit this!
        self.ctx.pyramid_transaction_commit()

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
                        isrgrootx1.pem
                        selfsigned_1-server.crt
                    PrivateKey
                        selfsigned_1-server.key

                    AcmeEventLog
                """
                # note: pre-populate AcmeAccount
                # this should create `/acme-account/1`
                _dbAcmeAccount_1 = None
                for _id in TEST_FILES["AcmeAccount"]:
                    _key_filename = TEST_FILES["AcmeAccount"][_id]["key"]
                    _private_key_cycle = TEST_FILES["AcmeAccount"][_id][
                        "private_key_cycle"
                    ]
                    key_pem = self._filedata_testfile(_key_filename)
                    (
                        _dbAcmeAccount,
                        _is_created,
                    ) = db.getcreate.getcreate__AcmeAccount(
                        self.ctx,
                        key_pem,
                        contact=TEST_FILES["AcmeAccount"][_id]["contact"],
                        acme_account_provider_id=1,  # acme_account_provider_id(1) == pebble
                        acme_account_key_source_id=model_utils.AcmeAccountKeySource.from_string(
                            "imported"
                        ),
                        event_type="AcmeAccount__insert",
                        private_key_cycle_id=model_utils.PrivateKeyCycle.from_string(
                            _private_key_cycle
                        ),
                    )
                    # print(_dbAcmeAccount_1, _is_created)
                    # self.ctx.pyramid_transaction_commit()
                    if _id == "1":
                        _dbAcmeAccount_1 = _dbAcmeAccount
                        if not _dbAcmeAccount.is_global_default:
                            db.update.update_AcmeAccount__set_global_default(
                                self.ctx, _dbAcmeAccount
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

                    if pkey_id == "5":
                        # make a CoverageAssuranceEvent
                        _event_type_id = model_utils.OperationsEventType.from_string(
                            "PrivateKey__revoke"
                        )
                        _event_payload_dict = utils.new_event_payload_dict()
                        _event_payload_dict["private_key.id"] = _dbPrivateKey_alt.id
                        _event_payload_dict["action"] = "compromised"
                        _dbOperationsEvent = db.logger.log__OperationsEvent(
                            self.ctx, _event_type_id, _event_payload_dict
                        )
                        _event_status = db.update.update_PrivateKey__set_compromised(
                            self.ctx, _dbPrivateKey_alt, _dbOperationsEvent
                        )

                # note: pre-populate ServerCertificate 1-5
                # this should create `/server-certificate/1`
                #
                _dbServerCertificate_1 = None
                _dbServerCertificate_2 = None
                _dbServerCertificate_3 = None
                _dbServerCertificate_4 = None
                _dbServerCertificate_5 = None
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
                        self.ctx,
                        _cert_domains_expected,
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
                    elif _id == "2":
                        _dbServerCertificate_2 = _dbServerCertificate
                    elif _id == "3":
                        _dbServerCertificate_3 = _dbServerCertificate
                    elif _id == "4":
                        _dbServerCertificate_4 = _dbServerCertificate
                    elif _id == "5":
                        _dbServerCertificate_5 = _dbServerCertificate

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

                # note: pre-populate ServerCertificate 6-10, via "Pebble"
                for _id in TEST_FILES["ServerCertificates"]["Pebble"].keys():
                    self._setUp_ServerCertificates_FormatA("Pebble", _id)

                # self.ctx.pyramid_transaction_commit()

                # note: pre-populate QueueDomain
                # queue a domain
                # this MUST be a new domain to add to the queue
                # if it is existing, a domain will not be added
                db.queues.queue_domains__add(
                    self.ctx,
                    ["queue.example.com", "queue2.example.com", "queue3.example.com"],
                )
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
                    dbAcmeAccount=_dbAcmeAccount_1,
                    dbPrivateKey=_dbPrivateKey_1,
                    dbServerCertificate=_dbServerCertificate_1,
                    private_key_cycle_id__renewal=1,  # "single_certificate"
                    private_key_strategy_id__requested=model_utils.PrivateKeyStrategy.from_string(
                        "specified"
                    ),
                )
                # self.ctx.pyramid_transaction_commit()

                # we need at least 4 of these
                _dbQueue2 = db.create.create__QueueCertificate(
                    self.ctx,
                    dbAcmeAccount=_dbAcmeAccount_1,
                    dbPrivateKey=_dbPrivateKey_1,
                    dbServerCertificate=_dbServerCertificate_2,
                    private_key_cycle_id__renewal=1,  # "single_certificate"
                    private_key_strategy_id__requested=model_utils.PrivateKeyStrategy.from_string(
                        "specified"
                    ),
                )
                _dbQueue3 = db.create.create__QueueCertificate(
                    self.ctx,
                    dbAcmeAccount=_dbAcmeAccount_1,
                    dbPrivateKey=_dbPrivateKey_1,
                    dbServerCertificate=_dbServerCertificate_3,
                    private_key_cycle_id__renewal=1,  # "single_certificate"
                    private_key_strategy_id__requested=model_utils.PrivateKeyStrategy.from_string(
                        "specified"
                    ),
                )
                _dbQueue4 = db.create.create__QueueCertificate(
                    self.ctx,
                    dbAcmeAccount=_dbAcmeAccount_1,
                    dbPrivateKey=_dbPrivateKey_1,
                    dbServerCertificate=_dbServerCertificate_4,
                    private_key_cycle_id__renewal=1,  # "single_certificate"
                    private_key_strategy_id__requested=model_utils.PrivateKeyStrategy.from_string(
                        "specified"
                    ),
                )
                self.ctx.pyramid_transaction_commit()

                # note: pre-populate AcmeOrder

                # merge these items in
                _dbAcmeAccount_1 = self.ctx.dbSession.merge(
                    _dbAcmeAccount_1, load=False
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
                _private_key_cycle_id__renewal = (
                    model_utils.PrivateKeyCycle.from_string("single_certificate")
                )
                _private_key_strategy_id__requested = (
                    model_utils.PrivateKeyStrategy.from_string("specified")
                )
                _acme_event_id = model_utils.AcmeEvent.from_string("v2|newOrder")
                _dbAcmeEventLog = model_objects.AcmeEventLog()
                _dbAcmeEventLog.acme_event_id = _acme_event_id
                _dbAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
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
                _dbAcmeOrder_1 = db.create.create__AcmeOrder(
                    self.ctx,
                    acme_order_response=_acme_order_response,
                    acme_order_type_id=_acme_order_type_id,
                    acme_order_processing_status_id=_acme_order_processing_status_id,
                    acme_order_processing_strategy_id=_acme_order_processing_strategy_id,
                    private_key_cycle_id__renewal=_private_key_cycle_id__renewal,
                    private_key_strategy_id__requested=_private_key_strategy_id__requested,
                    order_url="https://example.com/acme/order/acmeOrder-1",
                    dbAcmeAccount=_dbAcmeAccount_1,
                    dbEventLogged=_dbAcmeEventLog,
                    dbPrivateKey=_dbPrivateKey_1,
                    dbUniqueFQDNSet=_dbUniqueFQDNSet_1,
                    domains_challenged=_domains_challenged,
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
                assert _dbAcmeAuthorization_1.acme_challenge_http_01 is not None

                _db__AcmeChallengePoll = db.create.create__AcmeChallengePoll(
                    self.ctx,
                    dbAcmeChallenge=_dbAcmeAuthorization_1.acme_challenge_http_01,
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

                # note: pre-populate AcmeOrderless
                _domains_challenged = model_utils.DomainsChallenged.new_http01(
                    [
                        "acme-orderless.example.com",
                    ]
                )
                dbAcmeOrderless = db.create.create__AcmeOrderless(
                    self.ctx,
                    domains_challenged=_domains_challenged,
                    dbAcmeAccount=None,
                )

                # note: pre-populate AcmeDnsServer
                (dbAcmeDnsServer, _x) = db.getcreate.getcreate__AcmeDnsServer(
                    self.ctx,
                    root_url=ACME_DNS_API,
                    is_global_default=True,
                )
                (dbAcmeDnsServer_2, _x) = db.getcreate.getcreate__AcmeDnsServer(
                    self.ctx,
                    root_url=TEST_FILES["AcmeDnsServer"]["2"]["root_url"],
                )

                (
                    _dbAcmeDnsServerAccount_domain,
                    _x,
                ) = db.getcreate.getcreate__Domain__by_domainName(
                    self.ctx,
                    domain_name=TEST_FILES["AcmeDnsServerAccount"]["1"]["domain"],
                )
                dbAcmeDnsServerAccount = db.create.create__AcmeDnsServerAccount(
                    self.ctx,
                    dbAcmeDnsServer=dbAcmeDnsServer_2,
                    dbDomain=_dbAcmeDnsServerAccount_domain,
                    username=TEST_FILES["AcmeDnsServerAccount"]["1"]["username"],
                    password=TEST_FILES["AcmeDnsServerAccount"]["1"]["password"],
                    fulldomain=TEST_FILES["AcmeDnsServerAccount"]["1"]["fulldomain"],
                    subdomain=TEST_FILES["AcmeDnsServerAccount"]["1"]["subdomain"],
                    allowfrom=TEST_FILES["AcmeDnsServerAccount"]["1"]["allowfrom"],
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
            # merge in the settings
            self._ctx.request.registry.settings = self.testapp.app.registry.settings
        return self._ctx


# ==============================================================================


class AppTestWSGI(AppTest, _Mixin_filedata):
    testapp = None
    testapp_http = None
    _session_factory = None
    _DB_INTIALIZED = False

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
