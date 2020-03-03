from __future__ import print_function

# stdlib
import datetime
import os
import pdb
import unittest
from io import open  # overwrite `open` in Python2

# pyramid
from pyramid import testing
from pyramid.paster import get_appsettings

# pypi
import transaction
from webtest import TestApp

# local
from ..web import main
from ..model import utils as model_utils
from ..model import meta as model_meta
from ..lib import db
from ..lib import utils


# ==============================================================================

"""
export SSL_RUN_NGINX_TESTS=True
export SSL_RUN_REDIS_TESTS=True
export SSL_RUN_LETSENCRYPT_API_TESTS=True
export SSL_LETSENCRYPT_API_VALIDATES=True
export SSL_TEST_DOMAINS=dev.cliqued.in  # can be a comma-separated string
export SSL_TEST_PORT=7201

if running letsencrypt tests, you need to specify a domain and make sure to proxy to this app so letsencrypt can access it

see the nginx test config file `testing.conf`

"""

# run tests that expire nginx caches
RUN_NGINX_TESTS = os.environ.get("SSL_RUN_NGINX_TESTS", False)
# run tests to prime redis
RUN_REDIS_TESTS = os.environ.get("SSL_RUN_REDIS_TESTS", False)
# run tests against LE API
RUN_LETSENCRYPT_API_TESTS = os.environ.get("SSL_RUN_LETSENCRYPT_API_TESTS", False)
# does the LE validation work?  LE must be able to reach this
LETSENCRYPT_API_VALIDATES = os.environ.get("SSL_LETSENCRYPT_API_VALIDATES", False)

SSL_TEST_DOMAINS = os.environ.get("SSL_TEST_DOMAINS", "example.com")
SSL_TEST_PORT = int(os.environ.get("SSL_TEST_PORT", 7201))

DISABLE_UNWRITTEN_TESTS = True


# ==============================================================================


DEFAULT_acme_account_provider = "letsencrypt-v2-staging"
DEFAULT_acme_account_provider_id = None

pdb.set_trace()
raise ValueError("PORT ME")

for pvd in model_utils.AcmeAccountProvider.registry.values():
    if pvd["name"] == DEFAULT_acme_account_provider:
        DEFAULT_acme_account_provider_id = pvd["id"]
        break


class FakeRequest(testing.DummyRequest):
    @property
    def tm(self):
        return transaction.manager


# ==============================================================================


TEST_FILES = {
    "AcmeAccountKey": {
        "1": "acme_account_1.key",
        "2": "acme_account_2.key",
        "3": "acme_account_3.key",
        "4": "acme_account_4.key",
        "5": "acme_account_5.key",
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
    "Domains": {
        "Queue": {
            "1": {
                "add": "qadd1.example.com, qadd2.example.com, qadd3.example.com",
                "add.json": "qaddjson1.example.com, qaddjson2.example.com, qaddjson3.example.com",
            }
        }
    },
}


# ==============================================================================


class AppTestCore(unittest.TestCase):
    _data_root = None
    testapp = None
    testapp_http = None

    def _filepath_testfile(self, filename):
        return os.path.join(self._data_root, filename)

    def _filedata_testfile(self, filename):
        with open(os.path.join(self._data_root, filename), "rt", encoding="utf-8") as f:
            data = f.read()
        return data

    def setUp(self):
        settings = get_appsettings(
            "test.ini", name="main"
        )  # this can cause an unclosed resource
        # sqlalchemy.url = sqlite:///%(here)s/example_ssl_minnow_test.sqlite
        if False:
            settings["sqlalchemy.url"] = "sqlite://"
        app = main(global_config=None, **settings)
        self.testapp = TestApp(app)
        self._data_root = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "test_data"
        )

    def tearDown(self):
        if self.testapp_http is not None:
            self.testapp_http.shutdown()


# ==============================================================================


class AppTest(AppTestCore):

    _ctx = None
    _DB_INTIALIZED = False

    def setUp(self):
        AppTestCore.setUp(self)
        if not AppTest._DB_INTIALIZED:

            print("---------------")
            print("INITIALIZING DB")
            engine = self.testapp.app.registry["dbSession_factory"]().bind

            model_meta.Base.metadata.drop_all(engine)
            engine.execute("VACUUM")
            model_meta.Base.metadata.create_all(engine)

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

                #
                # insert AcmeAccountKey
                # this should create `/acme-account-key/1`
                #
                _key_filename = TEST_FILES["AcmeAccountKey"]["1"]
                key_pem = self._filedata_testfile(_key_filename)
                _key_account1, _is_created = db.getcreate.getcreate__AcmeAccountKey(
                    self.ctx,
                    key_pem,
                    acme_account_provider_id=DEFAULT_acme_account_provider_id,
                    acme_account_key_source_id=model_utils.AcmeAccountKeySource.from_string(
                        "imported"
                    ),
                    event_type="AcmeAccountKey__insert",
                )
                # print(_key_account1, _is_created)
                # self.ctx.pyramid_transaction_commit()

                #
                # insert CACertificate
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

                #
                # insert CACertificate - self signed
                # this should create `/ca-certificate/2`
                #
                _ca_cert_filename = TEST_FILES["ServerCertificates"]["SelfSigned"]["1"][
                    "cert"
                ]
                ca_cert_pem = self._filedata_testfile(_ca_cert_filename)
                (
                    _ca_cert_selfsigned1,
                    _is_created,
                ) = db.getcreate.getcreate__CACertificate__by_pem_text(
                    self.ctx, ca_cert_pem, ca_chain_name=_ca_cert_filename
                )
                # print(_ca_cert_selfsigned1, _is_created)
                # self.ctx.pyramid_transaction_commit()

                #
                # insert PrivateKey
                # this should create `/private-key/1`
                #
                _pkey_filename = TEST_FILES["ServerCertificates"]["SelfSigned"]["1"][
                    "pkey"
                ]
                pkey_pem = self._filedata_testfile(_pkey_filename)
                (
                    _key_private1,
                    _is_created,
                ) = db.getcreate.getcreate__PrivateKey__by_pem_text(
                    self.ctx,
                    pkey_pem,
                    private_key_source_id=model_utils.PrivateKeySource.from_string(
                        "imported"
                    ),
                )
                # print(_key_private1, _is_created)
                # self.ctx.pyramid_transaction_commit()

                #
                # insert ServerCertificate
                # this should create `/server-certificate/1`
                #
                _cert_filename = TEST_FILES["ServerCertificates"]["SelfSigned"]["1"][
                    "cert"
                ]
                cert_pem = self._filedata_testfile(_cert_filename)
                (
                    _cert_1,
                    _is_created,
                ) = db.getcreate.getcreate__ServerCertificate__by_pem_text(
                    self.ctx,
                    cert_pem,
                    dbCACertificate=_ca_cert_selfsigned1,
                    dbAcmeAccountKey=_key_account1,
                    dbPrivateKey=_key_private1,
                )
                # print(_cert_1, _is_created)
                # self.ctx.pyramid_transaction_commit()

                # ensure we have domains?
                domains = db.get.get__Domain__paginated(self.ctx)
                domain_names = [d.domain_name for d in domains]
                assert (
                    TEST_FILES["ServerCertificates"]["SelfSigned"]["1"][
                        "domain"
                    ].lower()
                    in domain_names
                )

                # upload a csr
                _csr_filename = TEST_FILES["ServerCertificates"]["SelfSigned"]["1"][
                    "csr"
                ]
                csr_pem = self._filedata_testfile(_csr_filename)
                (
                    _csr_1,
                    _is_created,
                ) = db.getcreate.getcreate__CertificateRequest__by_pem_text(
                    self.ctx,
                    csr_pem,
                    certificate_request_source_id=model_utils.CertificateRequestSource.IMPORTED,
                    dbPrivateKey=_key_private1,
                    domain_names=[
                        TEST_FILES["ServerCertificates"]["SelfSigned"]["1"]["domain"],
                    ],  # make it an iterable
                )
                # self.ctx.pyramid_transaction_commit()

                # queue a domain
                # this MUST be a new domain to add to the queue
                # if it is existing, a domain will not be added
                db.queues.queue_domains__add(self.ctx, ["queue.example.com"])
                # self.ctx.pyramid_transaction_commit()

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
                dbQueue = db.create._create__QueueCertificate(self.ctx, _cert_1)
                # self.ctx.pyramid_transaction_commit()

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
                raise
            print("DB INITIALIZED")
            AppTest._DB_INTIALIZED = True

    def tearDown(self):
        AppTestCore.tearDown(self)
        if self._ctx is not None:
            self._ctx.dbSession.close()

    @property
    def ctx(self):
        if self._ctx is None:
            dbSession_factory = self.testapp.app.registry["dbSession_factory"]
            dbSessionLogger_factory = self.testapp.app.registry[
                "dbSessionLogger_factory"
            ]
            self._ctx = utils.ApiContext(
                request=FakeRequest(),
                dbSession=dbSession_factory(),
                dbSessionLogger=dbSessionLogger_factory(),
                timestamp=datetime.datetime.utcnow(),
            )
        return self._ctx