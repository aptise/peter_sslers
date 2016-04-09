# pyramid
from pyramid import testing
from pyramid.paster import get_appsettings

# pypi
import transaction
from webtest import TestApp
from webtest import Upload

# stdlib
import json
import pdb
import os
import unittest

# local
from . import main
from . import models
from . import lib
import sqlalchemy


# ==============================================================================


"""
queue tests:
- add existing active domain to queue
- add existing inactive domain to queue
- add non-existing domain to queue
- turn off existing, active domain
- turn off existing, inactive domain
- turn off non-existing, inactive domain
"""


# ==============================================================================


TEST_FILES = {'AccountKey': {'1': 'account_1.key',
                             '2': 'account_2.key',
                             '3': 'account_3.key',
                             '4': 'account_4.key',
                             '5': 'account_5.key',
                             },
              'CaCertificates': {'order': ('isrgrootx1',
                                           'le_x1_auth',
                                           'le_x2_auth',
                                           'le_x1_cross_signed',
                                           'le_x2_cross_signed',
                                           'le_x3_cross_signed',
                                           'le_x4_cross_signed',
                                           ),
                                 'cert': {'isrgrootx1': 'isrgrootx1.pem.txt',
                                          'le_x1_auth': 'letsencryptauthorityx1.pem.txt',
                                          'le_x2_auth': 'letsencryptauthorityx2.pem.txt',
                                          'le_x1_cross_signed': 'lets-encrypt-x1-cross-signed.pem.txt',
                                          'le_x2_cross_signed': 'lets-encrypt-x2-cross-signed.pem.txt',
                                          'le_x3_cross_signed': 'lets-encrypt-x3-cross-signed.pem.txt',
                                          'le_x4_cross_signed': 'lets-encrypt-x4-cross-signed.pem.txt',
                                          },
                                 },
              # the certificates are a tuple of: (CommonName, crt, csr, key)
              'ServerCertificates': {'SelfSigned': {'1': {'domain': 'selfsigned-1.example.com',
                                                          'cert': 'selfsigned_1-server.crt',
                                                          'csr': 'selfsigned_1-server.csr',
                                                          'pkey': 'selfsigned_1-server.key',
                                                          },
                                                    '2': {'domain': 'selfsigned-2.example.com',
                                                          'cert': 'selfsigned_2-server.crt',
                                                          'csr': 'selfsigned_2-server.csr',
                                                          'pkey': 'selfsigned_2-server.key',
                                                          },
                                                    '3': {'domain': 'selfsigned-3.example.com',
                                                          'cert': 'selfsigned_3-server.crt',
                                                          'csr': 'selfsigned_3-server.csr',
                                                          'pkey': 'selfsigned_3-server.key',
                                                          },
                                                    '4': {'domain': 'selfsigned-4.example.com',
                                                          'cert': 'selfsigned_4-server.crt',
                                                          'csr': 'selfsigned_4-server.csr',
                                                          'pkey': 'selfsigned_4-server.key',
                                                          },
                                                    '5': {'domain': 'selfsigned-5.example.com',
                                                          'cert': 'selfsigned_5-server.crt',
                                                          'csr': 'selfsigned_5-server.csr',
                                                          'pkey': 'selfsigned_5-server.key',
                                                          },
                                                    },
                                     'LetsEncrypt': {},
                                     },
              }

# TODO - set these by environment variables
RUN_NGINX_TESTS = False
RUN_LETSENCRYPT_API_TESTS = False


class AppTest(unittest.TestCase):
    _session = None
    _DB_INTIALIZED = False
    _data_root = None

    def _filepath_testfile(self, filename):
        return os.path.join(self._data_root, filename)

    def _filedata_testfile(self, filename):
        return open(os.path.join(self._data_root, filename), 'r').read()

    def setUp(self):
        settings = get_appsettings('test.ini', name='main')
        # sqlalchemy.url = sqlite:///%(here)s/ssl_minnow_test.sqlite
        if False:
            settings['sqlalchemy.url'] = "sqlite://"
        app = main(global_config = None, **settings)
        self.testapp = TestApp(app)
        # DO STUFF HERE
        self._data_root = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'test_data')

        if not AppTest._DB_INTIALIZED:
            print "---------------"
            print "INITIALIZING DB"
            engine = app.registry['dbsession_factory']().bind

            models.meta.Base.metadata.drop_all(engine)
            engine.execute("VACUUM")
            models.meta.Base.metadata.create_all(engine)

            try:
                """
                This setup pre-populates the DB with some objects needed for routes to work:

                    AccountKey:
                        account_1.key
                    CaCertificates:
                        isrgrootx1.pem.txt
                        selfsigned_1-server.crt
                    PrivateKey
                        selfsigned_1-server.key
                """

                #
                # insert SslLetsEncryptAccountKey
                # this should create `/account-key/1`
                #
                _key_filename = TEST_FILES['AccountKey']['1']
                key_pem = self._filedata_testfile(_key_filename)
                _key_account1, _is_created = lib.db.getcreate__SslLetsEncryptAccountKey__by_pem_text(self.session, key_pem)
                # print _key_account1, _is_created
                self.session.commit()

                #
                # insert SslCaCertificate
                # this should create `/ca-certificate/1`
                #
                _ca_cert_id = 'isrgrootx1'
                _ca_cert_filename = TEST_FILES['CaCertificates']['cert'][_ca_cert_id]
                ca_cert_pem = self._filedata_testfile(_ca_cert_filename)
                _ca_cert_1, _is_created = lib.db.getcreate__SslCaCertificate__by_pem_text(
                    self.session,
                    ca_cert_pem,
                    "ISRG Root",
                    le_authority_name = "ISRG ROOT",
                    is_authority_certificate = True,
                    is_cross_signed_authority_certificate = False,
                )
                # print _ca_cert_1, _is_created
                self.session.commit()

                #
                # insert SslCaCertificate - self signed
                # this should create `/ca-certificate/2`
                #
                _ca_cert_filename = TEST_FILES['ServerCertificates']['SelfSigned']['1']['cert']
                ca_cert_pem = self._filedata_testfile(_ca_cert_filename)
                _ca_cert_selfsigned1, _is_created = lib.db.getcreate__SslCaCertificate__by_pem_text(
                    self.session,
                    ca_cert_pem,
                    _ca_cert_filename,
                )
                # print _ca_cert_selfsigned1, _is_created
                self.session.commit()

                #
                # insert SslPrivateKey
                # this should create `/private-key/1`
                #
                _pkey_filename = TEST_FILES['ServerCertificates']['SelfSigned']['1']['pkey']
                pkey_pem = self._filedata_testfile(_pkey_filename)
                _key_private1, _is_created = lib.db.getcreate__SslPrivateKey__by_pem_text(self.session, pkey_pem)
                # print _key_private1, _is_created
                self.session.commit()

                #
                # insert SslServerCertificate
                # this should create `/certificate/1`
                #
                _cert_filename = TEST_FILES['ServerCertificates']['SelfSigned']['1']['cert']
                cert_pem = self._filedata_testfile(_cert_filename)
                _cert_1, _is_created = lib.db.getcreate__SslServerCertificate__by_pem_text(
                    self.session,
                    cert_pem,
                    dbCACertificate = _ca_cert_selfsigned1,
                    dbAccountKey = _key_account1,
                    dbPrivateKey = _key_private1,
                )
                # print _cert_1, _is_created
                self.session.commit()

                # ensure we have domains?
                domains = lib.db.get__SslDomain__paginated(self.session)
                domain_names = [d.domain_name for d in domains]
                assert TEST_FILES['ServerCertificates']['SelfSigned']['1']['domain'].lower() in domain_names

                # this shouldn't need to be handled here, because creating a cert would populate this table
                if False:
                    # insert a domain name
                    # one should be extracted from uploading a ServerCertificate though
                    _domain, _is_created = lib.db.getcreate__SslDomain__by_domainName(self.session, "www.example.com")
                    self.session.commit()

                    # insert a domain name
                    # one should be extracted from uploading a ServerCertificate though
                    # getcreate__SslUniqueFQDNSet__by_domainObjects

                # upload a csr
                _csr_filename = TEST_FILES['ServerCertificates']['SelfSigned']['1']['csr']
                csr_pem = self._filedata_testfile(_csr_filename)
                _csr_1, _is_created = lib.db.getcreate__SslCertificateRequest__by_pem_text(
                    self.session,
                    csr_pem,
                    certificate_request_type_id = models.SslCertificateRequestType.ACME_FLOW,
                    dbAccountKey = _key_account1,
                    dbPrivateKey = _key_private1,
                )

            except Exception as e:
                print ""
                print ""
                print ""
                print "EXCEPTION IN SETUP"
                print ""
                print e
                print ""
                print ""
                print ""
                pdb.set_trace()
            print "DB INITIALIZED"
            AppTest._DB_INTIALIZED = True

    def tearDown(self):
        if self._session is not None:
            self._session.close()

    @property
    def session(self):
        if self._session is None:
            dbsession_factory = self.testapp.app.registry['dbsession_factory']
            self._session = dbsession_factory()
        return self._session


class FunctionalTests_Main(AppTest):

    def test_root(self):
        res = self.testapp.get('/.well-known/admin', status=200)

    def test_whoami(self):
        res = self.testapp.get('/.well-known/admin/whoami', status=200)

    def test_help(self):
        res = self.testapp.get('/.well-known/admin/help', status=200)

    def test_search(self):
        res = self.testapp.get('/.well-known/admin/search', status=200)


class FunctionalTests_AccountKeys(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_AccountKeys"""
    """python -m unittest peter_sslers.tests.FunctionalTests_AccountKeys.test_new"""

    def _get_item(self):
        # grab a Key
        focus_item = self.session.query(models.SslLetsEncryptAccountKey)\
            .filter(models.SslLetsEncryptAccountKey.is_active.op('IS')(True))\
            .order_by(models.SslLetsEncryptAccountKey.id.asc())\
            .first()
        return focus_item

    def test_list(self):
        # root
        res = self.testapp.get('/.well-known/admin/account-keys', status=200)
        # paginated
        res = self.testapp.get('/.well-known/admin/account-keys/1', status=200)

    def test_focus(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get('/.well-known/admin/account-key/%s' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/account-key/%s/parse.json' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/account-key/%s/key.key' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/account-key/%s/key.pem' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/account-key/%s/key.pem.txt' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/account-key/%s/certificate-requests' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/account-key/%s/certificate-requests/1' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/account-key/%s/certificates' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/account-key/%s/certificates/1' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/account-key/%s/config.json' % focus_id, status=200)

    def test_manipulate(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        if not focus_item.is_default:
            # make sure to roundtrip!
            # note we expect a 302 on success!
            if focus_item.is_active:
                res = self.testapp.get('/.well-known/admin/account-key/%s/mark' % focus_id, {'action': 'deactivate'}, status=302)
                res = self.testapp.get('/.well-known/admin/account-key/%s/mark.json' % focus_id, {'action': 'activate'}, status=302)
            else:
                res = self.testapp.get('/.well-known/admin/account-key/%s/mark' % focus_id, {'action': 'activate'}, status=302)
                res = self.testapp.get('/.well-known/admin/account-key/%s/mark.json' % focus_id, {'action': 'deactivate'}, status=302)
        else:
            # TODO
            print "MUST TEST non-default"

    def test_new(self):
        # this should be creating a new key
        _key_filename = TEST_FILES['AccountKey']['2']
        key_filepath = self._filepath_testfile(_key_filename)

        res = self.testapp.get('/.well-known/admin/account-key/new', status=200)
        form = res.form
        form['account_key_file'] = Upload(key_filepath)
        res2 = form.submit()
        assert res2.status_code == 302
        assert res2.location == """http://localhost/.well-known/admin/account-key/2?is_created=1"""
        res3 = self.testapp.get(res2.location, status=200)

    @unittest.skipUnless(RUN_LETSENCRYPT_API_TESTS, "not running against letsencrypt api")
    def tests_letsencrypt_api(self):
        raise NotImplementedError()
        # this hits LE
        res = self.testapp.get('/.well-known/admin/account-key/1/authenticate', status=200)


class FunctionalTests_API(AppTest):

    def test_simple(self):
        # root
        res = self.testapp.get('/.well-known/admin/api', status=200)
        res = self.testapp.get('/.well-known/admin/api/domain/enable', status=200)
        res = self.testapp.get('/.well-known/admin/api/domain/disable', status=200)


class FunctionalTests_CACertificate(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_CACertificate"""
    """python -m unittest peter_sslers.tests.FunctionalTests_CACertificate.test_upload"""

    def test_list(self):
        # root
        res = self.testapp.get('/.well-known/admin/ca-certificates', status=200)
        # paginated
        res = self.testapp.get('/.well-known/admin/ca-certificates/1', status=200)

    def test_focus(self):
        res = self.testapp.get('/.well-known/admin/ca-certificate/1', status=200)
        res = self.testapp.get('/.well-known/admin/ca-certificate/1/parse.json', status=200)

        res = self.testapp.get('/.well-known/admin/ca-certificate/1/chain.cer', status=200)
        res = self.testapp.get('/.well-known/admin/ca-certificate/1/chain.crt', status=200)
        res = self.testapp.get('/.well-known/admin/ca-certificate/1/chain.der', status=200)
        res = self.testapp.get('/.well-known/admin/ca-certificate/1/chain.pem', status=200)
        res = self.testapp.get('/.well-known/admin/ca-certificate/1/chain.pem.txt', status=200)
        res = self.testapp.get('/.well-known/admin/ca-certificate/1/signed_certificates', status=200)
        res = self.testapp.get('/.well-known/admin/ca-certificate/1/signed_certificates/1', status=200)

    def test_upload(self):
        """This should enter in item #3, but the CaCertificates.order is 1; the other cert is a self-signed"""
        _ca_cert_id = TEST_FILES['CaCertificates']['order'][1]
        _ca_cert_filename = TEST_FILES['CaCertificates']['cert'][_ca_cert_id]
        _ca_cert_filepath = self._filepath_testfile(_ca_cert_filename)

        res = self.testapp.get('/.well-known/admin/ca-certificate/upload', status=200)
        form = res.form
        form['chain_file'] = Upload(_ca_cert_filepath)
        res2 = form.submit()
        assert res2.status_code == 302
        assert res2.location == """http://localhost/.well-known/admin/ca-certificate/3?is_created=1"""
        res3 = self.testapp.get(res2.location, status=200)

        """This should enter in item #4"""
        _ca_cert_id = TEST_FILES['CaCertificates']['order'][2]
        _ca_cert_filename = TEST_FILES['CaCertificates']['cert'][_ca_cert_id]
        _ca_cert_filepath = self._filepath_testfile(_ca_cert_filename)

        res = self.testapp.get('/.well-known/admin/ca-certificate/upload.json', status=200)
        _data = {'chain_file': Upload(_ca_cert_filepath)
                 }
        res2 = self.testapp.post('/.well-known/admin/ca-certificate/upload.json', _data)
        assert res2.status_code == 200
        res2_json = json.loads(res2.body)
        assert res2_json['result'] == 'success'
        assert res2_json['ca_certificate']['id'] == 4
        assert res2_json['ca_certificate']['created'] is True
        res3 = self.testapp.get('/.well-known/admin/ca-certificate/4', status=200)

        # try a bundle
        res = self.testapp.get('/.well-known/admin/ca-certificate/upload-bundle', status=200)
        form = res.form
        form['isrgrootx1_file'] = Upload(self._filepath_testfile(TEST_FILES['CaCertificates']['cert']['isrgrootx1']))
        form['le_x1_auth_file'] = Upload(self._filepath_testfile(TEST_FILES['CaCertificates']['cert']['le_x1_auth']))
        form['le_x2_auth_file'] = Upload(self._filepath_testfile(TEST_FILES['CaCertificates']['cert']['le_x2_auth']))
        form['le_x1_cross_signed_file'] = Upload(self._filepath_testfile(TEST_FILES['CaCertificates']['cert']['le_x1_cross_signed']))
        form['le_x2_cross_signed_file'] = Upload(self._filepath_testfile(TEST_FILES['CaCertificates']['cert']['le_x2_cross_signed']))
        form['le_x3_cross_signed_file'] = Upload(self._filepath_testfile(TEST_FILES['CaCertificates']['cert']['le_x3_cross_signed']))
        form['le_x4_cross_signed_file'] = Upload(self._filepath_testfile(TEST_FILES['CaCertificates']['cert']['le_x4_cross_signed']))
        res2 = form.submit()
        assert res2.status_code == 302
        assert res2.location == """http://localhost/.well-known/admin/ca-certificates?uploaded=1"""
        res3 = self.testapp.get(res2.location, status=200)

        res = self.testapp.get('/.well-known/admin/ca-certificate/upload-bundle.json', status=200)
        chain_filepath = self._filepath_testfile('lets-encrypt-x1-cross-signed.pem.txt')
        form = {}
        form['isrgrootx1_file'] = Upload(self._filepath_testfile(TEST_FILES['CaCertificates']['cert']['isrgrootx1']))
        form['le_x1_auth_file'] = Upload(self._filepath_testfile(TEST_FILES['CaCertificates']['cert']['le_x1_auth']))
        form['le_x2_auth_file'] = Upload(self._filepath_testfile(TEST_FILES['CaCertificates']['cert']['le_x2_auth']))
        form['le_x1_cross_signed_file'] = Upload(self._filepath_testfile(TEST_FILES['CaCertificates']['cert']['le_x1_cross_signed']))
        form['le_x2_cross_signed_file'] = Upload(self._filepath_testfile(TEST_FILES['CaCertificates']['cert']['le_x2_cross_signed']))
        form['le_x3_cross_signed_file'] = Upload(self._filepath_testfile(TEST_FILES['CaCertificates']['cert']['le_x3_cross_signed']))
        form['le_x4_cross_signed_file'] = Upload(self._filepath_testfile(TEST_FILES['CaCertificates']['cert']['le_x4_cross_signed']))
        res2 = self.testapp.post('/.well-known/admin/ca-certificate/upload-bundle.json', form)
        assert res2.status_code == 200
        res2_json = json.loads(res2.body)
        assert res2_json['result'] == 'success'
        # this is going to be too messy to check all the vars
        # {u'isrgrootx1_pem': {u'id': 5, u'created': False}, u'le_x2_auth_pem': {u'id': 3, u'created': False}, u'le_x4_cross_signed_pem': {u'id': 6, u'created': False}, u'le_x2_cross_signed_pem': {u'id': 7, u'created': False}, u'le_x3_cross_signed_pem': {u'id': 8, u'created': False}, u'result': u'success', u'le_x1_cross_signed_pem': {u'id': 4, u'created': False}, u'le_x1_auth_pem': {u'id': 1, u'created': False}}


class FunctionalTests_Certificate(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_Certificate"""

    def _get_item(self):
        # grab a certificate
        focus_item = self.session.query(models.SslServerCertificate)\
            .filter(models.SslServerCertificate.is_active.op('IS')(True))\
            .order_by(models.SslServerCertificate.id.asc())\
            .first()
        return focus_item

    def test_list(self):
        # root
        res = self.testapp.get('/.well-known/admin/certificates', status=200)
        res = self.testapp.get('/.well-known/admin/certificates/expiring', status=200)
        # paginated
        res = self.testapp.get('/.well-known/admin/certificates/1', status=200)
        res = self.testapp.get('/.well-known/admin/certificates/expiring/1', status=200)

    def test_focus(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get('/.well-known/admin/certificate/%s' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/certificate/%s/config.json' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/certificate/%s/parse.json' % focus_id, status=200)

        res = self.testapp.get('/.well-known/admin/certificate/%s/chain.cer' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/certificate/%s/chain.crt' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/certificate/%s/chain.der' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/certificate/%s/chain.pem' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/certificate/%s/chain.pem.txt' % focus_id, status=200)

        res = self.testapp.get('/.well-known/admin/certificate/%s/fullchain.pem' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/certificate/%s/fullchain.pem.txt' % focus_id, status=200)

        res = self.testapp.get('/.well-known/admin/certificate/%s/privkey.key' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/certificate/%s/privkey.pem' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/certificate/%s/privkey.pem.txt' % focus_id, status=200)

        res = self.testapp.get('/.well-known/admin/certificate/%s/cert.crt' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/certificate/%s/cert.pem' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/certificate/%s/cert.pem.txt' % focus_id, status=200)

    def test_manipulate(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        if not focus_item.is_revoked:
            # make sure to roundtrip!
            # note we expect a 302 on success!
            if focus_item.is_active:
                res = self.testapp.get('/.well-known/admin/certificate/%s/mark' % focus_id, {'action': 'deactivated'}, status=302)
                res = self.testapp.get('/.well-known/admin/certificate/%s/mark.json' % focus_id, {'action': 'active'}, status=302)
            else:
                res = self.testapp.get('/.well-known/admin/certificate/%s/mark' % focus_id, {'action': 'active'}, status=302)
                res = self.testapp.get('/.well-known/admin/certificate/%s/mark.json' % focus_id, {'action': 'deactivated'}, status=302)
        else:
            # TODO
            print "MUST TEST revoked"

        #
        # upload a new cert
        #
        res = self.testapp.get('/.well-known/admin/certificate/upload', status=200)
        _SelfSigned_id = '1'
        form = res.form
        form['certificate_file'] = Upload(self._filepath_testfile(TEST_FILES['ServerCertificates']['SelfSigned'][_SelfSigned_id]['cert']))
        form['chain_file'] = Upload(self._filepath_testfile(TEST_FILES['ServerCertificates']['SelfSigned'][_SelfSigned_id]['cert']))
        form['private_key_file'] = Upload(self._filepath_testfile(TEST_FILES['ServerCertificates']['SelfSigned'][_SelfSigned_id]['pkey']))
        res2 = form.submit()
        assert res2.status_code == 302
        assert res2.location == """http://localhost/.well-known/admin/certificate/1"""

        res = self.testapp.get('/.well-known/admin/certificate/upload.json', status=200)
        chain_filepath = self._filepath_testfile('lets-encrypt-x1-cross-signed.pem.txt')
        _SelfSigned_id = '2'
        form = {}
        form['certificate_file'] = Upload(self._filepath_testfile(TEST_FILES['ServerCertificates']['SelfSigned'][_SelfSigned_id]['cert']))
        form['chain_file'] = Upload(self._filepath_testfile(TEST_FILES['ServerCertificates']['SelfSigned'][_SelfSigned_id]['cert']))
        form['private_key_file'] = Upload(self._filepath_testfile(TEST_FILES['ServerCertificates']['SelfSigned'][_SelfSigned_id]['pkey']))
        res2 = self.testapp.post('/.well-known/admin/certificate/upload.json', form)
        assert res2.status_code == 200
        res2_json = json.loads(res2.body)
        assert res2_json['result'] == 'success'
        assert res2_json['certificate']['id'] == 2
        assert res2_json['certificate']['created'] is True
        res3 = self.testapp.get('/.well-known/admin/certificate/2', status=200)

    @unittest.skipUnless(RUN_LETSENCRYPT_API_TESTS, "not running against letsencrypt api")
    def tests_letsencrypt_api(self):
        raise NotImplementedError()
        config.add_route_7('admin:certificate:focus:renew:quick', '/certificate/{@id}/renew/quick')
        config.add_route_7('admin:certificate:focus:renew:quick.json', '/certificate/{@id}/renew/quick.json')
        config.add_route_7('admin:certificate:focus:renew:custom', '/certificate/{@id}/renew/custom')
        config.add_route_7('admin:certificate:focus:renew:custom.json', '/certificate/{@id}/renew/custom.json')

    @unittest.skipUnless(RUN_NGINX_TESTS, "not running against nginx")
    def tests_nginx(self):
        raise NotImplementedError()
        config.add_route_7('admin:certificate:focus:nginx_cache_expire', '/certificate/{id:\d}/nginx-cache-expire')
        config.add_route_7('admin:certificate:focus:nginx_cache_expire.json', '/certificate/{id:\d}/nginx-cache-expire.json')


class FunctionalTests_CertificateRequest(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_CertificateRequest"""

    def _get_item(self):
        # grab a certificate
        focus_item = self.session.query(models.SslCertificateRequest)\
            .filter(models.SslCertificateRequest.is_active.op('IS')(True))\
            .order_by(models.SslCertificateRequest.id.asc())\
            .first()
        return focus_item

    def test_list(self):
        # root
        res = self.testapp.get('/.well-known/admin/certificate-requests', status=200)

        # paginated
        res = self.testapp.get('/.well-known/admin/certificate-requests/1', status=200)

    def test_focus(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get('/.well-known/admin/certificate-request/%s' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/certificate-request/%s/csr.csr' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/certificate-request/%s/csr.pem' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/certificate-request/%s/csr.pem.txt' % focus_id, status=200)

    @unittest.skip("these might need better APIs or migration")
    def tests_advanced(self):
        raise NotImplementedError()
        config.add_route_7('admin:certificate_request:process', '/certificate-request/{@id}/process')
        config.add_route_7('admin:certificate_request:deactivate', '/certificate-request/{@id}/deactivate')
        config.add_route_7('admin:certificate_request:process:domain', '/certificate-request/{@id}/process/domain/{domain_id:\d+}')


class FunctionalTests_Domain(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_Domain"""

    def _get_domain(self):
        # grab a certificate
        focus_item = self.session.query(models.SslDomain)\
            .filter(models.SslDomain.is_active.op('IS')(True))\
            .order_by(models.SslDomain.id.asc())\
            .first()
        return focus_item

    def test_list(self):
        # root
        res = self.testapp.get('/.well-known/admin/domains', status=200)
        res = self.testapp.get('/.well-known/admin/domains/expiring', status=200)

        # paginated
        res = self.testapp.get('/.well-known/admin/domains/1', status=200)
        res = self.testapp.get('/.well-known/admin/domains/expiring/1', status=200)

    def test_focus(self):
        focus_item = self._get_domain()
        assert focus_item is not None
        focus_id = focus_item.id
        focus_name = focus_item.domain_name

        res = self.testapp.get('/.well-known/admin/domain/%s' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/domain/%s' % focus_name, status=200)

        res = self.testapp.get('/.well-known/admin/domain/%s/config.json' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/domain/%s/calendar' % focus_id, status=200)

        res = self.testapp.get('/.well-known/admin/domain/%s/certificate-requests' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/domain/%s/certificate-requests/1' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/domain/%s/certificates' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/domain/%s/certificates/1' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/domain/%s/unique-fqdn-sets' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/domain/%s/unique-fqdn-sets/1' % focus_id, status=200)

    def test_manipulate(self):
        focus_item = self._get_domain()
        assert focus_item is not None
        focus_id = focus_item.id

        # make sure to roundtrip!
        # note we expect a 302 on success!
        if focus_item.is_active:
            res = self.testapp.get('/.well-known/admin/domain/%s/mark' % focus_id, {'action': 'inactive'}, status=302)
            res = self.testapp.get('/.well-known/admin/domain/%s/mark.json' % focus_id, {'action': 'active'}, status=302)
        else:
            res = self.testapp.get('/.well-known/admin/domain/%s/mark' % focus_id, {'action': 'active'}, status=302)
            res = self.testapp.get('/.well-known/admin/domain/%s/mark.json' % focus_id, {'action': 'inactive'}, status=302)

    @unittest.skipUnless(RUN_NGINX_TESTS, "not running against nginx")
    def tests_nginx(self):
        raise NotImplementedError()
        config.add_route_7('admin:domain:focus:nginx_cache_expire', '/domain/{domain_identifier}/nginx-cache-expire')
        config.add_route_7('admin:domain:focus:nginx_cache_expire.json', '/domain/{domain_identifier}/nginx-cache-expire.json')


class FunctionalTests_PrivateKeys(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_PrivateKeys"""

    def _get_item(self):
        # grab a Key
        focus_item = self.session.query(models.SslPrivateKey)\
            .filter(models.SslPrivateKey.is_active.op('IS')(True))\
            .order_by(models.SslPrivateKey.id.asc())\
            .first()
        return focus_item

    def test_list(self):
        # root
        res = self.testapp.get('/.well-known/admin/private-keys', status=200)
        # paginated
        res = self.testapp.get('/.well-known/admin/private-keys/1', status=200)

    def test_focus(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get('/.well-known/admin/private-key/%s' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/private-key/%s/parse.json' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/private-key/%s/key.key' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/private-key/%s/key.pem' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/private-key/%s/key.pem.txt' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/private-key/%s/certificate-requests' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/private-key/%s/certificate-requests/1' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/private-key/%s/certificates' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/private-key/%s/certificates/1' % focus_id, status=200)

    def test_manipulate(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        if not focus_item.is_compromised:
            # make sure to roundtrip!
            # note we expect a 302 on success!
            if focus_item.is_active:
                res = self.testapp.get('/.well-known/admin/private-key/%s/mark' % focus_id, {'action': 'deactivate'}, status=302)
                res = self.testapp.get('/.well-known/admin/private-key/%s/mark.json' % focus_id, {'action': 'activate'}, status=302)
            else:
                res = self.testapp.get('/.well-known/admin/private-key/%s/mark' % focus_id, {'action': 'activate'}, status=302)
                res = self.testapp.get('/.well-known/admin/private-key/%s/mark.json' % focus_id, {'action': 'deactivate'}, status=302)
        else:
            # TODO
            print "MUST TEST compromised"

    @unittest.skip("tests not written yet")
    def tests_todo(self):
        raise NotImplementedError()
        res = self.testapp.get('/.well-known/admin/private-key/1/new', status=200)


class FunctionalTests_UniqueFQDNSets(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_UniqueFQDNSets"""

    def _get_item(self):
        # grab a Key
        focus_item = self.session.query(models.SslUniqueFQDNSet)\
            .order_by(models.SslUniqueFQDNSet.id.asc())\
            .first()
        return focus_item

    def test_list(self):
        # root
        res = self.testapp.get('/.well-known/admin/unique-fqdn-sets', status=200)
        # paginated
        res = self.testapp.get('/.well-known/admin/unique-fqdn-sets/1', status=200)

    def test_focus(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get('/.well-known/admin/unique-fqdn-set/%s' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/unique-fqdn-set/%s/calendar' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/private-key/%s/certificate-requests' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/private-key/%s/certificate-requests/1' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/private-key/%s/certificates' % focus_id, status=200)
        res = self.testapp.get('/.well-known/admin/private-key/%s/certificates/1' % focus_id, status=200)


class FunctionalTests_QueueDomains(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_QueueDomains"""

    def _get_item(self):
        # grab an item
        focus_item = self.session.query(models.SslQueueDomain)\
            .order_by(models.SslQueueDomain.id.asc())\
            .first()
        return focus_item

    def test_list(self):
        # root
        res = self.testapp.get('/.well-known/admin/queue-domains', status=200)
        res = self.testapp.get('/.well-known/admin/queue-domains/all', status=200)
        # paginated
        res = self.testapp.get('/.well-known/admin/queue-domains/1', status=200)
        res = self.testapp.get('/.well-known/admin/queue-domains/all/1', status=200)

    def test_focus(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get('/.well-known/admin/queue-domain/%s' % focus_id, status=200)

    @unittest.skip("tests not written yet")
    def tests_todo(self):
        raise NotImplementedError()
        res = self.testapp.get('/.well-known/admin/queue-domains/add', status=200)
        res = self.testapp.get('/.well-known/admin/queue-domains/add.json', status=200)
        res = self.testapp.get('/.well-known/admin/queue-domains/process', status=200)
        res = self.testapp.get('/.well-known/admin/queue-domains/process.json', status=200)


class FunctionalTests_QueueRenewal(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_QueueRenewal"""

    def _get_item(self):
        # grab an item
        focus_item = self.session.query(models.SslQueueRenewal)\
            .order_by(models.SslQueueRenewal.id.asc())\
            .first()
        return focus_item

    def test_list(self):
        # root
        res = self.testapp.get('/.well-known/admin/queue-renewals', status=200)
        res = self.testapp.get('/.well-known/admin/queue-renewals/all', status=200)
        # paginated
        res = self.testapp.get('/.well-known/admin/queue-renewals/1', status=200)
        res = self.testapp.get('/.well-known/admin/queue-renewals/all/1', status=200)

    def test_focus(self):
        focus_item = self._get_item()
        assert focus_item is not None
        focus_id = focus_item.id

        res = self.testapp.get('/.well-known/admin/queue-renewal/%s' % focus_id, status=200)

    @unittest.skip("tests not written yet")
    def tests_todo(self):
        raise NotImplementedError()
        res = self.testapp.get('/.well-known/admin/queue-renewals/process', status=200)
        res = self.testapp.get('/.well-known/admin/queue-renewals/process.json', status=200)


class FunctionalTests_Operations(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_Operations"""

    def tests_passive(self):
        # this should redirect
        res = self.testapp.get('/.well-known/admin/operations', status=302)
        assert res.location == 'http://localhost/.well-known/admin/operations/log'

        res = self.testapp.get('/.well-known/admin/operations/ca-certificate-probes', status=200)
        res = self.testapp.get('/.well-known/admin/operations/ca-certificate-probes/1', status=200)
        res = self.testapp.get('/.well-known/admin/operations/log', status=200)
        res = self.testapp.get('/.well-known/admin/operations/log/1', status=200)
        res = self.testapp.get('/.well-known/admin/operations/nginx', status=200)
        res = self.testapp.get('/.well-known/admin/operations/nginx/1', status=200)
        res = self.testapp.get('/.well-known/admin/operations/redis', status=200)
        res = self.testapp.get('/.well-known/admin/operations/redis/1', status=200)

        focus_item = self.session.query(models.SslOperationsEvent)\
            .order_by(models.SslOperationsEvent.id.asc())\
            .limit(1)\
            .one()
        res = self.testapp.get('/.well-known/admin/operations/log/item/%s' % focus_item.id, status=200)

    @unittest.skip("tests not written yet")
    def tests_todo(self):
        raise NotImplementedError()
        # these are active, not passive
        config.add_route_7('admin:operations:ca_certificate_probes:probe', '/operations/ca-certificate-probes/probe')
        config.add_route_7('admin:operations:ca_certificate_probes:probe.json', '/operations/ca-certificate-probes/probe.json')
        # -
        config.add_route_7('admin:operations:deactivate_expired', '/operations/deactivate-expired')
        config.add_route_7('admin:operations:deactivate_expired.json', '/operations/deactivate-expired.json')
        config.add_route_7('admin:operations:nginx:cache_flush', '/operations/nginx/cache-flush')
        config.add_route_7('admin:operations:nginx:cache_flush.json', '/operations/nginx/cache-flush.json')
        # -
        config.add_route_7('admin:operations:redis:prime', '/operations/redis/prime')
        config.add_route_7('admin:operations:redis:prime.json', '/operations/redis/prime.json')
        # -
        config.add_route_7('admin:operations:update_recents', '/operations/update-recents')
        config.add_route_7('admin:operations:update_recents.json', '/operations/update-recents.json')
