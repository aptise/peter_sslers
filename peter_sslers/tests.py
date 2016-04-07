# pyramid
from pyramid import testing
from pyramid.paster import get_appsettings

# pypi
import transaction
from webtest import TestApp

# stdlib
import json
import pdb
import unittest

# local
from . import main
from . import models 
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


class AppTest(unittest.TestCase):
    _session = None

    def setUp(self):
        settings = get_appsettings('development.ini', name='main')
        app = main(global_config = None, **settings)
        self.testapp = TestApp(app)

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

    def _get_item(self):
        # grab a Key
        focus_item = self.session.query(models.LetsencryptAccountKey)\
            .filter(models.LetsencryptAccountKey.is_active.op('IS')(True))\
            .order_by(models.LetsencryptAccountKey.id.asc())\
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
        #res = self.testapp.get('/.well-known/admin/account-key/1/config.json', status=200)
        #key_data = json.loads(res.text)
        #if not key_data['is_default']:
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

    def tests_todo(self):
        # TODO
        return
        # this hits LE
        res = self.testapp.get('/.well-known/admin/account-key/1/authenticate', status=200)

        # test new?
        res = self.testapp.get('/.well-known/admin/account-key/1/new', status=200)


class FunctionalTests_API(AppTest):

    def test_simple(self):
        # root
        res = self.testapp.get('/.well-known/admin/api', status=200)
        res = self.testapp.get('/.well-known/admin/api/domain/enable', status=200)
        res = self.testapp.get('/.well-known/admin/api/domain/disable', status=200)


class FunctionalTests_CACertificate(AppTest):

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

    def tests_todo(self):
        # TODO
        return

        res = self.testapp.get('/.well-known/admin/ca-certificate/upload', status=200)
        res = self.testapp.get('/.well-known/admin/ca-certificate/upload.json', status=200)
        res = self.testapp.get('/.well-known/admin/ca-certificate/upload-bundle', status=200)
        res = self.testapp.get('/.well-known/admin/ca-certificate/upload-bundle.json', status=200)


class FunctionalTests_Certificate(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_Certificate"""

    def _get_item(self):
        # grab a certificate
        focus_item = self.session.query(models.LetsencryptServerCertificate)\
            .filter(models.LetsencryptServerCertificate.is_active.op('IS')(True))\
            .order_by(models.LetsencryptServerCertificate.id.asc())\
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
        print "test_manipulate"
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

    def tests_todo(self):
        # TODO
        return
        config.add_route_7('admin:certificate:focus:nginx_cache_expire', '/certificate/{id:\d}/nginx-cache-expire')
        config.add_route_7('admin:certificate:focus:nginx_cache_expire.json', '/certificate/{id:\d}/nginx-cache-expire.json')
        config.add_route_7('admin:certificate:focus:renew:quick', '/certificate/{@id}/renew/quick')
        config.add_route_7('admin:certificate:focus:renew:quick.json', '/certificate/{@id}/renew/quick.json')
        config.add_route_7('admin:certificate:focus:renew:custom', '/certificate/{@id}/renew/custom')
        config.add_route_7('admin:certificate:focus:renew:custom.json', '/certificate/{@id}/renew/custom.json')
        config.add_route_7('admin:certificate:upload', '/certificate/upload')
        config.add_route_7('admin:certificate:upload.json', '/certificate/upload.json')


class FunctionalTests_CertificateRequest(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_CertificateRequest"""

    def _get_item(self):
        # grab a certificate
        focus_item = self.session.query(models.LetsencryptCertificateRequest)\
            .filter(models.LetsencryptCertificateRequest.is_active.op('IS')(True))\
            .order_by(models.LetsencryptCertificateRequest.id.asc())\
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

    def tests_todo(self):
        # TODO
        return
        config.add_route_7('admin:certificate_request:process', '/certificate-request/{@id}/process')
        config.add_route_7('admin:certificate_request:deactivate', '/certificate-request/{@id}/deactivate')
        config.add_route_7('admin:certificate_request:process:domain', '/certificate-request/{@id}/process/domain/{domain_id:\d+}')


class FunctionalTests_Domain(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_Domain"""

    def _get_domain(self):
        # grab a certificate
        focus_item = self.session.query(models.LetsencryptDomain)\
            .filter(models.LetsencryptDomain.is_active.op('IS')(True))\
            .order_by(models.LetsencryptDomain.id.asc())\
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

            
    def tests_todo(self):
        # TODO
        return
        config.add_route_7('admin:domain:focus:nginx_cache_expire', '/domain/{domain_identifier}/nginx-cache-expire')
        config.add_route_7('admin:domain:focus:nginx_cache_expire.json', '/domain/{domain_identifier}/nginx-cache-expire.json')


class FunctionalTests_PrivateKeys(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_PrivateKeys"""

    def _get_item(self):
        # grab a Key
        focus_item = self.session.query(models.LetsencryptPrivateKey)\
            .filter(models.LetsencryptPrivateKey.is_active.op('IS')(True))\
            .order_by(models.LetsencryptPrivateKey.id.asc())\
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

    def tests_todo(self):
        # TODO
        return
        # test new?
        res = self.testapp.get('/.well-known/admin/private-key/1/new', status=200)
        
        
        
class FunctionalTests_UniqueFQDNSets(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_UniqueFQDNSets"""

    def _get_item(self):
        # grab a Key
        focus_item = self.session.query(models.LetsencryptUniqueFQDNSet)\
            .order_by(models.LetsencryptUniqueFQDNSet.id.asc())\
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
        focus_item = self.session.query(models.LetsencryptQueueDomain)\
            .order_by(models.LetsencryptQueueDomain.id.asc())\
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

    def tests_todo(self):
        # TODO
        return
        # test new?
        res = self.testapp.get('/.well-known/admin/queue-domains/add', status=200)
        res = self.testapp.get('/.well-known/admin/queue-domains/add.json', status=200)
        res = self.testapp.get('/.well-known/admin/queue-domains/process', status=200)
        res = self.testapp.get('/.well-known/admin/queue-domains/process.json', status=200)


class FunctionalTests_QueueRenewal(AppTest):
    """python -m unittest peter_sslers.tests.FunctionalTests_QueueRenewal"""

    def _get_item(self):
        # grab an item
        focus_item = self.session.query(models.LetsencryptQueueRenewal)\
            .order_by(models.LetsencryptQueueRenewal.id.asc())\
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

    def tests_todo(self):
        # TODO
        return
        # test new?
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

        focus_item = self.session.query(models.LetsencryptOperationsEvent)\
            .order_by(models.LetsencryptOperationsEvent.id.asc())\
            .one()
        res = self.testapp.get('/.well-known/admin/operations/log/item/%s' % focus_item.id, status=200)

    def tests_todo(self):
        # these are active, not passive
        return
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