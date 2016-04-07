# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPFound
from pyramid.httpexceptions import HTTPNotFound

# stdlib
import datetime
import pdb
try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode

# pypi
import pyramid_formencode_classic as formhandling
import sqlalchemy

# localapp
from ..models import *
from ..lib import acme as lib_acme
from ..lib import db as lib_db
from ..lib.handler import Handler, items_per_page


# ==============================================================================


class ViewAdminMain(Handler):

    @view_config(route_name="admin_whoami", renderer="string")
    def public_whoami(self):
        """this is really only useful for testing"""
        return self.request.active_domain_name

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin', renderer='/admin/index.mako')
    def index(self):
        return {'project': 'peter_sslers',
                'enable_redis': self.request.registry.settings['enable_redis'],
                'enable_nginx': self.request.registry.settings['enable_nginx'],
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:help', renderer='/admin/help.mako')
    def help(self):
        return {'project': 'peter_sslers',
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:search', renderer=None)
    def search(self):
        search_type = self.request.params.get('type')
        search_type_valid = True if search_type in ('modulus',
                                                    'cert_subject_hash',
                                                    'cert_issuer_hash',
                                                    ) else False
        if search_type_valid:
            return self._search__submit(search_type)
        return self._search__print()

    def _search__print(self):
        return render_to_response("/admin/search.mako", {'search_type': None,
                                                         'ResultsPage': None,
                                                         'results': None,
                                                         }, self.request)

    def _search__submit(self, search_type):
        results = {'LetsencryptAccountKey': {'count': 0, 'items': [], 'next': False, },
                   'LetsencryptDomain': {'count': 0, 'items': [], 'next': False, },
                   'LetsencryptCACertificate': {'count': 0, 'items': [], 'next': False, },
                   'LetsencryptCertificateRequest': {'count': 0, 'items': [], 'next': False, },
                   'LetsencryptPrivateKey': {'count': 0, 'items': [], 'next': False, },
                   'LetsencryptServerCertificate': {'count': 0, 'items': [], 'next': False, },
                   }

        # lightweight pagination
        item_limit = 25
        offset = int(self.request.params.get('offset', 0))

        # show only X items
        show_only = dict([(k, True) for k in results.keys()])
        _show_only = self.request.params.get('show_only', None)
        if _show_only and _show_only in results:
            show_only = dict([(k, False) for k in results.keys()])
            show_only[_show_only] = True

        source_type = self.request.params.get('source', None)
        source_id = int(self.request.params.get('%s.id' % source_type), 0)

        q_query_args = {'type': search_type,
                        'offset': offset + item_limit,
                        'source': source_type,
                        '%s.id' % source_type: source_id,
                        }

        if search_type == 'modulus':
            search_modulus = self.request.params.get('modulus', None)
            q_query_args['modulus'] = search_modulus

            if not all((search_modulus, source_type, source_id)):
                raise ValueError("invalid search")

            # LetsencryptAccountKey
            if show_only['LetsencryptAccountKey']:
                _base = self.request.dbsession.query(LetsencryptAccountKey)\
                    .filter(LetsencryptAccountKey.key_pem_modulus_md5 == search_modulus)
                results['LetsencryptAccountKey']['count'] = _base.count()
                if results['LetsencryptAccountKey']['count']:
                    results['LetsencryptAccountKey']['items'] = _base.limit(item_limit).offset(offset).all()

            # LetsencryptCACertificate
            if show_only['LetsencryptCACertificate']:
                _base = self.request.dbsession.query(LetsencryptCACertificate)\
                    .filter(LetsencryptCACertificate.cert_pem_modulus_md5 == search_modulus)
                results['LetsencryptCACertificate']['count'] = _base.count()
                if results['LetsencryptCACertificate']['count']:
                    results['LetsencryptCACertificate']['items'] = _base.limit(item_limit).offset(offset).all()

            # LetsencryptCertificateRequest
            if show_only['LetsencryptCertificateRequest']:
                _base = self.request.dbsession.query(LetsencryptCertificateRequest)\
                    .filter(LetsencryptCertificateRequest.csr_pem_modulus_md5 == search_modulus)
                results['LetsencryptCertificateRequest']['count'] = _base.count()
                if results['LetsencryptCertificateRequest']['count']:
                    results['LetsencryptCertificateRequest']['items'] = _base.limit(item_limit).offset(offset).all()

            # LetsencryptPrivateKey
            if show_only['LetsencryptPrivateKey']:
                _base = self.request.dbsession.query(LetsencryptPrivateKey)\
                    .filter(LetsencryptPrivateKey.key_pem_modulus_md5 == search_modulus)
                results['LetsencryptPrivateKey']['count'] = _base.count()
                if results['LetsencryptPrivateKey']['count']:
                    results['LetsencryptPrivateKey']['items'] = _base.limit(item_limit).offset(offset).all()

            # LetsencryptServerCertificate
            if show_only['LetsencryptServerCertificate']:
                _base = self.request.dbsession.query(LetsencryptServerCertificate)\
                    .filter(LetsencryptServerCertificate.cert_pem_modulus_md5 == search_modulus)
                results['LetsencryptServerCertificate']['count'] = _base.count()
                if results['LetsencryptServerCertificate']['count']:
                    results['LetsencryptServerCertificate']['items'] = _base.limit(item_limit).offset(offset).all()

        elif search_type in ('cert_subject_hash', 'cert_issuer_hash'):
            cert_subject_hash = self.request.params.get('cert_subject_hash', None)
            cert_issuer_hash = self.request.params.get('cert_issuer_hash', None)

            if not any((source_type, source_id)):
                raise ValueError("invalid search")

            if not any((cert_subject_hash, cert_issuer_hash)) or all((cert_subject_hash, cert_issuer_hash)):
                raise ValueError("invalid search")

            if cert_subject_hash:
                q_query_args['cert_subject_hash'] = cert_subject_hash
            if cert_issuer_hash:
                q_query_args['cert_issuer_hash'] = cert_issuer_hash

            search_hash = cert_subject_hash or cert_issuer_hash

            # LetsencryptCACertificate
            if show_only['LetsencryptCACertificate']:
                _base = self.request.dbsession.query(LetsencryptCACertificate)\
                    .filter(sqlalchemy.or_(LetsencryptCACertificate.cert_subject_hash == search_hash,
                                           LetsencryptCACertificate.cert_issuer_hash == search_hash,
                                           )
                            )
                results['LetsencryptCACertificate']['count'] = _base.count()
                if results['LetsencryptCACertificate']['count']:
                    results['LetsencryptCACertificate']['items'] = _base.limit(item_limit).offset(offset).all()

            # LetsencryptServerCertificate
            if show_only['LetsencryptServerCertificate']:
                _base = self.request.dbsession.query(LetsencryptServerCertificate)\
                    .filter(sqlalchemy.or_(LetsencryptServerCertificate.cert_subject_hash == search_hash,
                                           LetsencryptServerCertificate.cert_issuer_hash == search_hash,
                                           )
                            )
                results['LetsencryptServerCertificate']['count'] = _base.count()
                if results['LetsencryptServerCertificate']['count']:
                    results['LetsencryptServerCertificate']['items'] = _base.limit(item_limit).offset(offset).all()

        query_args = urlencode(q_query_args)
        for k in results.keys():
            if results[k]['count'] and results[k]['items']:
                if (len(results[k]['items']) + offset) < results[k]['count']:
                    results[k]['next'] = '%s/search?show_only=%s&%s' % (self.request.registry.settings['admin_prefix'], k, query_args)

        return render_to_response("/admin/search.mako", {'search_type': search_type,
                                                         'ResultsPage': True,
                                                         'results': results,
                                                         'item_limit': item_limit,
                                                         'query_args': query_args,
                                                         'show_only': show_only,
                                                         }, self.request)
