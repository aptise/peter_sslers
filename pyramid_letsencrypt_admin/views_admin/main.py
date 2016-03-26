# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPFound
from pyramid.httpexceptions import HTTPNotFound

# stdlib
import datetime
import pdb

# pypi
import pyramid_formencode_classic as formhandling
import sqlalchemy

# localapp
from ..models import *
from ..lib.forms import (Form_CertificateRequest_new_flow,
                         # Form_CertificateRequest_new_full,
                         Form_CertificateRequest_new_full__file,
                         Form_CertificateRequest_process_domain,
                         Form_CertificateUpload__file,
                         Form_CACertificateUpload__file,
                         Form_CACertificateUploadBundle__file,
                         Form_PrivateKey_new__file,
                         Form_AccountKey_new__file,
                         )
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
        return {'project': 'pyramid_letsencrypt_admin',
                'enable_redis': self.request.registry.settings['enable_redis'],
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:search', renderer=None)
    def search(self):
        search_params = {'cert_pem_modulus_md5': self.request.params.get('cert_pem_modulus_md5', None),
                         'cert_subject': self.request.params.get('cert_subject', None),
                         'cert_subject_hash': self.request.params.get('cert_subject_hash', None),
                         'cert_issuer': self.request.params.get('cert_issuer', None),
                         'cert_issuer_hash': self.request.params.get('cert_issuer_hash', None),
                         }
        search_params = dict([i for i in search_params.items() if i[1]])
        if search_params:
            return self._search__submit(search_params)
        return self._search__print()

    def _search__print(self):
        return render_to_response("/admin/search.mako", {'ResultsPage': None, }, self.request)

    def _search__submit(self, search_params):
        certs = {}
        return render_to_response("/admin/search.mako", {'ResultsPage': True,
                                                         'certs': certs,
                                                         }, self.request)
