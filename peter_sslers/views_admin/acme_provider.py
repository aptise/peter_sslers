# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPFound
from pyramid.httpexceptions import HTTPNotFound

# stdlib
import datetime

# pypi
import pyramid_formencode_classic as formhandling
import sqlalchemy

# localapp
from ..models import models
from ..lib.handler import Handler


# ==============================================================================


class ViewAdmin(Handler):

    @view_config(route_name='admin:acme_providers', renderer='/admin/acme_providers.mako')
    @view_config(route_name='admin:acme_providers|json', renderer='json')
    def acme_providers(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        acmeProviders = {provider_name: {'id': provider_id,
                                         'name': provider_name,
                                         }
                         for (provider_id, provider_name)
                         in models.AcmeAccountProvider._mapping.items()
                         }
        for (provider_name, provider_endpoint) in models.AcmeAccountEndpoint._mapping.items():
            acmeProviders[provider_name]['endpoint'] = provider_endpoint
        if wants_json:
            return {'AcmeProviders': acmeProviders, }
        return {'project': 'peter_sslers',
                'AcmeProviders': acmeProviders,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
