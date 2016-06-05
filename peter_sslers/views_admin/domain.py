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
from ..lib.forms import (Form_Domain_Mark,
                         )
from ..lib import acme as lib_acme
from ..lib import db as lib_db
from ..lib.handler import Handler, items_per_page
from ..lib import utils as lib_utils


# ==============================================================================


class ViewAdmin(Handler):

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:domains', renderer='/admin/domains.mako')
    @view_config(route_name='admin:domains_paginated', renderer='/admin/domains.mako')
    def domains(self):
        items_count = lib_db.get__SslDomain__count(self.request.api_context)
        (pager, offset) = self._paginate(items_count, url_template='%s/domains/{0}' % self.request.registry.settings['admin_prefix'])
        items_paged = lib_db.get__SslDomain__paginated(self.request.api_context, eagerload_web=True, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslDomains_count': items_count,
                'SslDomains': items_paged,
                'sidenav_option': 'all',
                'pager': pager,
                }

    @view_config(route_name='admin:domains:expiring', renderer='/admin/domains.mako')
    @view_config(route_name='admin:domains:expiring_paginated', renderer='/admin/domains.mako')
    def domains_expiring_only(self):
        expiring_days = self.request.registry.settings['expiring_days']
        items_count = lib_db.get__SslDomain__count(self.request.api_context, expiring_days=expiring_days)
        (pager, offset) = self._paginate(items_count, url_template='%s/domains/expiring/{0}' % self.request.registry.settings['admin_prefix'])
        items_paged = lib_db.get__SslDomain__paginated(self.request.api_context, expiring_days=expiring_days, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslDomains_count': items_count,
                'SslDomains': items_paged,
                'sidenav_option': 'expiring',
                'expiring_days': expiring_days,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _domain_focus(self, eagerload_web=False):
        domain_identifier = self.request.matchdict['domain_identifier'].strip()
        if domain_identifier.isdigit():
            dbSslDomain = lib_db.get__SslDomain__by_id(self.request.api_context, domain_identifier, preload=True, eagerload_web=eagerload_web)
        else:
            dbSslDomain = lib_db.get__SslDomain__by_name(self.request.api_context, domain_identifier, preload=True, eagerload_web=eagerload_web)
        if not dbSslDomain:
            raise HTTPNotFound('the domain was not found')
        return dbSslDomain

    @view_config(route_name='admin:domain:focus', renderer='/admin/domain-focus.mako')
    def domain_focus(self):
        dbSslDomain = self._domain_focus(eagerload_web=True)
        return {'project': 'peter_sslers',
                'SslDomain': dbSslDomain
                }

    @view_config(route_name='admin:domain:focus:nginx_cache_expire', renderer=None)
    @view_config(route_name='admin:domain:focus:nginx_cache_expire.json', renderer='json')
    def domain_focus_nginx_expire(self):
        dbSslDomain = self._domain_focus(eagerload_web=True)
        if not self.request.registry.settings['enable_nginx']:
            raise HTTPFound('%s/domain/%s?error=no_nginx' % (self.request.registry.settings['admin_prefix'], dbSslDomain.id))
        success, dbEvent = lib_utils.nginx_expire_cache(self.request, self.request.api_context, dbDomains=[dbSslDomain, ])
        if self.request.matched_route.name == 'admin:domain:focus:nginx_cache_expire.json':
            return {'result': 'success',
                    'operations_event': {'id': dbEvent.id,
                                         },
                    }
        return HTTPFound('%s/domain/%s?operation=nginx_cache_expire&result=success&event.id=%s' % (self.request.registry.settings['admin_prefix'], dbSslDomain.id, dbEvent.id))

    @view_config(route_name='admin:domain:focus:config_json', renderer='json')
    def domain_focus_config_json(self):
        dbSslDomain = self._domain_focus()
        rval = {'domain': {'id': str(dbSslDomain.id),
                           'domain_name': dbSslDomain.domain_name,
                           'is_active': dbSslDomain.is_active,
                           },
                'latest_certificate_single': None,
                'latest_certificate_multi': None,
                }
        if dbSslDomain.ssl_server_certificate_id__latest_single:
            if self.request.params.get('idonly', None):
                rval['latest_certificate_single'] = dbSslDomain.latest_certificate_single.config_payload_idonly
            else:
                rval['latest_certificate_single'] = dbSslDomain.latest_certificate_single.config_payload
        if dbSslDomain.ssl_server_certificate_id__latest_multi:
            if self.request.params.get('idonly', None):
                rval['latest_certificate_multi'] = dbSslDomain.latest_certificate_multi.config_payload_idonly
            else:
                rval['latest_certificate_multi'] = dbSslDomain.latest_certificate_multi.config_payload
        if self.request.params.get('openresty', None):
            lib_utils.prime_redis_domain(self.request, dbSslDomain)
        return rval

    @view_config(route_name='admin:domain:focus:certificates', renderer='/admin/domain-focus-certificates.mako')
    @view_config(route_name='admin:domain:focus:certificates_paginated', renderer='/admin/domain-focus-certificates.mako')
    def domain_focus__certificates(self):
        dbSslDomain = self._domain_focus()
        items_count = lib_db.get__SslServerCertificate__by_SslDomainId__count(
            self.request.api_context, dbSslDomain.id)
        (pager, offset) = self._paginate(items_count, url_template='%s/domain/%s/certificates/{0}' % (self.request.registry.settings['admin_prefix'], dbSslDomain.id))
        items_paged = lib_db.get__SslServerCertificate__by_SslDomainId__paginated(
            self.request.api_context, dbSslDomain.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslDomain': dbSslDomain,
                'SslServerCertificates_count': items_count,
                'SslServerCertificates': items_paged,
                'pager': pager,
                }

    @view_config(route_name='admin:domain:focus:certificate_requests', renderer='/admin/domain-focus-certificate_requests.mako')
    @view_config(route_name='admin:domain:focus:certificate_requests_paginated', renderer='/admin/domain-focus-certificate_requests.mako')
    def domain_focus__certificate_requests(self):
        dbSslDomain = self._domain_focus()
        items_count = lib_db.get__SslCertificateRequest__by_SslDomainId__count(
            self.request.api_context, SslDomain.id)
        (pager, offset) = self._paginate(items_count, url_template='%s/domain/%s/certificate-requests/{0}' % (self.request.registry.settings['admin_prefix'], SslDomain.id))
        items_paged = lib_db.get__SslCertificateRequest__by_SslDomainId__paginated(
            self.request.api_context, dbSslDomain.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslDomain': dbSslDomain,
                'SslCertificateRequests_count': items_count,
                'SslCertificateRequests': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:domain:focus:calendar', renderer='json')
    def domain_focus__calendar(self):
        rval = {}
        dbSslDomain = self._domain_focus()
        weekly_certs = self.request.api_context.dbSession.query(year_week(SslServerCertificate.timestamp_signed).label('week_num'),
                                                                sqlalchemy.func.count(SslServerCertificate.id)
                                                                )\
            .join(SslUniqueFQDNSet2SslDomain,
                  SslServerCertificate.ssl_unique_fqdn_set_id == SslUniqueFQDNSet2SslDomain.ssl_unique_fqdn_set_id,
                  )\
            .filter(SslUniqueFQDNSet2SslDomain.ssl_domain_id == dbSslDomain.id,
                    )\
            .group_by('week_num')\
            .order_by(sqlalchemy.asc('week_num'))\
            .all()
        rval['issues'] = {}
        for wc in weekly_certs:
            rval['issues'][str(wc[0])] = wc[1]
        return rval

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:domain:focus:unique_fqdn_sets', renderer='/admin/domain-focus-unique_fqdn_sets.mako')
    @view_config(route_name='admin:domain:focus:unique_fqdn_sets_paginated', renderer='/admin/domain-focus-unique_fqdn_sets.mako')
    def domain_focus__unique_fqdns(self):
        dbSslDomain = self._domain_focus()
        items_count = lib_db.get__SslUniqueFQDNSet__by_SslDomainId__count(
            self.request.api_context, SslDomain.id)
        (pager, offset) = self._paginate(items_count, url_template='%s/domain/%s/unique-fqdn-sets/{0}' % (self.request.registry.settings['admin_prefix'], SslDomain.id))
        items_paged = lib_db.get__SslUniqueFQDNSet__by_SslDomainId__paginated(
            self.request.api_context, dbSslDomain.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslDomain': dbSslDomain,
                'SslUniqueFQDNSets_count': items_count,
                'SslUniqueFQDNSets': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:domain:focus:mark', renderer=None)
    @view_config(route_name='admin:domain:focus:mark.json', renderer='json')
    def domain_focus_mark(self):
        dbSslDomain = self._domain_focus()
        action = '!MISSING or !INVALID'
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_Domain_Mark,
                                                             validate_get=True
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results['action']
            event_type = SslOperationsEventType.from_string('domain__mark')
            event_payload = {'domain_id': dbSslDomain.id,
                             'action': action,
                             'v': 1,
                             }
            if action == 'active':
                if dbSslDomain.is_active:
                    raise formhandling.FormInvalid('Already active')
                dbSslDomain.is_active = True
            elif action == 'inactive':
                if not dbSslDomain.is_active:
                    raise formhandling.FormInvalid('Already inactive')
                dbSslDomain.is_active = False
            else:
                raise formhandling.FormInvalid('invalid `action`')

            self.request.api_context.dbSession.flush()

            # bookkeeping
            operationsEvent = lib_db.log__SslOperationsEvent(
                self.request.api_context,
                event_type,
                event_payload,
            )
            url_success = '%s/domain/%s?operation=mark&action=%s&result=sucess' % (
                self.request.registry.settings['admin_prefix'],
                dbSslDomain.id,
                action,
            )
            return HTTPFound(url_success)

        except formhandling.FormInvalid, e:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            url_failure = '%s/domain/%s?operation=mark&action=%s&result=error&error=%s' % (
                self.request.registry.settings['admin_prefix'],
                dbSslDomain.id,
                action,
                e.message,
            )
            raise HTTPFound(url_failure)
