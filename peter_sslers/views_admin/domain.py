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
from ..lib.forms import (Form_Domain_mark,
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
            dbDomain = lib_db.get__SslDomain__by_id(self.request.api_context, domain_identifier, preload=True, eagerload_web=eagerload_web)
        else:
            dbDomain = lib_db.get__SslDomain__by_name(self.request.api_context, domain_identifier, preload=True, eagerload_web=eagerload_web)
        if not dbDomain:
            raise HTTPNotFound('the domain was not found')
        return dbDomain

    @view_config(route_name='admin:domain:focus', renderer='/admin/domain-focus.mako')
    def domain_focus(self):
        dbDomain = self._domain_focus(eagerload_web=True)
        return {'project': 'peter_sslers',
                'SslDomain': dbDomain
                }

    @view_config(route_name='admin:domain:focus:nginx_cache_expire', renderer=None)
    @view_config(route_name='admin:domain:focus:nginx_cache_expire.json', renderer='json')
    def domain_focus_nginx_expire(self):
        dbDomain = self._domain_focus(eagerload_web=True)
        if not self.request.registry.settings['enable_nginx']:
            raise HTTPFound('%s/domain/%s?error=no_nginx' % (self.request.registry.settings['admin_prefix'], dbDomain.id))
        success, dbEvent = lib_utils.nginx_expire_cache(self.request, self.request.api_context, dbDomains=[dbDomain, ])
        if self.request.matched_route.name == 'admin:domain:focus:nginx_cache_expire.json':
            return {'result': 'success',
                    'operations_event': {'id': dbEvent.id,
                                         },
                    }
        return HTTPFound('%s/domain/%s?operation=nginx_cache_expire&result=success&event.id=%s' % (self.request.registry.settings['admin_prefix'], dbDomain.id, dbEvent.id))

    @view_config(route_name='admin:domain:focus:config_json', renderer='json')
    def domain_focus_config_json(self):
        dbDomain = self._domain_focus()
        rval = {'domain': {'id': str(dbDomain.id),
                           'domain_name': dbDomain.domain_name,
                           'is_active': dbDomain.is_active,
                           },
                'server_certificate__latest_single': None,
                'server_certificate__latest_multi': None,
                }
        if dbDomain.ssl_server_certificate_id__latest_single:
            if self.request.params.get('idonly', None):
                rval['server_certificate__latest_single'] = dbDomain.server_certificate__latest_single.config_payload_idonly
            else:
                rval['server_certificate__latest_single'] = dbDomain.server_certificate__latest_single.config_payload
        if dbDomain.ssl_server_certificate_id__latest_multi:
            if self.request.params.get('idonly', None):
                rval['server_certificate__latest_multi'] = dbDomain.server_certificate__latest_multi.config_payload_idonly
            else:
                rval['server_certificate__latest_multi'] = dbDomain.server_certificate__latest_multi.config_payload
        if self.request.params.get('openresty', None):
            lib_utils.prime_redis_domain(self.request, dbDomain)
        return rval

    @view_config(route_name='admin:domain:focus:certificates', renderer='/admin/domain-focus-certificates.mako')
    @view_config(route_name='admin:domain:focus:certificates_paginated', renderer='/admin/domain-focus-certificates.mako')
    def domain_focus__certificates(self):
        dbDomain = self._domain_focus()
        items_count = lib_db.get__SslServerCertificate__by_SslDomainId__count(
            self.request.api_context, dbDomain.id)
        (pager, offset) = self._paginate(items_count, url_template='%s/domain/%s/certificates/{0}' % (self.request.registry.settings['admin_prefix'], dbDomain.id))
        items_paged = lib_db.get__SslServerCertificate__by_SslDomainId__paginated(
            self.request.api_context, dbDomain.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslDomain': dbDomain,
                'SslServerCertificates_count': items_count,
                'SslServerCertificates': items_paged,
                'pager': pager,
                }

    @view_config(route_name='admin:domain:focus:certificate_requests', renderer='/admin/domain-focus-certificate_requests.mako')
    @view_config(route_name='admin:domain:focus:certificate_requests_paginated', renderer='/admin/domain-focus-certificate_requests.mako')
    def domain_focus__certificate_requests(self):
        dbDomain = self._domain_focus()
        items_count = lib_db.get__SslCertificateRequest__by_SslDomainId__count(
            self.request.api_context, SslDomain.id)
        (pager, offset) = self._paginate(items_count, url_template='%s/domain/%s/certificate-requests/{0}' % (self.request.registry.settings['admin_prefix'], SslDomain.id))
        items_paged = lib_db.get__SslCertificateRequest__by_SslDomainId__paginated(
            self.request.api_context, dbDomain.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslDomain': dbDomain,
                'SslCertificateRequests_count': items_count,
                'SslCertificateRequests': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:domain:focus:calendar', renderer='json')
    def domain_focus__calendar(self):
        rval = {}
        dbDomain = self._domain_focus()
        weekly_certs = self.request.api_context.dbSession.query(year_week(SslServerCertificate.timestamp_signed).label('week_num'),
                                                                sqlalchemy.func.count(SslServerCertificate.id)
                                                                )\
            .join(SslUniqueFQDNSet2SslDomain,
                  SslServerCertificate.ssl_unique_fqdn_set_id == SslUniqueFQDNSet2SslDomain.ssl_unique_fqdn_set_id,
                  )\
            .filter(SslUniqueFQDNSet2SslDomain.ssl_domain_id == dbDomain.id,
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
        dbDomain = self._domain_focus()
        items_count = lib_db.get__SslUniqueFQDNSet__by_SslDomainId__count(
            self.request.api_context, SslDomain.id)
        (pager, offset) = self._paginate(items_count, url_template='%s/domain/%s/unique-fqdn-sets/{0}' % (self.request.registry.settings['admin_prefix'], SslDomain.id))
        items_paged = lib_db.get__SslUniqueFQDNSet__by_SslDomainId__paginated(
            self.request.api_context, dbDomain.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslDomain': dbDomain,
                'SslUniqueFQDNSets_count': items_count,
                'SslUniqueFQDNSets': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:domain:focus:mark', renderer=None)
    @view_config(route_name='admin:domain:focus:mark.json', renderer='json')
    def domain_focus_mark(self):
        dbDomain = self._domain_focus()
        action = '!MISSING or !INVALID'
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_Domain_mark,
                                                             validate_get=True
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results['action']
            event_type = SslOperationsEventType.from_string('domain__mark')
            event_payload_dict = lib_utils.new_event_payload_dict()
            event_payload_dict['domain_id'] = dbDomain.id
            event_payload_dict['action'] = action
            event_status = False

            if action == 'active':
                if dbDomain.is_active:
                    raise formhandling.FormInvalid('Already active')
                dbDomain.is_active = True
                event_status = 'domain__mark__active'

            elif action == 'inactive':
                if not dbDomain.is_active:
                    raise formhandling.FormInvalid('Already inactive')
                dbDomain.is_active = False
                event_status = 'domain__mark__inactive'

            else:
                raise formhandling.FormInvalid('invalid `action`')

            self.request.api_context.dbSession.flush()

            # bookkeeping
            dbOperationsEvent = lib_db.log__SslOperationsEvent(
                self.request.api_context,
                event_type,
                event_payload_dict,
            )
            lib_db._log_object_event(self.request.api_context,
                                     dbOperationsEvent=dbOperationsEvent,
                                     event_status_id=SslOperationsObjectEventStatus.from_string(event_status),
                                     dbDomain=dbDomain,
                                     )

            url_success = '%s/domain/%s?operation=mark&action=%s&result=sucess' % (
                self.request.registry.settings['admin_prefix'],
                dbDomain.id,
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
                dbDomain.id,
                action,
                e.message,
            )
            raise HTTPFound(url_failure)
