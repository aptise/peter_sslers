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
        items_count = lib_db.get__LetsencryptDomain__count(DBSession)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/domains/{0}')
        items_paged = lib_db.get__LetsencryptDomain__paginated(DBSession, eagerload_web=True, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'LetsencryptDomains_count': items_count,
                'LetsencryptDomains': items_paged,
                'sidenav_option': 'all',
                'pager': pager,
                }

    @view_config(route_name='admin:domains:expiring', renderer='/admin/domains.mako')
    @view_config(route_name='admin:domains:expiring_paginated', renderer='/admin/domains.mako')
    def domains_expiring_only(self):
        expiring_days = self.request.registry.settings['expiring_days']
        items_count = lib_db.get__LetsencryptDomain__count(DBSession, expiring_days=expiring_days)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/domains/expiring/{0}')
        items_paged = lib_db.get__LetsencryptDomain__paginated(DBSession, expiring_days=expiring_days, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'LetsencryptDomains_count': items_count,
                'LetsencryptDomains': items_paged,
                'sidenav_option': 'expiring',
                'expiring_days': expiring_days,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _domain_focus(self, eagerload_web=False):
        domain_identifier = self.request.matchdict['domain_identifier'].strip()
        if domain_identifier.isdigit():
            dbLetsencryptDomain = lib_db.get__LetsencryptDomain__by_id(DBSession, domain_identifier, preload=True, eagerload_web=eagerload_web)
        else:
            dbLetsencryptDomain = lib_db.get__LetsencryptDomain__by_name(DBSession, domain_identifier, preload=True, eagerload_web=eagerload_web)
        if not dbLetsencryptDomain:
            raise HTTPNotFound('the domain was not found')
        return dbLetsencryptDomain

    @view_config(route_name='admin:domain:focus', renderer='/admin/domain-focus.mako')
    def domain_focus(self):
        dbLetsencryptDomain = self._domain_focus(eagerload_web=True)
        return {'project': 'peter_sslers',
                'LetsencryptDomain': dbLetsencryptDomain
                }

    @view_config(route_name='admin:domain:focus:nginx_cache_expire', renderer=None)
    @view_config(route_name='admin:domain:focus:nginx_cache_expire:json', renderer='json')
    def domain_focus_nginx_expire(self):
        dbLetsencryptDomain = self._domain_focus(eagerload_web=True)
        if not self.request.registry.settings['enable_nginx']:
            raise HTTPFound('/.well-known/admin/domain/%s?error=no_nginx' % dbLetsencryptDomain.id)
        success, dbEvent = lib_utils.nginx_expire_cache(self.request, DBSession, dbDomains=[dbLetsencryptDomain, ])
        if self.request.matched_route.name == 'admin:domain:focus:nginx_cache_expire:json':
            return {'result': 'success',
                    'operations_event': {'id': dbEvent.id,
                                         },
                    }
        return HTTPFound('/.well-known/admin/domain/%s?operation=nginx_cache_expire&result=success&event.id=%s' % (dbLetsencryptDomain.id, dbEvent.id))

    @view_config(route_name='admin:domain:focus:config_json', renderer='json')
    def domain_focus_config_json(self):
        dbLetsencryptDomain = self._domain_focus()
        rval = {'domain': {'id': str(dbLetsencryptDomain.id),
                           'domain_name': dbLetsencryptDomain.domain_name,
                           'is_active': dbLetsencryptDomain.is_active,
                           },
                'latest_certificate_single': None,
                'latest_certificate_multi': None,
                }
        if dbLetsencryptDomain.letsencrypt_server_certificate_id__latest_single:
            if self.request.params.get('idonly', None):
                rval['latest_certificate_single'] = dbLetsencryptDomain.latest_certificate_single.config_payload_idonly
            else:
                rval['latest_certificate_single'] = dbLetsencryptDomain.latest_certificate_single.config_payload
        if dbLetsencryptDomain.letsencrypt_server_certificate_id__latest_multi:
            if self.request.params.get('idonly', None):
                rval['latest_certificate_multi'] = dbLetsencryptDomain.latest_certificate_multi.config_payload_idonly
            else:
                rval['latest_certificate_multi'] = dbLetsencryptDomain.latest_certificate_multi.config_payload
        if self.request.params.get('openresty', None):
            lib_utils.prime_redis_domain(self.request, dbLetsencryptDomain)
        return rval

    @view_config(route_name='admin:domain:focus:certificates', renderer='/admin/domain-focus-certificates.mako')
    @view_config(route_name='admin:domain:focus:certificates_paginated', renderer='/admin/domain-focus-certificates.mako')
    def domain_focus__certificates(self):
        dbLetsencryptDomain = self._domain_focus()
        items_count = lib_db.get__LetsencryptServerCertificate__by_LetsencryptDomainId__count(
            DBSession, dbLetsencryptDomain.id)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/domain/%s/certificates/{0}' % dbLetsencryptDomain.id)
        items_paged = lib_db.get__LetsencryptServerCertificate__by_LetsencryptDomainId__paginated(
            DBSession, dbLetsencryptDomain.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'LetsencryptDomain': dbLetsencryptDomain,
                'LetsencryptServerCertificates_count': items_count,
                'LetsencryptServerCertificates': items_paged,
                'pager': pager,
                }

    @view_config(route_name='admin:domain:focus:certificate_requests', renderer='/admin/domain-focus-certificate_requests.mako')
    @view_config(route_name='admin:domain:focus:certificate_requests_paginated', renderer='/admin/domain-focus-certificate_requests.mako')
    def domain_focus__certificate_requests(self):
        dbLetsencryptDomain = self._domain_focus()
        items_count = lib_db.get__LetsencryptCertificateRequest__by_LetsencryptDomainId__count(
            DBSession, LetsencryptDomain.id)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/domain/%s/certificate-requests/{0}' % LetsencryptDomain.id)
        items_paged = lib_db.get__LetsencryptCertificateRequest__by_LetsencryptDomainId__paginated(
            DBSession, dbLetsencryptDomain.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'LetsencryptDomain': dbLetsencryptDomain,
                'LetsencryptCertificateRequests_count': items_count,
                'LetsencryptCertificateRequests': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:domain:focus:calendar', renderer='json')
    def domain_focus__calendar(self):
        rval = {}
        dbLetsencryptDomain = self._domain_focus()
        weekly_certs = DBSession.query(year_week(LetsencryptServerCertificate.timestamp_signed).label('week_num'),
                                       sqlalchemy.func.count(LetsencryptServerCertificate.id)
                                       )\
            .join(LetsencryptUniqueFQDNSet2LetsencryptDomain,
                  LetsencryptServerCertificate.letsencrypt_unique_fqdn_set_id == LetsencryptUniqueFQDNSet2LetsencryptDomain.letsencrypt_unique_fqdn_set_id,
            )\
            .filter(LetsencryptUniqueFQDNSet2LetsencryptDomain.letsencrypt_domain_id == dbLetsencryptDomain.id,
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
        dbLetsencryptDomain = self._domain_focus()
        items_count = lib_db.get__LetsencryptUniqueFQDNSet__by_LetsencryptDomainId__count(
            DBSession, LetsencryptDomain.id)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/domain/%s/unique-fqdn-sets/{0}' % LetsencryptDomain.id)
        items_paged = lib_db.get__LetsencryptUniqueFQDNSet__by_LetsencryptDomainId__paginated(
            DBSession, dbLetsencryptDomain.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'LetsencryptDomain': dbLetsencryptDomain,
                'LetsencryptUniqueFQDNSets_count': items_count,
                'LetsencryptUniqueFQDNSets': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:domain:focus:mark', renderer=None)
    @view_config(route_name='admin:domain:focus:mark:json', renderer='json')
    def domain_focus_mark(self):
        dbLetsencryptDomain = self._domain_focus()
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_Domain_Mark,
                                                             validate_get=True
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results['action']
            event_type = None
            event_payload = {'domain_id': dbLetsencryptDomain.id,
                             'v': 1,
                             }
            if action == 'active':
                if dbLetsencryptDomain.is_active:
                    raise formhandling.FormInvalid('Already active')
                dbLetsencryptDomain.is_active = True
                event_type = LetsencryptOperationsEventType.domain_mark_active
            elif action == 'inactive':
                if not dbLetsencryptDomain.is_active:
                    raise formhandling.FormInvalid('Already inactive')
                dbLetsencryptDomain.is_active = False
                event_type = LetsencryptOperationsEventType.domain_mark_inactive
            else:
                raise formhandling.FormInvalid('invalid `action`')
                
            DBSession.flush()

            # bookkeeping
            operationsEvent = lib_db.create__LetsencryptOperationsEvent(
                DBSession,
                event_type,
                event_payload,
            )
            url_success = '/.well-known/admin/domain/%s?operation=mark&action=%s&result=sucess' % (
                dbLetsencryptDomain.id,
                action,
            )
            return HTTPFound(url_success)
            
        except formhandling.FormInvalid:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            url_failure = '/.well-known/admin/domain/%s?operation=mark&action=%s&result=error&error=%s' % (
                dbLetsencryptDomain.id,
                action,
                e.message,
            )
            raise HTTPFound(url_failure)
