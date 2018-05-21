# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther

# stdlib
import datetime

# pypi
import pyramid_formencode_classic as formhandling
import sqlalchemy

# localapp
from ..models import models
from .. import lib
from ..lib import db as lib_db
from ..lib.forms import Form_Domain_mark
from ..lib.handler import Handler, items_per_page


# ==============================================================================


class ViewAdmin(Handler):

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:domains', renderer='/admin/domains.mako')
    @view_config(route_name='admin:domains_paginated', renderer='/admin/domains.mako')
    @view_config(route_name='admin:domains:expiring', renderer='/admin/domains.mako')
    @view_config(route_name='admin:domains:expiring_paginated', renderer='/admin/domains.mako')
    @view_config(route_name='admin:domains|json', renderer='json')
    @view_config(route_name='admin:domains_paginated|json', renderer='json')
    @view_config(route_name='admin:domains:expiring|json', renderer='json')
    @view_config(route_name='admin:domains:expiring_paginated|json', renderer='json')
    def domains(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        expiring_days = self.request.registry.settings['expiring_days']
        if self.request.matched_route.name in ('admin:domains:expiring',
                                               'admin:domains:expiring_paginated',
                                               'admin:domains:expiring|json',
                                               'admin:domains:expiring_paginated|json',
                                               ):
            sidenav_option = 'expiring'
            if wants_json:
                url_template = '%s/domains/expiring/{0}.json' % self.request.registry.settings['admin_prefix']
            else:
                url_template = '%s/domains/expiring/{0}' % self.request.registry.settings['admin_prefix']
            items_count = lib_db.get.get__SslDomain__count(self.request.api_context, expiring_days=expiring_days)
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__SslDomain__paginated(self.request.api_context, expiring_days=expiring_days, limit=items_per_page, offset=offset)
        else:
            sidenav_option = 'all'
            if wants_json:
                url_template = '%s/domains/{0}.json' % self.request.registry.settings['admin_prefix']
            else:
                url_template = '%s/domains/{0}' % self.request.registry.settings['admin_prefix']
            items_count = lib_db.get.get__SslDomain__count(self.request.api_context)
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__SslDomain__paginated(self.request.api_context, eagerload_web=True, limit=items_per_page, offset=offset)
        if wants_json:
            _domains = {d.id: d.as_json for d in items_paged}
            return {'SslDomains': _domains,
                    'pagination': {'total_items': items_count,
                                   'page': pager.page_num,
                                   'page_next': pager.next if pager.has_next else None,
                                   }
                    }
        return {'project': 'peter_sslers',
                'SslDomains_count': items_count,
                'SslDomains': items_paged,
                'sidenav_option': sidenav_option,
                'expiring_days': expiring_days,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _domain_focus(self, eagerload_web=False):
        domain_identifier = self.request.matchdict['domain_identifier'].strip()
        if domain_identifier.isdigit():
            dbDomain = lib_db.get.get__SslDomain__by_id(self.request.api_context, domain_identifier, preload=True, eagerload_web=eagerload_web)
        else:
            dbDomain = lib_db.get.get__SslDomain__by_name(self.request.api_context, domain_identifier, preload=True, eagerload_web=eagerload_web)
        if not dbDomain:
            raise HTTPNotFound('the domain was not found')
        return dbDomain

    @view_config(route_name='admin:domain:focus', renderer='/admin/domain-focus.mako')
    @view_config(route_name='admin:domain:focus|json', renderer='json')
    def domain_focus(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        dbDomain = self._domain_focus(eagerload_web=True)
        if wants_json:
            return {'SslDomain': dbDomain.as_json,
                    }
        return {'project': 'peter_sslers',
                'SslDomain': dbDomain
                }

    @view_config(route_name='admin:domain:focus:nginx_cache_expire', renderer=None)
    @view_config(route_name='admin:domain:focus:nginx_cache_expire|json', renderer='json')
    def domain_focus_nginx_expire(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        dbDomain = self._domain_focus(eagerload_web=True)
        if not self.request.registry.settings['enable_nginx']:
            raise HTTPSeeOther('%s/domain/%s?error=no_nginx' % (self.request.registry.settings['admin_prefix'], dbDomain.id))
        success, dbEvent = lib.utils.nginx_expire_cache(self.request, self.request.api_context, dbDomains=[dbDomain, ])
        if wants_json:
            return {'result': 'success',
                    'operations_event': {'id': dbEvent.id,
                                         },
                    }
        return HTTPSeeOther('%s/domain/%s?operation=nginx_cache_expire&result=success&event.id=%s' % (self.request.registry.settings['admin_prefix'], dbDomain.id, dbEvent.id))

    @view_config(route_name='admin:domain:focus:config|json', renderer='json')
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
            lib.utils.prime_redis_domain(self.request, dbDomain)
        return rval

    @view_config(route_name='admin:domain:focus:certificates', renderer='/admin/domain-focus-certificates.mako')
    @view_config(route_name='admin:domain:focus:certificates_paginated', renderer='/admin/domain-focus-certificates.mako')
    def domain_focus__certificates(self):
        dbDomain = self._domain_focus()
        items_count = lib_db.get.get__SslServerCertificate__by_SslDomainId__count(self.request.api_context, dbDomain.id)
        (pager, offset) = self._paginate(items_count, url_template='%s/domain/%s/certificates/{0}' % (self.request.registry.settings['admin_prefix'], dbDomain.id))
        items_paged = lib_db.get.get__SslServerCertificate__by_SslDomainId__paginated(
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
        items_count = lib_db.get.get__SslCertificateRequest__by_SslDomainId__count(self.request.api_context, dbDomain.id)
        (pager, offset) = self._paginate(items_count, url_template='%s/domain/%s/certificate-requests/{0}' % (self.request.registry.settings['admin_prefix'], dbDomain.id))
        items_paged = lib_db.get.get__SslCertificateRequest__by_SslDomainId__paginated(
            self.request.api_context, dbDomain.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslDomain': dbDomain,
                'SslCertificateRequests_count': items_count,
                'SslCertificateRequests': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:domain:focus:calendar|json', renderer='json')
    def domain_focus__calendar(self):
        rval = {}
        dbDomain = self._domain_focus()
        weekly_certs = self.request.api_context.dbSession.query(models.year_week(models.SslServerCertificate.timestamp_signed).label('week_num'),
                                                                sqlalchemy.func.count(models.SslServerCertificate.id)
                                                                )\
            .join(models.SslUniqueFQDNSet2SslDomain,
                  models.SslServerCertificate.ssl_unique_fqdn_set_id == models.SslUniqueFQDNSet2SslDomain.ssl_unique_fqdn_set_id,
                  )\
            .filter(models.SslUniqueFQDNSet2SslDomain.ssl_domain_id == dbDomain.id,
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
        items_count = lib_db.get.get__SslUniqueFQDNSet__by_SslDomainId__count(self.request.api_context, dbDomain.id)
        (pager, offset) = self._paginate(items_count, url_template='%s/domain/%s/unique-fqdn-sets/{0}' % (self.request.registry.settings['admin_prefix'], dbDomain.id))
        items_paged = lib_db.get.get__SslUniqueFQDNSet__by_SslDomainId__paginated(
            self.request.api_context, dbDomain.id, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslDomain': dbDomain,
                'SslUniqueFQDNSets_count': items_count,
                'SslUniqueFQDNSets': items_paged,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:domain:focus:mark', renderer=None)
    @view_config(route_name='admin:domain:focus:mark|json', renderer='json')
    def domain_focus_mark(self):
        dbDomain = self._domain_focus()
        if self.request.method == 'POST':
            return self._domain_focus_mark__submit(dbDomain)
        return self._domain_focus_mark__print(dbDomain)
    
    def _domain_focus_mark__print(self, dbDomain):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        if wants_json:
            return {'instructions': ["""curl --form 'action=active' %s/domain/1/mark.json""" % self.request.admin_url,
                                     ],
                    'form_fields': {'action': 'the intended action',
                                    },
                    'valid_options': {'action': ['active', 'inactive'],
                                      }
                    }
        url_post_required = '%s/domain/%s?operation=mark&result=post+required' % (
            self.request.registry.settings['admin_prefix'],
            dbDomain.id,
        )
        return HTTPSeeOther(url_post_required)    

    def _account_key_focus_mark__submit(self, dbAcmeAccountKey):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        action = '!MISSING or !INVALID'
        try:
            (result,
             formStash
             ) = formhandling.form_validate(self.request,
                                            schema=Form_Domain_mark,
                                            validate_get=False
                                            )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results['action']
            event_type = models.SslOperationsEventType.from_string('domain__mark')
            event_payload_dict = lib.utils.new_event_payload_dict()
            event_payload_dict['domain_id'] = dbDomain.id
            event_payload_dict['action'] = action
            event_status = False

            # bookkeeping
            dbOperationsEvent = lib_db.logger.log__SslOperationsEvent(
                self.request.api_context,
                event_type,
                event_payload_dict,
            )

            if action == 'active':
                if dbDomain.is_active:
                    formStash.set_error(field='Error_Main',
                                        message='Already active.',
                                        raise_FormInvalid=True,
                                        )
                lib_db.actions.enable_Domain(self.request.api_context,
                                             dbDomain,
                                             dbOperationsEvent=dbOperationsEvent,
                                             event_status='domain__mark__active',
                                             action='activated'
                                             )

            elif action == 'inactive':
                if not dbDomain.is_active:
                    formStash.set_error(field='Error_Main',
                                        message='Already inactive.',
                                        raise_FormInvalid=True,
                                        )
                lib_db.actions.disable_Domain(self.request.api_context,
                                              dbDomain,
                                              dbOperationsEvent=dbOperationsEvent,
                                              event_status='domain__mark__inactive',
                                              action='deactivated'
                                              )

            else:
                formStash.set_error(field='action',
                                    message='invalid option.',
                                    raise_FormInvalid=True,
                                    )

            self.request.api_context.dbSession.flush(objects=[dbOperationsEvent, dbDomain])
            
            if wants_json:
                return {'result': 'success',
                        'SslDomain': dbDomain.as_json,
                        }

            url_success = '%s/domain/%s?operation=mark&action=%s&result=success' % (
                self.request.registry.settings['admin_prefix'],
                dbDomain.id,
                action,
            )
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as e:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            if wants_json:
                return {'result': 'error',
                        'form_errors': formStash.errors,
                        }
            url_failure = '%s/domain/%s?operation=mark&action=%s&result=error&error=%s' % (
                self.request.registry.settings['admin_prefix'],
                dbDomain.id,
                action,
                e.message,
            )
            raise HTTPSeeOther(url_failure)
