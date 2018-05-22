# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther

# stdlib
import datetime
import json

# pypi
import pyramid_formencode_classic as formhandling
import sqlalchemy
import transaction

# localapp
from ..models import models
from .. import lib
from ..lib import db as lib_db
from ..lib import text as lib_text
from ..lib.forms import Form_QueueDomains_add
from ..lib.forms import Form_QueueDomain_mark
from ..lib import errors
from ..lib.handler import Handler, items_per_page


# ==============================================================================


class ViewAdmin(Handler):

    @view_config(route_name='admin:queue_domains', renderer='/admin/queue-domains.mako')
    @view_config(route_name='admin:queue_domains_paginated', renderer='/admin/queue-domains.mako')
    @view_config(route_name='admin:queue_domains|json', renderer='json')
    @view_config(route_name='admin:queue_domains_paginated|json', renderer='json')
    @view_config(route_name='admin:queue_domains:all', renderer='/admin/queue-domains.mako')
    @view_config(route_name='admin:queue_domains:all_paginated', renderer='/admin/queue-domains.mako')
    @view_config(route_name='admin:queue_domains:all|json', renderer='json')
    @view_config(route_name='admin:queue_domains:all_paginated|json', renderer='json')
    def queue_domains(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        wants_all = True if self.request.matched_route.name in ('admin:queue_domains:all',
                                                                'admin:queue_domains:all_paginated',
                                                                'admin:queue_domains:all|json',
                                                                'admin:queue_domains:all_paginated|json',
                                                                ) else False
        sidenav_option = 'unprocessed'
        unprocessed_only = True
        show_all = None
        if wants_all:
            sidenav_option = 'all'
            unprocessed_only = False
            show_all = True
        if wants_json:
            if wants_all:
                url_template = '%s/queue-domains/all/{0}.json' % self.request.registry.settings['admin_prefix']
            else:
                url_template = '%s/queue-domains/{0}.json' % self.request.registry.settings['admin_prefix']
        else:
            if wants_all:
                url_template = '%s/queue-domains/all/{0}' % self.request.registry.settings['admin_prefix']
            else:
                url_template = '%s/queue-domains/{0}' % self.request.registry.settings['admin_prefix']
        items_count = lib_db.get.get__SslQueueDomain__count(self.request.api_context, show_all=show_all, unprocessed_only=unprocessed_only)
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__SslQueueDomain__paginated(self.request.api_context, show_all=show_all, unprocessed_only=unprocessed_only, limit=items_per_page, offset=offset)
        if wants_json:
            _domains = {d.id: d.as_json for d in items_paged}
            return {'SslQueueDomains': _domains,
                    'pagination': {'total_items': items_count,
                                   'page': pager.page_num,
                                   'page_next': pager.next if pager.has_next else None,
                                   }
                    }
        return {'project': 'peter_sslers',
                'SslQueueDomains_count': items_count,
                'SslQueueDomains': items_paged,
                'sidenav_option': sidenav_option,
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:queue_domains:add')
    @view_config(route_name='admin:queue_domains:add|json', renderer='json')
    def queue_domains_add(self):
        if self.request.method == 'POST':
            return self._queue_domains_add__submit()
        return self._queue_domains_add__print()

    def _queue_domains_add__print(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        if wants_json:
            return {'instructions': """POST `domain_names""",
                    'form_fields': {'domain_names': 'required',
                                    },
                    }
        return render_to_response("/admin/queue-domains-add.mako", {}, self.request)

    def _queue_domains_add__submit(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_QueueDomains_add,
                                                             validate_get=False
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            domain_names = lib.utils.domains_from_string(formStash.results['domain_names'])
            if not domain_names:
                formStash.set_error(field="domain_names",
                                    message="Found no domain names",
                                    raise_FormInvalid=True,
                                    message_prepend=True
                                    )

            queue_results = lib_db.queues.queue_domains__add(self.request.api_context,
                                                             domain_names,
                                                             )

            if wants_json:
                return {'result': 'success',
                        'domains': queue_results,
                        }
            results_json = json.dumps(queue_results)
            return HTTPSeeOther('%s/queue-domains?result=success&is_created=1&results=%s' % (self.request.registry.settings['admin_prefix'], results_json))

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
            return formhandling.form_reprint(
                self.request,
                self._queue_domains_add__print,
                auto_error_formatter=lib_text.formatter_error,
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:queue_domains:process', renderer=None)
    @view_config(route_name='admin:queue_domains:process|json', renderer='json')
    def queue_domain_process(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        try:
            queue_results = lib_db.queues.queue_domains__process(self.request.api_context)
            if wants_json:
                return {'result': 'success',
                        }
            return HTTPSeeOther("%s/queue-domains?processed=1" % self.request.registry.settings['admin_prefix'])
        except (errors.DisplayableError,
                errors.DomainVerificationError,
                ) as e:
            # return, don't raise
            # we still commit the bookkeeping
            if wants_json:
                return {'result': 'error',
                        'error': e.message,
                        }
            return HTTPSeeOther("%s/queue-domains?processed=0&error=%s" % (self.request.registry.settings['admin_prefix'], e.message))
        except Exception as e:
            print e
            transaction.abort()
            if wants_json:
                return {'result': 'error',
                        'error': e.message,
                        }
            raise

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _queue_domain_focus(self):
        item = lib_db.get.get__SslQueueDomain__by_id(self.request.api_context, self.request.matchdict['id'], eagerload_log=True)
        if not item:
            raise HTTPNotFound('the item was not found')
        return item

    @view_config(route_name='admin:queue_domain:focus', renderer='/admin/queue-domain-focus.mako')
    @view_config(route_name='admin:queue_domain:focus|json', renderer='json')
    def queue_domain_focus(self):
        dbQueueDomain = self._queue_domain_focus()
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        if wants_json:
            return {'status': 'success',
                    'SslQueueDomain': dbQueueDomain.as_json,
                    }
        return {'project': 'peter_sslers',
                'QueueDomainItem': dbQueueDomain,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:queue_domain:focus:mark', renderer=None)
    @view_config(route_name='admin:queue_domain:focus:mark|json', renderer='json')
    def queue_domain_focus_mark(self):
        dbQueueDomain = self._queue_domain_focus()
        if self.request.method == 'POST':
            return self._queue_domain_focus_mark__submit(dbQueueDomain)
        return self._queue_domain_focus_mark__print(dbQueueDomain)

    def _queue_domain_focus_mark__print(self, dbQueueDomain):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        if wants_json:
            return {'instructions': ["""curl --form 'action=active' %s/queue-domain/1/mark.json""" % self.request.admin_url,
                                     ],
                    'form_fields': {'action': 'the intended action',
                                    },
                    'valid_options': {'action': ['cancel'],
                                      }
                    }
        url_post_required = '%s/queue-domain/%s?operation=mark&result=post+required' % (
            self.request.registry.settings['admin_prefix'],
            dbQueueDomain.id,
        )
        return HTTPSeeOther(url_post_required)            
    
    def _queue_domain_focus_mark__submit(self, dbQueueDomain):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        try:
            (result,
             formStash
             ) = formhandling.form_validate(self.request,
                                            schema=Form_QueueDomain_mark,
                                            validate_get=True
                                            )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results['action']
            event_type = models.SslOperationsEventType.from_string('queue_domain__mark')
            event_payload_dict = lib.utils.new_event_payload_dict()
            event_payload_dict['ssl_queue_domain.id'] = dbQueueDomain.id
            event_payload_dict['action'] = formStash.results['action']

            # bookkeeping
            dbOperationsEvent = lib_db.logger.log__SslOperationsEvent(
                self.request.api_context,
                event_type,
                event_payload_dict,
            )

            event_status = False
            if action == 'cancel':
                if not dbQueueDomain.is_active:
                    formStash.set_error(field='action',
                                        message="Already cancelled",
                                        raise_FormInvalid=True,
                                        )
                lib_db.queues.dequeue_QueuedDomain(self.request.api_context,
                                                   dbQueueDomain,
                                                   dbOperationsEvent=dbOperationsEvent,
                                                   event_status='queue_domain__mark__cancelled',
                                                   action='de-queued'
                                                   )
            else:
                formStash.set_error(field='action',
                                    message="invalid `action",
                                    raise_FormInvalid=True,
                                    )

            self.request.api_context.dbSession.flush(objects=[dbQueueDomain, dbOperationsEvent])

            if wants_json:
                return {'result': 'success',
                        'SslQueueDomain': dbQueueDomain.as_json,
                        }

            url_success = '%s/queue-domain/%s?operation=mark&action=%s&result=success' % (
                self.request.registry.settings['admin_prefix'],
                dbQueueDomain.id,
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
            url_failure = '%s/queue-domain/%s?operation=mark&action=%s&result=error&error=%s' % (
                self.request.registry.settings['admin_prefix'],
                dbQueueDomain.id,
                action,
                e.message,
            )
            raise HTTPSeeOther(url_failure)
