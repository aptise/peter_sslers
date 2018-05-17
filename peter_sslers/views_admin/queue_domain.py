# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPFound
from pyramid.httpexceptions import HTTPNotFound

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
    def queue_domains(self):
        items_count = lib_db.get.get__SslQueueDomain__count(self.request.api_context, show_processed=False)
        (pager, offset) = self._paginate(items_count, url_template='%s/queue-domains/{0}' % self.request.registry.settings['admin_prefix'])
        items_paged = lib_db.get.get__SslQueueDomain__paginated(self.request.api_context, show_processed=False, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslQueueDomains_count': items_count,
                'SslQueueDomains': items_paged,
                'sidenav_option': 'unprocessed',
                'pager': pager,
                }

    @view_config(route_name='admin:queue_domains:all', renderer='/admin/queue-domains.mako')
    @view_config(route_name='admin:queue_domains:all_paginated', renderer='/admin/queue-domains.mako')
    def queue_domains_all(self):
        items_count = lib_db.get.get__SslQueueDomain__count(self.request.api_context, show_processed=True)
        (pager, offset) = self._paginate(items_count, url_template='%s/queue-domains/all/{0}' % self.request.registry.settings['admin_prefix'])
        items_paged = lib_db.get.get__SslQueueDomain__paginated(self.request.api_context, show_processed=True, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslQueueDomains_count': items_count,
                'SslQueueDomains': items_paged,
                'sidenav_option': 'all',
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:queue_domains:add')
    @view_config(route_name='admin:queue_domains:add.json', renderer='json')
    def queue_domains_add(self):
        if self.request.method == 'POST':
            return self._queue_domains_add__submit()
        return self._queue_domains_add__print()

    def _queue_domains_add__print(self):
        if self.request.matched_route.name == 'admin:queue_domains:add.json':
            return {'instructions': """POST `domain_names""",
                    'form_fields': {'domain_names': 'required',
                                    },
                    }
        return render_to_response("/admin/queue-domains-add.mako", {}, self.request)

    def _queue_domains_add__submit(self):
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

            if self.request.matched_route.name == 'admin:queue_domains:add.json':
                return {'result': 'success',
                        'domains': queue_results,
                        }
            results_json = json.dumps(queue_results)
            return HTTPFound('%s/queue-domains?result=success&is_created=1&results=%s' % (self.request.registry.settings['admin_prefix'], results_json))

        except formhandling.FormInvalid as e:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            if self.request.matched_route.name == 'admin:queue_domains:add.json':
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
    @view_config(route_name='admin:queue_domains:process.json', renderer='json')
    def queue_domain_process(self):
        try:
            queue_results = lib_db.queues.queue_domains__process(self.request.api_context)
            if self.request.matched_route.name == 'admin:queue_domains:process.json':
                return {'result': 'success',
                        }
            return HTTPFound("%s/queue-domains?processed=1" % self.request.registry.settings['admin_prefix'])
        except (errors.DisplayableError, errors.DomainVerificationError) as e:
            # return, don't raise
            # we still commit the bookkeeping
            if self.request.matched_route.name == 'admin:queue_domains:process.json':
                return {'result': 'error',
                        'error': e.message,
                        }
            return HTTPFound("%s/queue-domains?processed=0&error=%s" % (self.request.registry.settings['admin_prefix'], e.message))
        except Exception as e:
            transaction.abort()
            if self.request.matched_route.name == 'admin:queue_domains:process.json':
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
    def queue_domain_focus(self):
        dbQueueDomain = self._queue_domain_focus()
        return {'project': 'peter_sslers',
                'QueueDomainItem': dbQueueDomain,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:queue_domain:focus:mark', renderer=None)
    @view_config(route_name='admin:queue_domain:focus:mark.json', renderer='json')
    def queue_domain_focus_mark(self):
        dbQueueDomain = self._queue_domain_focus()
        action = '!MISSING or !INVALID'
        try:
            (result, formStash) = formhandling.form_validate(self.request,
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
            if action == 'cancelled':
                if not dbQueueDomain.is_active:
                    raise formhandling.FormInvalid('Already cancelled')
                lib_db.queues.dequeue_QueuedDomain(self.request.api_context,
                                                   dbQueueDomain,
                                                   dbOperationsEvent=dbOperationsEvent,
                                                   event_status='queue_domain__mark__cancelled',
                                                   action='de-queued'
                                                   )
            else:
                raise formhandling.FormInvalid('invalid `action`')

            self.request.api_context.dbSession.flush(objects=[dbQueueDomain, dbOperationsEvent])

            url_success = '%s/queue-domain/%s?operation=mark&action=%s&result=success' % (
                self.request.registry.settings['admin_prefix'],
                dbQueueDomain.id,
                action,
            )
            return HTTPFound(url_success)

        except formhandling.FormInvalid as e:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            url_failure = '%s/queue-domain/%s?operation=mark&action=%s&result=error&error=%s' % (
                self.request.registry.settings['admin_prefix'],
                dbQueueDomain.id,
                action,
                e.message,
            )
            raise HTTPFound(url_failure)
