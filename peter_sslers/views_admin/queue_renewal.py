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
import transaction

# localapp
from ..models import models
from ..lib import acme as lib_acme
from ..lib import cert_utils as lib_cert_utils
from ..lib import db as lib_db
from ..lib import utils as lib_utils
from ..lib import letsencrypt_info as lib_letsencrypt_info
from ..lib.forms import (Form_QueueRenewal_mark,
                         )
from ..lib.handler import Handler, items_per_page


# ==============================================================================


class ViewAdmin(Handler):

    @view_config(route_name='admin:queue_renewals', renderer='/admin/queue-renewals.mako')
    @view_config(route_name='admin:queue_renewals_paginated', renderer='/admin/queue-renewals.mako')
    def rewnewal_queue(self):
        items_count = lib_db.get.get__SslQueueRenewal__count(self.request.api_context, show_all=False)
        (pager, offset) = self._paginate(items_count, url_template='%s/queue-renewals/{0}' % self.request.registry.settings['admin_prefix'])
        items_paged = lib_db.get.get__SslQueueRenewal__paginated(self.request.api_context, show_all=False, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslQueueRenewals_count': items_count,
                'SslQueueRenewals': items_paged,
                'sidenav_option': 'unprocessed',
                'pager': pager,
                }

    @view_config(route_name='admin:queue_renewals:all', renderer='/admin/queue-renewals.mako')
    @view_config(route_name='admin:queue_renewals:all_paginated', renderer='/admin/queue-renewals.mako')
    def queue_renewal_all(self):
        items_count = lib_db.get.get__SslQueueRenewal__count(self.request.api_context, show_all=True)
        (pager, offset) = self._paginate(items_count, url_template='%s/queue-renewals/all/{0}' % self.request.registry.settings['admin_prefix'])
        items_paged = lib_db.get.get__SslQueueRenewal__paginated(self.request.api_context, show_all=True, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslQueueRenewals_count': items_count,
                'SslQueueRenewals': items_paged,
                'sidenav_option': 'all',
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _queue_renewal_focus(self):
        item = lib_db.get.get__SslQueueRenewal__by_id(self.request.api_context, self.request.matchdict['id'], load_events=True)
        if not item:
            raise HTTPNotFound('the item was not found')
        return item

    @view_config(route_name='admin:queue_renewal:focus', renderer='/admin/queue-renewal-focus.mako')
    def queue_renewal_focus(self):
        dbRenewalQueueItem = self._queue_renewal_focus()
        return {'project': 'peter_sslers',
                'RenewalQueueItem': dbRenewalQueueItem,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:queue_renewal:focus:mark', renderer=None)
    @view_config(route_name='admin:queue_renewal:focus:mark.json', renderer='json')
    def queue_renewal_focus_mark(self):
        dbQueueRenewal = self._queue_renewal_focus()
        action = '!MISSING or !INVALID'
        try:
            (result, formStash) = formhandling.form_validate(self.request,
                                                             schema=Form_QueueRenewal_mark,
                                                             validate_get=True
                                                             )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results['action']
            event_type = models.SslOperationsEventType.from_string('queue_renewal__mark')
            event_payload_dict = lib_utils.new_event_payload_dict()
            event_payload_dict['ssl_queue_renewal.id'] = dbQueueRenewal.id
            event_payload_dict['action'] = formStash.results['action']

            event_status = False
            if action == 'cancelled':
                if not dbQueueRenewal.is_active:
                    raise formhandling.FormInvalid('Already cancelled')
                dbQueueRenewal.is_active = False
                dbQueueRenewal.timestamp_processed = self.request.api_context.timestamp
                event_status = 'queue_renewal__mark__cancelled'
                self.request.api_context.dbSession.flush(objects=[dbQueueRenewal, ])
            else:
                raise formhandling.FormInvalid('invalid `action`')

            # bookkeeping
            dbOperationsEvent = lib_db.log__SslOperationsEvent(
                self.request.api_context,
                event_type,
                event_payload_dict,
            )
            lib_db._log_object_event(self.request.api_context,
                                     dbOperationsEvent=dbOperationsEvent,
                                     event_status_id=models.SslOperationsObjectEventStatus.from_string(event_status),
                                     dbQueueRenewal=dbQueueRenewal,
                                     )

            url_success = '%s/queue-renewal/%s?operation=mark&action=%s&result=success' % (
                self.request.registry.settings['admin_prefix'],
                dbQueueRenewal.id,
                action,
            )
            return HTTPFound(url_success)

        except formhandling.FormInvalid as e:
            formStash.set_error(field="Error_Main",
                                message="There was an error with your form.",
                                raise_FormInvalid=False,
                                message_prepend=True
                                )
            url_failure = '%s/queue-renewal/%s?operation=mark&action=%s&result=error&error=%s' % (
                self.request.registry.settings['admin_prefix'],
                dbQueueRenewal.id,
                action,
                e.message,
            )
            raise HTTPFound(url_failure)
