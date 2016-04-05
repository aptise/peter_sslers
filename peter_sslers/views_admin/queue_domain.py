# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPFound
from pyramid.httpexceptions import HTTPNotFound

# stdlib
import datetime
import json
import pdb
import transaction

# pypi
import pyramid_formencode_classic as formhandling
import sqlalchemy

# localapp
from ..models import *
from ..lib.forms import (Form_QueueDomains_add
                         )
from ..lib import acme as lib_acme
from ..lib import cert_utils as lib_cert_utils
from ..lib import db as lib_db
from ..lib import errors as lib_errors
from ..lib import letsencrypt_info as lib_letsencrypt_info
from ..lib.handler import Handler, items_per_page


# ==============================================================================


class ViewAdmin(Handler):

    @view_config(route_name='admin:queue_domains', renderer='/admin/queue-domains.mako')
    @view_config(route_name='admin:queue_domains_paginated', renderer='/admin/queue-domains.mako')
    def queue_domains(self):
        items_count = lib_db.get__LetsencryptQueueDomain__count(DBSession, show_processed=False)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/queue-domains/{0}')
        items_paged = lib_db.get__LetsencryptQueueDomain__paginated(DBSession, show_processed=False, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'LetsencryptQueueDomains_count': items_count,
                'LetsencryptQueueDomains': items_paged,
                'sidenav_option': 'unprocessed',
                'pager': pager,
                }

    @view_config(route_name='admin:queue_domains:all', renderer='/admin/queue-domains.mako')
    @view_config(route_name='admin:queue_domains:all_paginated', renderer='/admin/queue-domains.mako')
    def queue_domains_all(self):
        items_count = lib_db.get__LetsencryptQueueDomain__count(DBSession, show_processed=True)
        (pager, offset) = self._paginate(items_count, url_template='/.well-known/admin/queue-domains/all/{0}')
        items_paged = lib_db.get__LetsencryptQueueDomain__paginated(DBSession, show_processed=True, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'LetsencryptQueueDomains_count': items_count,
                'LetsencryptQueueDomains': items_paged,
                'sidenav_option': 'all',
                'pager': pager,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _queue_domain_focus(self):
        item = lib_db.get__LetsencryptQueueDomain__by_id(DBSession, self.request.matchdict['id'])
        if not item:
            raise HTTPNotFound('the item was not found')
        return item

    @view_config(route_name='admin:queue_domain:focus', renderer='/admin/queue-domain-focus.mako')
    def queue_domain_focus(self):
        dbQueueDomainItem = self._queue_domain_focus()
        return {'project': 'peter_sslers',
                'QueueDomainItem': dbQueueDomainItem,
                }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:queue_domains:add')
    @view_config(route_name='admin:queue_domains:add.json', renderer='json')
    def queue_domains_add(self):
        if self.request.POST:
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
                
            domain_names = list(set([d.strip().lower() for d in formStash.results['domain_names'].split(',')]))
            if not domain_names:
                formStash.set_error(field="domain_names",
                                    message="Found no domain names",
                                    raise_FormInvalid=True,
                                    message_prepend=True
                                    )
            queue_results = lib_db.queue_domains__add(DBSession, domain_names)

            if self.request.matched_route.name == 'admin:queue_domains:add.json':
                return {'result': 'success',
                        'domains': queue_results,
                        }
            results_json = json.dumps(queue_results)
            return HTTPFound('/.well-known/admin/queue-domains?is_created=1&results=%s' % results_json)

        except formhandling.FormInvalid, e:
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
                auto_error_formatter=formhandling.formatter_none,
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name='admin:queue_domains:process', renderer=None)
    @view_config(route_name='admin:queue_domains:process.json', renderer='json')
    def queue_domain_process(self):
        try:
            queue_results = lib_db.queue_domains__process(DBSession)
            return HTTPFound("/.well-known/admin/queue-domains?processed=1")
        except lib_errors.DisplayableError, e:
            # return, don't raise
            # we still commit the bookkeeping
            if self.request.matched_route.name == 'admin:queue_domains:process.json':
                return {'result': 'error',
                        'error': e.message,
                        }
            return HTTPFound("/.well-known/admin/queue-domains?processed=0&error=%s" % e.message)
