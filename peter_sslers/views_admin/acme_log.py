# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPFound
from pyramid.httpexceptions import HTTPNotFound

# stdlib
import datetime

# pypi
import sqlalchemy

# localapp
from ..models import models
from ..lib import db as lib_db
from ..lib.handler import Handler, items_per_page


# ==============================================================================


class ViewAdmin_AcmeEventLog(Handler):

    @view_config(route_name='admin:acme_event_log', renderer='/admin/acme_event_log.mako')
    @view_config(route_name='admin:acme_event_log_paginated', renderer='/admin/acme_event_log.mako')
    def acme_event_log(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        items_count = lib_db.get.get__SslAcmeEventLogs__count(self.request.api_context)
        (pager, offset) = self._paginate(items_count, url_template='%s/acme-event-logs/{0}' % self.request.registry.settings['admin_prefix'])
        items_paged = lib_db.get.get__SslAcmeEventLogs__paginated(self.request.api_context, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslAcmeEventLogs': items_paged,
                }

    def _acme_event_log_focus(self):
        dbSslAcmeEventLog = lib_db.get.get__SslAcmeEventLog__by_id(self.request.api_context, self.request.matchdict['id'])
        if not dbSslAcmeEventLog:
            raise HTTPNotFound('the log was not found')
        return dbSslAcmeEventLog

    @view_config(route_name='admin:acme_event_log:focus', renderer='/admin/acme_event_log-focus.mako')
    def acme_event_log_focus(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        item = self._acme_event_log_focus()
        return {'project': 'peter_sslers',
                'SslAcmeEventLog': item,
                }


class ViewAdmin_AcmeChallengeLog(Handler):

    @view_config(route_name='admin:acme_challenge_log', renderer='/admin/acme_challenge_log.mako')
    @view_config(route_name='admin:acme_challenge_log_paginated', renderer='/admin/acme_challenge_log.mako')
    def acme_challenge_log(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        items_count = lib_db.get.get__SslAcmeChallengeLogs__count(self.request.api_context)
        (pager, offset) = self._paginate(items_count, url_template='%s/acme-challenge-logs/{0}' % self.request.registry.settings['admin_prefix'])
        items_paged = lib_db.get.get__SslAcmeChallengeLogs__paginated(self.request.api_context, limit=items_per_page, offset=offset)
        return {'project': 'peter_sslers',
                'SslAcmeChallengeLogs': items_paged,
                }

    def _acme_challenge_log_focus(self):
        dbSslAcmeChallengeLog = lib_db.get.get__SslAcmeChallengeLog__by_id(self.request.api_context, self.request.matchdict['id'])
        if not dbSslAcmeChallengeLog:
            raise HTTPNotFound('the log was not found')
        return dbSslAcmeChallengeLog

    @view_config(route_name='admin:acme_challenge_log:focus', renderer='/admin/acme_challenge_log-focus.mako')
    def acme_challenge_log_focus(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        item = self._acme_challenge_log_focus()
        return {'project': 'peter_sslers',
                'SslAcmeChallengeLog': item,
                }

    @view_config(route_name='admin:acme_challenge_log:filtered', renderer='/admin/acme_challenge_log-filtered.mako')
    @view_config(route_name='admin:acme_challenge_log:filtered|json', renderer='json')
    def acme_challenge_log_filtered(self):
        wants_json = True if self.request.matched_route.name.endswith('|json') else False
        dbAcmeAccountKey = None
        try:
            acme_account_key_id = int(self.request.params.get('account-key-id', 0))
            dbAcmeAccountKey = lib_db.get.get__SslAcmeAccountKey__by_id(self.request.api_context, acme_account_key_id, eagerload_web=False, )
        except ValueError:
            pass
        if not dbAcmeAccountKey:
            if wants_json:
                return {'status': 'error',
                        'error': 'invalid or no account-key-id submitted',
                        }
            return HTTPFound("%s/acme-challenge-logs" % self.request.admin_url)

        items_paged = lib_db.get.get__SslAcmeChallengeLogs__paginated(
            self.request.api_context,
            limit=None,
            offset=0,
            acme_account_key_id=acme_account_key_id,
            pending_only=True,
        )
        if wants_json:
                rval = {'filtered_status': "Pending",
                        'SslAcmeAccountKey': dbAcmeAccountKey.as_json,
                        'SslAcmeChallengeLogs': [i.as_json for i in items_paged],
                        }
                del rval['SslAcmeAccountKey']['key_pem']
                return rval
        return {'project': 'peter_sslers',
                'filtered_status': "Pending",
                'SslAcmeAccountKey': dbAcmeAccountKey,
                'SslAcmeChallengeLogs': items_paged,
                }
