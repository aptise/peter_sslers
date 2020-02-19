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
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db


# ==============================================================================


class ViewAdmin_List(Handler):
    @view_config(
        route_name="admin:acme_event_log", renderer="/admin/acme_event_log.mako"
    )
    @view_config(
        route_name="admin:acme_event_log_paginated",
        renderer="/admin/acme_event_log.mako",
    )
    @view_config(route_name="admin:acme_event_log|json", renderer="json")
    @view_config(route_name="admin:acme_event_log_paginated|json", renderer="json")
    def acme_event_log(self):
        items_count = lib_db.get.get__AcmeEventLog__count(self.request.api_context)
        (pager, offset) = self._paginate(
            items_count,
            url_template="%s/acme-event-logs/{0}"
            % self.request.registry.settings["admin_prefix"],
        )
        items_paged = lib_db.get.get__AcmeEventLog__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        if self.request.wants_json:
            _auths = {k.id: k.as_json for k in items_paged}
            return {
                "AcmeEventLogs": _auths,
                "pagination": json_pagination(items_count, pager),
            }
        return {"project": "peter_sslers", "AcmeEventLogs": items_paged}


class ViewAdmin_Focus(Handler):
    def _acme_event_log_focus(self):
        dbAcmeEventLog = lib_db.get.get__AcmeEventLog__by_id(
            self.request.api_context, self.request.matchdict["id"]
        )
        if not dbAcmeEventLog:
            raise HTTPNotFound("the log was not found")
        return dbAcmeEventLog

    @view_config(
        route_name="admin:acme_event_log:focus",
        renderer="/admin/acme_event_log-focus.mako",
    )
    @view_config(
        route_name="admin:acme_event_log:focus|json", renderer="json",
    )
    def acme_event_log_focus(self):
        item = self._acme_event_log_focus()
        if self.request.wants_json:
            return {
                "AcmeEventLog": item.as_json,
            }
        return {"project": "peter_sslers", "AcmeEventLog": item}
