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
from ...lib import db as lib_db


# ==============================================================================


class ViewAdmin_AcmeEventLog(Handler):
    @view_config(
        route_name="admin:acme_event_log", renderer="/admin/acme_event_log.mako"
    )
    @view_config(
        route_name="admin:acme_event_log_paginated",
        renderer="/admin/acme_event_log.mako",
    )
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
        return {"project": "peter_sslers", "AcmeEventLogs": items_paged}

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
    def acme_event_log_focus(self):
        item = self._acme_event_log_focus()
        return {"project": "peter_sslers", "AcmeEventLog": item}
