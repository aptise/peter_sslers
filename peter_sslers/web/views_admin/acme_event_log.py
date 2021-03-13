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
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db


# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:acme_event_log", renderer="/admin/acme_event_log.mako"
    )
    @view_config(
        route_name="admin:acme_event_log_paginated",
        renderer="/admin/acme_event_log.mako",
    )
    @view_config(route_name="admin:acme_event_log|json", renderer="json")
    @view_config(route_name="admin:acme_event_log_paginated|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-event-logs.json",
            "section": "acme-event-log",
            "about": """list AcmeEventLog(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-event-logs.json",
        }
    )
    @docify(
        {
            "endpoint": "/acme-event-logs/{PAGE}.json",
            "section": "acme-event-log",
            "example": "curl {ADMIN_PREFIX}/acme-event-logs/1.json",
            "variant_of": "/acme-event-logs.json",
        }
    )
    def list(self):
        items_count = lib_db.get.get__AcmeEventLog__count(self.request.api_context)
        url_template = (
            "%s/acme-event-logs/{0}"
            % self.request.registry.settings["app_settings"]["admin_prefix"]
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__AcmeEventLog__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        if self.request.wants_json:
            _auths = {k.id: k.as_json for k in items_paged}
            return {
                "AcmeEventLogs": _auths,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "AcmeEventLogs": items_paged,
            "pager": pager,
        }


class View_Focus(Handler):
    def _acme_event_log_focus(self):
        dbAcmeEventLog = lib_db.get.get__AcmeEventLog__by_id(
            self.request.api_context, self.request.matchdict["id"]
        )
        if not dbAcmeEventLog:
            raise HTTPNotFound("the log was not found")
        return dbAcmeEventLog

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_event_log:focus",
        renderer="/admin/acme_event_log-focus.mako",
    )
    @view_config(
        route_name="admin:acme_event_log:focus|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-event-log/{ID}.json",
            "section": "acme-event-log",
            "about": """AcmeEventLog""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-event-log/1.json",
        }
    )
    def focus(self):
        item = self._acme_event_log_focus()
        if self.request.wants_json:
            return {
                "AcmeEventLog": item.as_json,
            }
        return {"project": "peter_sslers", "AcmeEventLog": item}
