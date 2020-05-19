# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther

# stdlib
import datetime
import json
import pdb

# pypi
import sqlalchemy
from six.moves.urllib.parse import quote_plus

# localapp
from .. import lib
from ..lib import formhandling
from ..lib import form_utils as form_utils
from ..lib import text as lib_text
from ..lib.forms import Form_QueueDomain_mark
from ..lib.forms import Form_QueueDomains_add
from ..lib.forms import Form_QueueDomains_process
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...model import utils as model_utils


# ==============================================================================


class ViewAdmin_List(Handler):
    @view_config(
        route_name="admin:coverage_assurance_events",
        renderer="/admin/coverage_assurance_events.mako",
    )
    def list_redirect(self):
        url_all = (
            "%s/coverage-assurance-events/all"
            % self.request.registry.settings["app_settings"]["admin_prefix"]
        )
        return HTTPSeeOther(url_all)

    @view_config(
        route_name="admin:coverage_assurance_events:all",
        renderer="/admin/coverage_assurance_events.mako",
    )
    @view_config(
        route_name="admin:coverage_assurance_events:all_paginated",
        renderer="/admin/coverage_assurance_events.mako",
    )
    @view_config(
        route_name="admin:coverage_assurance_events:unresolved",
        renderer="/admin/coverage_assurance_events.mako",
    )
    @view_config(
        route_name="admin:coverage_assurance_events:unresolved_paginated",
        renderer="/admin/coverage_assurance_events.mako",
    )
    def list(self):
        sidenav_option = None
        unresolved_only = None
        if self.request.matched_route.name in (
            "admin:coverage_assurance_events:all",
            "admin:coverage_assurance_events:all_paginated",
        ):
            sidenav_option = "all"
            unresolved_only = False
        elif self.request.matched_route.name in (
            "admin:coverage_assurance_events:unresolved",
            "admin:coverage_assurance_events:unresolved_paginated",
        ):
            sidenav_option = "unresolved"
            unresolved_only = True
        url_template = "%s/coverage-assurance-events/%s/{0}" % (
            self.request.registry.settings["app_settings"]["admin_prefix"],
            "unresolved" if unresolved_only else "all",
        )
        items_count = lib_db.get.get__CoverageAssuranceEvent__count(
            self.request.api_context, unresolved_only=unresolved_only
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__CoverageAssuranceEvent__paginated(
            self.request.api_context,
            unresolved_only=unresolved_only,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "CoverageAssuranceEvents_count": items_count,
            "CoverageAssuranceEvents": items_paged,
            "sidenav_option": sidenav_option,
            "pager": pager,
        }


class ViewAdmin_Focus(Handler):
    def _focus(self):
        dbCoverageAssuranceEvent = lib_db.get.get__CoverageAssuranceEvent__by_id(
            self.request.api_context, self.request.matchdict["id"],
        )
        if not dbCoverageAssuranceEvent:
            raise HTTPNotFound("the item was not found")
        self._focus_item = dbCoverageAssuranceEvent
        self._focus_url = "%s/coverage-assurance-event/%s" % (
            self.request.registry.settings["app_settings"]["admin_prefix"],
            dbCoverageAssuranceEvent.id,
        )
        return dbCoverageAssuranceEvent

    @view_config(
        route_name="admin:coverage_assurance_event:focus",
        renderer="/admin/coverage_assurance_event-focus.mako",
    )
    def focus(self):
        dbCoverageAssuranceEvent = self._focus()
        return {
            "project": "peter_sslers",
            "CoverageAssuranceEvent": dbCoverageAssuranceEvent,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
