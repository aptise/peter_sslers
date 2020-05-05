# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther

# stdlib
import datetime

# pypi
import sqlalchemy

# localapp
from .. import lib
from ..lib import formhandling
from ..lib import text as lib_text
from ..lib.forms import Form_Domain_mark
from ..lib.forms import Form_Domain_search
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...lib import utils_nginx
from ...model import utils as model_utils
from ...model import objects as model_objects


# ==============================================================================


class ViewAdmin_List(Handler):

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:domains_blacklisted",
        renderer="/admin/domains_blacklisted.mako",
    )
    @view_config(
        route_name="admin:domains_blacklisted_paginated",
        renderer="/admin/domains_blacklisted.mako",
    )
    @view_config(route_name="admin:domains_blacklisted|json", renderer="json")
    @view_config(route_name="admin:domains_blacklisted_paginated|json", renderer="json")
    def list(self):
        url_template = (
            "%s/domains-blacklisted/{0}"
            % self.request.registry.settings["app_settings"]["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = (
                "%s/domains-blacklisted/{0}.json"
                % self.request.registry.settings["app_settings"]["admin_prefix"]
            )
        items_count = lib_db.get.get__DomainBlacklisted__count(
            self.request.api_context,
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__DomainBlacklisted__paginated(
            self.request.api_context, limit=items_per_page, offset=offset,
        )

        if self.request.wants_json:
            return {
                "DomainsBlacklisted": [d.as_json for d in items_paged],
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "DomainsBlacklisted_count": items_count,
            "DomainsBlacklisted": items_paged,
            "pager": pager,
        }
