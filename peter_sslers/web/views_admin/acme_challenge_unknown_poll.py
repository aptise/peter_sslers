# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther

# stdlib
import json

# pypi
import sqlalchemy

# localapp
from .. import lib
from ..lib import formhandling
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ...lib import cert_utils
from ...lib import db as lib_db
from ...lib import utils
from ...model import utils as model_utils


# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:acme_challenge_unknown_polls",
        renderer="/admin/acme_challenge_unknown_polls.mako",
    )
    @view_config(
        route_name="admin:acme_challenge_unknown_polls_paginated",
        renderer="/admin/acme_challenge_unknown_polls.mako",
    )
    @view_config(
        route_name="admin:acme_challenge_unknown_polls|json", renderer="json",
    )
    @view_config(
        route_name="admin:acme_challenge_unknown_polls_paginated|json", renderer="json",
    )
    def list(self):
        items_count = lib_db.get.get__AcmeChallengeUnknownPoll__count(
            self.request.api_context
        )
        (pager, offset) = self._paginate(
            items_count,
            url_template="%s/acme-challenge-unknown-polls/{0}"
            % self.request.registry.settings["app_settings"]["admin_prefix"],
        )
        items_paged = lib_db.get.get__AcmeChallengeUnknownPoll__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        if self.request.wants_json:
            _items = {k.id: k.as_json for k in items_paged}
            return {
                "AcmeChallengeUnknownPolls": _items,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "AcmeChallengeUnknownPolls_count": items_count,
            "AcmeChallengeUnknownPolls": items_paged,
            "pager": pager,
        }
