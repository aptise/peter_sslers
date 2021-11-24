# pypi
from pyramid.view import view_config

# local
from ..lib.docs import docify
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db

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
        route_name="admin:acme_challenge_unknown_polls|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:acme_challenge_unknown_polls_paginated|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-challenge-unknown-polls.json",
            "section": "acme-challenge-unknown-poll",
            "about": """list AcmeChallengeUnknownPolls(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-challenge-unknown-polls.json",
        }
    )
    @docify(
        {
            "endpoint": "/acme-challenge-unknown-polls/{PAGE}.json",
            "section": "acme-challenge-unknown-poll",
            "example": "curl {ADMIN_PREFIX}/acme-challenge-unknown-polls/1.json",
            "variant_of": "/acme-challenge-unknown-polls.json",
        }
    )
    def list(self):
        items_count = lib_db.get.get__AcmeChallengeUnknownPoll__count(
            self.request.api_context
        )
        url_template = (
            "%s/acme-challenge-unknown-polls/{0}"
            % self.request.registry.settings["app_settings"]["admin_prefix"]
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template)
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
