# stdlib

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
        route_name="admin:acme_challenge_polls",
        renderer="/admin/acme_challenge_polls.mako",
    )
    @view_config(
        route_name="admin:acme_challenge_polls_paginated",
        renderer="/admin/acme_challenge_polls.mako",
    )
    @view_config(
        route_name="admin:acme_challenge_polls|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:acme_challenge_polls_paginated|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-challenge-polls.json",
            "section": "acme-challenge-poll",
            "about": """list AcmeChallengePolls(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-challenge-polls.json",
        }
    )
    @docify(
        {
            "endpoint": "/acme-challenge-polls/{PAGE}.json",
            "section": "acme-challenge-poll",
            "example": "curl {ADMIN_PREFIX}/acme-challenge-polls/1.json",
            "variant_of": "/acme-challenge-polls.json",
        }
    )
    def list(self):
        items_count = lib_db.get.get__AcmeChallengePoll__count(self.request.api_context)
        url_template = (
            "%s/acme-challenge-polls/{0}"
            % self.request.api_context.application_settings["admin_prefix"]
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__AcmeChallengePoll__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        if self.request.wants_json:
            _items = {k.id: k.as_json for k in items_paged}
            return {
                "AcmeChallengePolls": _items,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "AcmeChallengePolls_count": items_count,
            "AcmeChallengePolls": items_paged,
            "pager": pager,
        }
