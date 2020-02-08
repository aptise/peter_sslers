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
from ..lib import text as lib_text
from ..lib.handler import Handler, items_per_page
from ...lib import cert_utils
from ...lib import db as lib_db
from ...lib import utils
from ...model import utils as model_utils


# ==============================================================================


class ViewAdmin_List(Handler):

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_challenges", renderer="/admin/acme_challenges.mako",
    )
    @view_config(
        route_name="admin:acme_challenges_paginated",
        renderer="/admin/acme_challenges.mako",
    )
    def list(self):
        items_count = lib_db.get.get__AcmeChallenges__count(self.request.api_context)
        (pager, offset) = self._paginate(
            items_count,
            url_template="%s/acme-challenge/{0}"
            % self.request.registry.settings["admin_prefix"],
        )
        items_paged = lib_db.get.get__AcmeChallenges__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        return {
            "project": "peter_sslers",
            "AcmeChallenges_count": items_count,
            "AcmeChallenges": items_paged,
            "pager": pager,
        }


class ViewAdmin_Focus(Handler):
    def _focus(self, eagerload_web=False):
        dbAcmeChallenge = lib_db.get.get__AcmeChallenge__by_id(
            self.request.api_context, self.request.matchdict["id"],
        )
        if not dbAcmeChallenge:
            raise HTTPNotFound("the order was not found")
        self._focus_url = "%s/acme-challenge/%s" % (
            self.request.admin_url,
            dbAcmeChallenge.id,
        )
        return dbAcmeChallenge

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_challenge:focus",
        renderer="/admin/acme_challenge-focus.mako",
    )
    def focus(self):
        dbAcmeChallenge = self._focus(eagerload_web=True)
        return {"project": "peter_sslers", "AcmeChallenge": dbAcmeChallenge}
