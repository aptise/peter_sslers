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
from ..lib import form_utils as form_utils
from ..lib import formhandling
from ..lib import text as lib_text
from ..lib.forms import Form_AcmeOrderless_manage_domain
from ..lib.forms import Form_AcmeOrderless_new
from ..lib.handler import Handler, items_per_page
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...model import utils as model_utils
from ...model import objects as model_objects


# ==============================================================================


class ViewAdmin_List(Handler):

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_orderlesss", renderer="/admin/acme_orderlesss.mako",
    )
    @view_config(
        route_name="admin:acme_orderlesss_paginated",
        renderer="/admin/acme_orderlesss.mako",
    )
    def list(self):
        if not self.request.registry.settings["enable_acme_flow"]:
            raise HTTPNotFound("Acme-Flow is disabled on this system")

        items_count = lib_db.get.get__AcmeOrderless__count(self.request.api_context)
        (pager, offset) = self._paginate(
            items_count,
            url_template="%s/acme-orderlesss/{0}"
            % self.request.registry.settings["admin_prefix"],
        )
        items_paged = lib_db.get.get__AcmeOrderless__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        return {
            "project": "peter_sslers",
            "AcmeOrderlesss_count": items_count,
            "AcmeOrderlesss": items_paged,
            "pager": pager,
        }


class ViewAdmin_New(Handler):
    @view_config(route_name="admin:acme_orderless:new")
    def new_AcmeOrderless(self):

        if not self.request.registry.settings["enable_acme_flow"]:
            raise HTTPNotFound("Acme-Flow is disabled on this system")

        if self.request.method == "POST":
            return self._new_AcmeOrderless__submit()
        return self._new_AcmeOrderless__print()

    def _new_AcmeOrderless__print(self):
        return render_to_response("/admin/acme_orderless-new.mako", {}, self.request,)

    def _new_AcmeOrderless__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_AcmeOrderless_new, validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            domain_names = utils.domains_from_string(formStash.results["domain_names"])
            if not domain_names:
                raise ValueError("missing valid domain names")

            dbAcmeOrderless = lib_db.create.create__AcmeOrderless(
                self.request.api_context, domain_names=domain_names,
            )

            return HTTPSeeOther(
                "%s/acme-orderless/%s"
                % (self.request.registry.settings["admin_prefix"], dbAcmeOrderless.id,)
            )

        except formhandling.FormInvalid as exc:
            return formhandling.form_reprint(
                self.request, self._new_AcmeOrderless__print
            )


class ViewAdmin_Focus(Handler):
    def _focus(self, eagerload_web=False):
        dbAcmeOrderless = lib_db.get.get__AcmeOrderless__by_id(
            self.request.api_context,
            self.request.matchdict["id"],
            eagerload_web=eagerload_web,
        )
        if not dbAcmeOrderless:
            raise HTTPNotFound("the item was not found")
        self._focus_url = "%s/acme-orderless/%s" % (
            self.request.admin_url,
            dbAcmeOrderless.id,
        )
        return dbAcmeOrderless

    @view_config(
        route_name="admin:acme_orderless:focus",
        renderer="/admin/acme_orderless-focus.mako",
    )
    @view_config(route_name="admin:acme_orderless:focus|json", renderer="json")
    def focus(self):
        if not self.request.registry.settings["enable_acme_flow"]:
            raise HTTPNotFound("Acme-Flow is disabled on this system")
        wants_json = (
            True if self.request.matched_route.name.endswith("|json") else False
        )
        dbAcmeOrderless = self._focus()
        if wants_json:
            return {
                "AcmeOrderless": dbAcmeOrderless.as_json,
            }
        return {
            "project": "peter_sslers",
            "AcmeOrderless": dbAcmeOrderless,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_orderless:focus:update")
    @view_config(route_name="admin:acme_orderless:focus:update|json", renderer="json")
    def focus_update(self):
        wants_json = (
            True if self.request.matched_route.name.endswith("|json") else False
        )
        dbAcmeOrderless = self._focus()
        if self.request.method != "POST":
            if wants_json:
                return {"error": "This route requires a POST"}
            return HTTPSeeOther("%s?error=must+POST" % self._focus_url)

        _changes = []
        _post = self.request.POST
        for dbChallenge in dbAcmeOrderless.acme_orderless_challenges:
            _changed = None
            challenge_id = dbChallenge.id

            # token
            form_token = _post.get("%s_token" % challenge_id)
            if form_token != dbChallenge.token:
                dbChallenge.token = form_token
                _changed = True

            # keyauth
            form_keyauth = _post.get("%s_keyauth" % challenge_id)
            if form_keyauth != dbChallenge.keyauthorization:
                dbChallenge.keyauthorization = form_keyauth
                _changed = True

            # url
            form_url = _post.get("%s_url" % challenge_id)
            if form_url != dbChallenge.challenge_url:
                dbChallenge.challenge_url = form_url
                _changed = True

            if _changed:
                dbChallenge.timestamp_updated = ctx.timestamp
                _changes.append(dbChallenge)

        if wants_json:
            return {
                "AcmeOrderless": dbAcmeOrderless.as_json,
                "changed": True if _changes else False,
            }
        return HTTPSeeOther("%s?status=success" % self._focus_url)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_orderless:focus:deactivate")
    @view_config(
        route_name="admin:acme_orderless:focus:deactivate|json", renderer="json",
    )
    def focus_deactivate(self):
        wants_json = (
            True if self.request.matched_route.name.endswith("|json") else False
        )
        dbAcmeOrderless = self._focus()
        if self.request.method != "POST":
            if wants_json:
                return {"error": "This route requires a POST"}
            return HTTPSeeOther("%s?error=must+POST" % self._focus_url)
        # todo: use the api
        dbAcmeOrderless.is_active = False
        dbAcmeOrderless.timestamp_updated = self.request.api_context.timestamp
        self.request.api_context.dbSession.flush(objects=[dbAcmeOrderless])

        if wants_json:
            return {
                "result": "success",
                "dbAcmeOrderless": dbAcmeOrderless.as_json,
            }
        return HTTPSeeOther("%s?result=success" % self._focus_url)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_orderless:focus:add")
    @view_config(route_name="admin:acme_orderless:focus:add|json", renderer="json")
    def focus_add(self):
        wants_json = (
            True if self.request.matched_route.name.endswith("|json") else False
        )
        dbAcmeOrderless = self._focus()
        if self.request.method != "POST":
            if wants_json:
                return {"error": "This route requires a POST"}
            return HTTPSeeOther("%s?error=must+POST" % self._focus_url)

        _post = self.request.POST
        domain_name = _post.get("add_domain")
        if not domain_name:
            # todo: clenaup
            raise ValueError("must have a domain")

        (dbDomain, is_domain_added) = lib_db.getcreate.getcreate__Domain__by_domainName(
            self.request.api_context, domain_name
        )
        if not dbDomain:
            raise ValueError("invalid domain")

        token = _post.get("add_token")
        keyauthorization = _post.get("add_keyauthorization")
        challenge_url = _post.get("add_challenge_url")

        dbChallenge = lib_db.create.create__AcmeOrderlessChallenge(
            self.request.api_context,
            dbAcmeOrderless=dbAcmeOrderless,
            dbDomain=dbDomain,
            token=token,
            keyauthorization=keyauthorization,
            challenge_url=challenge_url,
        )

        if wants_json:
            return {
                "AcmeOrderless": dbAcmeOrderless.as_json,
                "changed": True if _changes else False,
            }
        return HTTPSeeOther("%s?status=success" % self._focus_url)


class ViewAdmin_Focus_Challenge(ViewAdmin_Focus):
    @view_config(
        route_name="admin:acme_orderless:focus:acme_orderless_challenge",
        renderer="/admin/acme_orderless-focus-acme_orderless_challenge.mako",
    )
    @view_config(
        route_name="admin:acme_orderless:focus:acme_orderless_challenge|json",
        renderer="json",
    )
    def focus(self):
        if not self.request.registry.settings["enable_acme_flow"]:
            raise HTTPNotFound("Acme-Flow is disabled on this system")
        wants_json = (
            True if self.request.matched_route.name.endswith("|json") else False
        )
        dbAcmeOrderless = self._focus()
        id_challenge = int(self.request.matchdict["id_challenge"])
        try:
            dbChallenge = [
                i
                for i in dbAcmeOrderless.acme_orderless_challenges
                if i.id == id_challenge
            ]
            if len(dbChallenge) != 1:
                raise ValueEror("invalid challenge")
            dbChallenge = dbChallenge[0]
        except:
            return HTTPSeeOther("%s?status=error" % self._focus_url)

        if wants_json:
            return {
                "AcmeOrderless": dbAcmeOrderless.as_json,
                "AcmeOrderlessChallenge": dbChallenge.as_json,
            }
        return {
            "project": "peter_sslers",
            "AcmeOrderless": dbAcmeOrderless,
            "AcmeOrderlessChallenge": dbChallenge,
        }
