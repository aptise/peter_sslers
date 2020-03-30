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
from ..lib.forms import Form_AcmeOrderless_AcmeChallenge_add
from ..lib.forms import Form_AcmeOrderless_new
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...model import utils as model_utils
from ...model import objects as model_objects


# ==============================================================================


class ViewAdmin_List(Handler):
    @view_config(
        route_name="admin:acme_orderlesss", renderer="/admin/acme_orderlesss.mako",
    )
    @view_config(
        route_name="admin:acme_orderlesss_paginated",
        renderer="/admin/acme_orderlesss.mako",
    )
    @view_config(
        route_name="admin:acme_orderlesss|json", renderer="json",
    )
    @view_config(
        route_name="admin:acme_orderlesss_paginated|json", renderer="json",
    )
    def list(self):
        if not self.request.registry.settings["app_settings"]["enable_acme_flow"]:
            raise HTTPNotFound("Acme-Flow is disabled on this system")
        items_count = lib_db.get.get__AcmeOrderless__count(self.request.api_context)
        (pager, offset) = self._paginate(
            items_count,
            url_template="%s/acme-orderlesss/{0}"
            % self.request.registry.settings["app_settings"]["admin_prefix"],
        )
        items_paged = lib_db.get.get__AcmeOrderless__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        if self.request.wants_json:
            _keys = {k.id: k.as_json for k in items_paged}
            return {
                "AcmeOrderless": _keys,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "AcmeOrderlesss_count": items_count,
            "AcmeOrderlesss": items_paged,
            "pager": pager,
        }


class ViewAdmin_New(Handler):
    @view_config(route_name="admin:acme_orderless:new")
    @view_config(route_name="admin:acme_orderless:new|json", renderer="json")
    def new_AcmeOrderless(self):
        if not self.request.registry.settings["app_settings"]["enable_acme_flow"]:
            raise HTTPNotFound("Acme-Flow is disabled on this system")

        self._load_AcmeAccountKey_GlobalDefault()
        self._load_AcmeAccountProviders()

        if self.request.method == "POST":
            return self._new_AcmeOrderless__submit()
        return self._new_AcmeOrderless__print()

    def _new_AcmeOrderless__print(self):
        if self.request.wants_json:
            return {
                "instructions": [
                    """curl --form 'domain_names=@domain_names' %s/acme-orderless/new.json"""
                    % self.request.registry.settings["app_settings"]["admin_prefix"]
                ],
                "form_fields": {
                    "domain_names": "a comma separated list of domain names"
                },
                "notes": [
                    "You can configure the challenges and add domain names to an existing AcmeOrderless"
                ],
            }
        return render_to_response(
            "/admin/acme_orderless-new.mako",
            {
                "AcmeAccountKey_GlobalDefault": self.dbAcmeAccountKey_GlobalDefault,
                "AcmeAccountProviders": self.dbAcmeAccountProviders,
            },
            self.request,
        )

    def _new_AcmeOrderless__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_AcmeOrderless_new, validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            domain_names = utils.domains_from_string(formStash.results["domain_names"])
            if not domain_names:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(
                    field="domain_names", message="missing valid domain names"
                )

            accountKeySelection = form_utils.parse_AccountKeySelection(
                self.request,
                formStash,
                seek_selected=formStash.results["account_key_option"],
            )
            if accountKeySelection.selection == "upload":
                key_create_args = accountKeySelection.upload_parsed.getcreate_args
                key_create_args["event_type"] = "AcmeAccountKey__insert"
                key_create_args[
                    "acme_account_key_source_id"
                ] = model_utils.AcmeAccountKeySource.from_string("imported")
                (
                    _dbAcmeAccountKey,
                    _is_created,
                ) = lib_db.getcreate.getcreate__AcmeAccountKey(
                    self.request.api_context, **key_create_args
                )
                accountKeySelection.AcmeAccountKey = _dbAcmeAccountKey

            dbAcmeAccountKey = accountKeySelection.AcmeAccountKey

            try:
                dbAcmeOrderless = lib_db.create.create__AcmeOrderless(
                    self.request.api_context,
                    domain_names=domain_names,
                    dbAcmeAccountKey=dbAcmeAccountKey,
                )
            except errors.AcmeDuplicateChallenges as exc:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_form(message=exc.as_querystring)

            if self.request.wants_json:
                return {
                    "result": "success",
                    "AcmeOrderless": dbAcmeOrderless.as_json,
                }

            return HTTPSeeOther(
                "%s/acme-orderless/%s"
                % (
                    self.request.registry.settings["app_settings"]["admin_prefix"],
                    dbAcmeOrderless.id,
                )
            )

        except formhandling.FormInvalid as exc:
            return formhandling.form_reprint(
                self.request, self._new_AcmeOrderless__print
            )


class ViewAdmin_Focus(Handler):

    _dbAcmeOrderless = None

    def _focus(self, eagerload_web=False):
        self._dbAcmeOrderless = dbAcmeOrderless = lib_db.get.get__AcmeOrderless__by_id(
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

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _focus_print(self):
        if self._dbAcmeOrderless is None:
            self._focus()
        return render_to_response(
            "/admin/acme_orderless-focus.mako",
            {"AcmeOrderless": self._dbAcmeOrderless,},
            self.request,
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_orderless:focus",
        renderer="/admin/acme_orderless-focus.mako",
    )
    @view_config(route_name="admin:acme_orderless:focus|json", renderer="json")
    def focus(self):
        if not self.request.registry.settings["app_settings"]["enable_acme_flow"]:
            raise HTTPNotFound("Acme-Flow is disabled on this system")
        dbAcmeOrderless = self._focus()
        if self.request.wants_json:
            return {
                "AcmeOrderless": dbAcmeOrderless.as_json,
            }
        return self._focus_print()


class ViewAdmin_Focus_Manipulate(ViewAdmin_Focus):
    @view_config(route_name="admin:acme_orderless:focus:update")
    @view_config(route_name="admin:acme_orderless:focus:update|json", renderer="json")
    def focus_update(self):
        dbAcmeOrderless = self._focus()
        if self.request.method != "POST":
            if self.request.wants_json:
                return {"error": "This route requires a POST"}
            return HTTPSeeOther("%s?result=error&error=must+POST" % self._focus_url)

        _changes = []
        _post = self.request.POST
        for dbChallenge in dbAcmeOrderless.acme_challenges:
            _changed = None
            challenge_id = dbChallenge.id

            # token
            form_token = _post.get("%s_token" % challenge_id)
            if form_token != dbChallenge.token:
                dbChallenge.token = form_token
                _changed = True

            # keyauth
            form_keyauth = _post.get("%s_keyauthorization" % challenge_id)
            if form_keyauth != dbChallenge.keyauthorization:
                dbChallenge.keyauthorization = form_keyauth
                _changed = True

            # url
            if dbAcmeOrderless.acme_account_key_id:
                form_url = _post.get("%s_url" % challenge_id)
                if form_url != dbChallenge.challenge_url:
                    dbChallenge.challenge_url = form_url
                    _changed = True

            if _changed:
                dbChallenge.timestamp_updated = self.request.api_context.timestamp
                _changes.append(dbChallenge)

        if self.request.wants_json:
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
        dbAcmeOrderless = self._focus()
        if self.request.method != "POST":
            if self.request.wants_json:
                return {"error": "This route requires a POST"}
            return HTTPSeeOther("%s?result=error&error=must+POST" % self._focus_url)

        # todo: use the api
        dbAcmeOrderless.is_processing = False
        dbAcmeOrderless.timestamp_updated = self.request.api_context.timestamp
        self.request.api_context.dbSession.flush(objects=[dbAcmeOrderless])

        if self.request.wants_json:
            return {
                "result": "success",
                "AcmeOrderless": dbAcmeOrderless.as_json,
            }
        return HTTPSeeOther("%s?result=success" % self._focus_url)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_orderless:focus:add")
    @view_config(route_name="admin:acme_orderless:focus:add|json", renderer="json")
    def focus_add(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_AcmeOrderless_AcmeChallenge_add,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            dbAcmeOrderless = self._focus()
            if self.request.method != "POST":
                # `formStash.fatal_form()` will raise `FormInvalid()`
                formStash.fatal_form("This route requires a POST")

            _post = self.request.POST
            if not formStash.results["domain"]:
                formStash.fatal_field(field="domain", message="A Domain is required")
            domain_names = utils.domains_from_string(formStash.results["domain"])
            if len(domain_names) != 1:
                formStash.fatal_field(
                    field="domain", message="A valid Domain is required"
                )
            domain_name = domain_names[0]

            (
                dbDomain,
                is_domain_added,
            ) = lib_db.getcreate.getcreate__Domain__by_domainName(
                self.request.api_context, domain_name
            )
            if not dbDomain:
                formStash.fatal_field(field="domain", message="invalid domain")

            # okay, what if the domain is already IN this orderless?
            orderless_domain_ids = [
                dbChallenge.domain_id for dbChallenge in dbAcmeOrderless.acme_challenges
            ]
            if dbDomain.id in orderless_domain_ids:
                formStash.fatal_field(
                    field="domain",
                    message="This domain is already configured for this AcmeOrderless.",
                )

            create_kwargs = {
                "dbAcmeOrderless": dbAcmeOrderless,
                "dbDomain": dbDomain,
                "token": formStash.results["token"],
                "keyauthorization": formStash.results["keyauthorization"],
            }
            if dbAcmeOrderless.acme_account_key_id:
                create_kwargs["challenge_url"] = formStash.results["challenge_url"]

            dbChallenge = lib_db.create.create__AcmeChallenge(
                self.request.api_context, **create_kwargs
            )

            if self.request.wants_json:
                return {
                    "AcmeOrderless": dbAcmeOrderless.as_json,
                }
            return HTTPSeeOther("%s?status=success" % self._focus_url)

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._focus_print)


class ViewAdmin_Focus_Challenge(ViewAdmin_Focus):
    @view_config(
        route_name="admin:acme_orderless:focus:acme_challenge",
        renderer="/admin/acme_orderless-focus-acme_challenge.mako",
    )
    @view_config(
        route_name="admin:acme_orderless:focus:acme_challenge|json", renderer="json",
    )
    def focus(self):
        if not self.request.registry.settings["app_settings"]["enable_acme_flow"]:
            raise HTTPNotFound("Acme-Flow is disabled on this system")
        dbAcmeOrderless = self._focus()
        id_challenge = int(self.request.matchdict["id_challenge"])
        try:
            dbChallenge = [
                i for i in dbAcmeOrderless.acme_challenges if i.id == id_challenge
            ]
            if len(dbChallenge) != 1:
                raise ValueError("invalid challenge")
            dbChallenge = dbChallenge[0]
        except:
            return HTTPSeeOther("%s?status=error" % self._focus_url)

        if self.request.wants_json:
            return {
                "AcmeOrderless": dbAcmeOrderless.as_json,
                "AcmeChallenge": dbChallenge.as_json,
            }
        return {
            "project": "peter_sslers",
            "AcmeOrderless": dbAcmeOrderless,
            "AcmeChallenge": dbChallenge,
        }
