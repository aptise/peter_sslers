import logging

log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


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


class View_List(Handler):
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
        url_template = (
            "%s/acme-orderlesss/{0}"
            % self.request.registry.settings["app_settings"]["admin_prefix"]
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template)
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


class View_New(Handler):
    @view_config(route_name="admin:acme_orderless:new")
    @view_config(route_name="admin:acme_orderless:new|json", renderer="json")
    def new_AcmeOrderless(self):
        if not self.request.registry.settings["app_settings"]["enable_acme_flow"]:
            raise HTTPNotFound("Acme-Flow is disabled on this system")

        self._load_AcmeAccount_GlobalDefault()
        self._load_AcmeAccountProviders()

        if self.request.method == "POST":
            return self._new_AcmeOrderless__submit()
        return self._new_AcmeOrderless__print()

    def _new_AcmeOrderless__print(self):
        if self.request.wants_json:
            return {
                "instructions": [
                    """curl --form 'domain_names_http01=@domain_names' 'account_key_option=none' %s/acme-orderless/new.json"""
                    % self.request.registry.settings["app_settings"]["admin_prefix"]
                ],
                "form_fields": {
                    "domain_names_http01": "a comma separated list of domain names for http01 challenge",
                    "account_key_option": "How is the AcmeAccount specified?",
                    "account_key_reuse": "pem_md5 of the existing account key. Must/Only submit if `account_key_option==account_key_reuse`",
                    "account_key_global_default": "pem_md5 of the Global Default account key. Must/Only submit if `account_key_option==account_key_global_default`",
                    "account_key_existing": "pem_md5 of any key. Must/Only submit if `account_key_option==account_key_existing`",
                    "account_key_file_pem": "pem of the account key file. Must/Only submit if `account_key_option==account_key_file`",
                    "acme_account_provider_id": "account provider. Must/Only submit if `account_key_option==account_key_file` and `account_key_file_pem` is used.",
                    "account_key_file_le_meta": "LetsEncrypt Certbot file. Must/Only submit if `account_key_option==account_key_file` and `account_key_file_pem` is not used",
                    "account_key_file_le_pkey": "LetsEncrypt Certbot file",
                    "account_key_file_le_reg": "LetsEncrypt Certbot file",
                },
                "form_fields_related": [
                    ["account_key_file_pem", "acme_account_provider_id"],
                    [
                        "account_key_file_le_meta",
                        "account_key_file_le_pkey",
                        "account_key_file_le_reg",
                    ],
                ],
                "valid_options": {
                    "acme_account_provider_id": {
                        i.id: "%s (%s)" % (i.name, i.url)
                        for i in self.dbAcmeAccountProviders
                    },
                    "account_key_option": model_utils.AcmeAccontKey_options_c,
                    "AcmeAccount_GlobalDefault": self.dbAcmeAccount_GlobalDefault.as_json
                    if self.dbAcmeAccount_GlobalDefault
                    else None,
                },
                "requirements": [
                    "Submit corresponding field(s) to account_key_option. If `account_key_file` is your intent, submit either PEM+ProviderID or the three LetsEncrypt Certbot files."
                ],
                "notes": [
                    "You can configure the challenges and add domain names to an existing AcmeOrderless"
                ],
            }
        return render_to_response(
            "/admin/acme_orderless-new.mako",
            {
                "AcmeAccount_GlobalDefault": self.dbAcmeAccount_GlobalDefault,
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

            domains_challenged = form_utils.form_domains_challenge_typed(
                self.request, formStash, http01_only=True,
            )

            acmeAccountSelection = form_utils.parse_AcmeAccountSelection(
                self.request,
                formStash,
                account_key_option=formStash.results["account_key_option"],
                require_contact=None,
                allow_none=True,
            )
            if acmeAccountSelection.selection == "upload":
                key_create_args = acmeAccountSelection.upload_parsed.getcreate_args
                key_create_args["event_type"] = "AcmeAccount__insert"
                key_create_args[
                    "acme_account_key_source_id"
                ] = model_utils.AcmeAccountKeySource.from_string("imported")
                (
                    _dbAcmeAccount,
                    _is_created,
                ) = lib_db.getcreate.getcreate__AcmeAccount(
                    self.request.api_context, **key_create_args
                )
                acmeAccountSelection.AcmeAccount = _dbAcmeAccount

            dbAcmeAccount = acmeAccountSelection.AcmeAccount
            try:
                dbAcmeOrderless = lib_db.create.create__AcmeOrderless(
                    self.request.api_context,
                    domains_challenged=domains_challenged,
                    dbAcmeAccount=dbAcmeAccount,
                )
            except errors.AcmeDomainsBlocklisted as exc:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(field="domain_names_http01", message=str(exc))
            except errors.AcmeDuplicateChallenges as exc:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_form(message=str(exc))
            except Exception as exc:
                log.critical("create__AcmeOrderless: %s", exc)
                raise

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
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(
                self.request, self._new_AcmeOrderless__print
            )


class View_Focus(Handler):

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
        if self.request.wants_json:
            resp = {
                "AcmeOrderless": self._dbAcmeOrderless.as_json,
                "forms": {},
            }
            if self._dbAcmeOrderless.is_processing:
                resp["forms"]["acmeorderless-update"] = {
                    "_url": "%s/update.json" % self._focus_url,
                    "_challenges": [],
                }
                for challenge in self._dbAcmeOrderless.acme_challenges:
                    resp["forms"]["acmeorderless-update"]["_challenges"].append(
                        str(challenge.id)
                    )
                    if self._dbAcmeOrderless.acme_account_id:
                        resp["forms"]["acmeorderless-update"][
                            "%s_url" % challenge.id
                        ] = (challenge.challenge_url or "")
                    resp["forms"]["acmeorderless-update"][
                        "%s_keyauthorization" % challenge.id
                    ] = (challenge.keyauthorization or "")
                    resp["forms"]["acmeorderless-update"]["%s_token" % challenge.id] = (
                        challenge.token or ""
                    )
                    resp["forms"]["acmeorderless-update"][
                        "%s_domain" % challenge.id
                    ] = (challenge.domain_name or "")
                resp["forms"]["acmeorderless-update"]["_challenges"] = ",".join(
                    resp["forms"]["acmeorderless-update"]["_challenges"]
                )
                resp["forms"]["acmeorderless-add_challenge"] = {
                    "_url": "%s/add.json" % self._focus_url,
                    "acme_challenge_type": "",
                    "keyauthorization": "",
                    "domain": "",
                    "token": "",
                }
                resp["forms"]["acmeorderless-deactivate"] = {
                    "_url": "%s/deactivate.json" % self._focus_url,
                }
            return resp
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
        return self._focus_print()


class View_Focus_Manipulate(View_Focus):
    @view_config(route_name="admin:acme_orderless:focus:update")
    @view_config(route_name="admin:acme_orderless:focus:update|json", renderer="json")
    def update(self):
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
            if form_token is not None:
                if form_token != dbChallenge.token:
                    dbChallenge.token = form_token
                    _changed = True

            # keyauth
            form_keyauth = _post.get("%s_keyauthorization" % challenge_id)
            if form_keyauth is not None:
                if form_keyauth != dbChallenge.keyauthorization:
                    dbChallenge.keyauthorization = form_keyauth
                    _changed = True

            # url
            if dbAcmeOrderless.acme_account_id:
                form_url = _post.get("%s_url" % challenge_id)
                if form_url is not None:
                    if form_url != dbChallenge.challenge_url:
                        dbChallenge.challenge_url = form_url
                        _changed = True

            if _changed:
                dbChallenge.timestamp_updated = self.request.api_context.timestamp
                _changes.append(dbChallenge)

        if self.request.wants_json:
            return {
                "result": "success",
                "AcmeOrderless": dbAcmeOrderless.as_json,
                "changed": True if _changes else False,
            }
        return HTTPSeeOther("%s?result=success" % self._focus_url)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_orderless:focus:deactivate")
    @view_config(
        route_name="admin:acme_orderless:focus:deactivate|json", renderer="json",
    )
    def deactivate(self):
        dbAcmeOrderless = self._focus()
        if self.request.method != "POST":
            if self.request.wants_json:
                return {"error": "This route requires a POST"}
            return HTTPSeeOther("%s?result=error&error=must+POST" % self._focus_url)

        if not dbAcmeOrderless.is_processing:
            if self.request.wants_json:
                return {
                    "result": "error",
                    "error": "already deactivated",
                    "AcmeOrderless": dbAcmeOrderless.as_json,
                }
            return HTTPSeeOther(
                "%s?result=error&error=already+deactivated&operation=mark&action=deactivate"
                % self._focus_url
            )

        lib_db.update.update_AcmeOrderless_deactivate(
            self.request.api_context, dbAcmeOrderless
        )

        if self.request.wants_json:
            return {
                "result": "success",
                "AcmeOrderless": dbAcmeOrderless.as_json,
            }
        return HTTPSeeOther("%s?result=success" % self._focus_url)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_orderless:focus:add")
    @view_config(route_name="admin:acme_orderless:focus:add|json", renderer="json")
    def add_challenge(self):
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

            # this function checks the domain names match a simple regex
            domain_names = utils.domains_from_string(formStash.results["domain"])
            if len(domain_names) != 1:
                formStash.fatal_field(
                    field="domain", message="A valid Domain is required"
                )
            domain_name = domain_names[0]

            _dbDomainBlocklisted = lib_db.get.get__DomainBlocklisted__by_name(
                self.request.api_context, domain_name
            )
            if _dbDomainBlocklisted:
                # errors.AcmeDomainsBlocklisted
                formStash.fatal_field(
                    field="domain", message="This domain is blocklisted.",
                )

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

            acme_challenge_type_id = model_utils.AcmeChallengeType.from_string(
                formStash.results["acme_challenge_type"]
            )
            create_kwargs = {
                "dbAcmeOrderless": dbAcmeOrderless,
                "dbDomain": dbDomain,
                "token": formStash.results["token"],
                "keyauthorization": formStash.results["keyauthorization"],
                "acme_challenge_type_id": acme_challenge_type_id,
            }
            if dbAcmeOrderless.acme_account_id:
                create_kwargs["challenge_url"] = formStash.results["challenge_url"]

            dbChallenge = lib_db.create.create__AcmeChallenge(
                self.request.api_context, **create_kwargs
            )

            if self.request.wants_json:
                # expire this so the updates appear
                self.request.dbSession.expire(dbAcmeOrderless)
                return {
                    "result": "success",
                    "AcmeOrderless": dbAcmeOrderless.as_json,
                }
            return HTTPSeeOther("%s?result=success" % self._focus_url)

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._focus_print)


class View_Focus_Challenge(View_Focus):
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
            return HTTPSeeOther("%s?result=error" % self._focus_url)

        if self.request.wants_json:
            return {
                "result": "success",
                "AcmeOrderless": dbAcmeOrderless.as_json,
                "AcmeChallenge": dbChallenge.as_json,
            }
        return {
            "project": "peter_sslers",
            "AcmeOrderless": dbAcmeOrderless,
            "AcmeChallenge": dbChallenge,
        }
