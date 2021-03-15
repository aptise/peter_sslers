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
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
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


class View_List(Handler):
    @view_config(route_name="admin:queue_domains", renderer="/admin/queue_domains.mako")
    @view_config(
        route_name="admin:queue_domains_paginated", renderer="/admin/queue_domains.mako"
    )
    @view_config(route_name="admin:queue_domains|json", renderer="json")
    @view_config(route_name="admin:queue_domains_paginated|json", renderer="json")
    @view_config(
        route_name="admin:queue_domains:all", renderer="/admin/queue_domains.mako"
    )
    @view_config(
        route_name="admin:queue_domains:all_paginated",
        renderer="/admin/queue_domains.mako",
    )
    @view_config(route_name="admin:queue_domains:all|json", renderer="json")
    @view_config(route_name="admin:queue_domains:all_paginated|json", renderer="json")
    @docify(
        {
            "endpoint": "/queue-domains.json",
            "section": "queue-domain",
            "about": """list QueueDomain(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/queue-domains.json",
        }
    )
    @docify(
        {
            "endpoint": "/queue-domains/{PAGE}.json",
            "section": "queue-domain",
            "example": "curl {ADMIN_PREFIX}/queue-domains/1.json",
            "variant_of": "/queue-domains.json",
        }
    )
    @docify(
        {
            "endpoint": "/queue-domains/all.json",
            "section": "queue-domain",
            "about": """list QueueDomain(s): All""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/queue-domains/all.json",
        }
    )
    @docify(
        {
            "endpoint": "/queue-domains/all/{PAGE}.json",
            "section": "queue-domain",
            "example": "curl {ADMIN_PREFIX}/queue-domains/all/1.json",
            "variant_of": "/queue-domains/all.json",
        }
    )
    def list(self):
        wants_all = (
            True
            if self.request.matched_route.name
            in (
                "admin:queue_domains:all",
                "admin:queue_domains:all_paginated",
                "admin:queue_domains:all|json",
                "admin:queue_domains:all_paginated|json",
            )
            else False
        )
        sidenav_option = "unprocessed"
        unprocessed_only = True
        show_all = None
        if wants_all:
            sidenav_option = "all"
            unprocessed_only = False
            show_all = True

        if wants_all:
            url_template = (
                "%s/queue-domains/all/{0}"
                % self.request.registry.settings["app_settings"]["admin_prefix"]
            )
        else:
            url_template = (
                "%s/queue-domains/{0}"
                % self.request.registry.settings["app_settings"]["admin_prefix"]
            )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        items_count = lib_db.get.get__QueueDomain__count(
            self.request.api_context,
            show_all=show_all,
            unprocessed_only=unprocessed_only,
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__QueueDomain__paginated(
            self.request.api_context,
            show_all=show_all,
            unprocessed_only=unprocessed_only,
            limit=items_per_page,
            offset=offset,
        )
        if self.request.wants_json:
            _domains = {d.id: d.as_json for d in items_paged}
            return {
                "QueueDomains": _domains,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "QueueDomains_count": items_count,
            "QueueDomains": items_paged,
            "sidenav_option": sidenav_option,
            "pager": pager,
        }


class View_New(Handler):
    @view_config(route_name="admin:queue_domains:add")
    @view_config(route_name="admin:queue_domains:add|json", renderer="json")
    @docify(
        {
            "endpoint": "/queue-domains/add.json",
            "section": "queue-domain",
            "about": """Add QueueDomain(s)""",
            "POST": True,
            "GET": None,
            "example": "curl {ADMIN_PREFIX}/queue-domains/add.json",
            "instructions": """POST `domain_names_http01""",
            "form_fields": {"domain_names_http01": "required"},
        }
    )
    def add(self):
        if self.request.method == "POST":
            return self._add__submit()
        return self._add__print()

    def _add__print(self):
        if self.request.wants_json:
            return formatted_get_docs(self, "/queue-domains/add.json")
        return render_to_response("/admin/queue_domains-add.mako", {}, self.request)

    def _add__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_QueueDomains_add, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            domains_challenged = form_utils.form_domains_challenge_typed(
                self.request,
                formStash,
                http01_only=True,
            )

            queue_results = lib_db.queues.queue_domains__add(
                self.request.api_context, domains_challenged["http-01"]
            )

            if self.request.wants_json:
                return {"result": "success", "domains": queue_results}
            results_json = json.dumps(queue_results, sort_keys=True)
            return HTTPSeeOther(
                "%s/queue-domains?result=success&operation=add&results=%s"
                % (
                    self.request.registry.settings["app_settings"]["admin_prefix"],
                    quote_plus(results_json),
                )
            )

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._add__print)


class View_Process(Handler):
    @view_config(route_name="admin:queue_domains:process", renderer=None)
    @view_config(route_name="admin:queue_domains:process|json", renderer="json")
    @docify(
        {
            "endpoint": "/queue-domains/process.json",
            "section": "queue-domain",
            "about": """Process QueueDomain(s)""",
            "POST": True,
            "GET": None,
            "example": "curl {ADMIN_PREFIX}/queue-domains/process.json",
            "form_fields": {
                "processing_strategy": "How should the order be processed?",
                "account_key_option": "How is the AcmeAccount specified?",
                "account_key_global_default": "pem_md5 of the Global Default account key. Must/Only submit if `account_key_option==account_key_global_default`",
                "account_key_existing": "pem_md5 of any key. Must/Only submit if `account_key_option==account_key_existing`",
                "account_key_file_pem": "pem of the account key file. Must/Only submit if `account_key_option==account_key_file`",
                "acme_account_provider_id": "account provider. Must/Only submit if `account_key_option==account_key_file` and `account_key_file_pem` is used.",
                "account_key_file_le_meta": "LetsEncrypt Certbot file. Must/Only submit if `account_key_option==account_key_file` and `account_key_file_pem` is not used",
                "account_key_file_le_pkey": "LetsEncrypt Certbot file",
                "account_key_file_le_reg": "LetsEncrypt Certbot file",
                "private_key_option": "How is the PrivateKey being specified?",
                "private_key_existing": "pem_md5 of existing key",
                "private_key_file_pem": "pem to upload",
                "private_key_cycle__renewal": "how should the PrivateKey be cycled on renewals?",
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
                "acme_account_provider_id": "{RENDER_ON_REQUEST}",
                "account_key_option": model_utils.AcmeAccontKey_options_a,
                "processing_strategy": model_utils.AcmeOrder_ProcessingStrategy.OPTIONS_ALL,
                "private_key_option": model_utils.PrivateKey_options_a,
                "AcmeAccount_GlobalDefault": "{RENDER_ON_REQUEST}",
                "private_key_cycle__renewal": model_utils.PrivateKeyCycle._options_AcmeOrder_private_key_cycle,
            },
            "requirements": [
                "Submit corresponding field(s) to account_key_option. If `account_key_file` is your intent, submit either PEM+ProviderID or the three LetsEncrypt Certbot files."
            ],
            "notes": [
                "`extra` will contain a dict with the current count and next 100 items",
            ],
        }
    )
    def process(self):
        self._load_AcmeAccount_GlobalDefault()
        self._load_AcmeAccountProviders()

        self.QueueDomains_count = lib_db.get.get__QueueDomain__count(
            self.request.api_context,
            show_all=False,
            unprocessed_only=True,
        )

        if self.request.method == "POST":
            return self._process__submit()
        return self._process__print()

    def _process__print(self):
        queue_items = []
        if self.QueueDomains_count:
            queue_items = lib_db.get.get__QueueDomain__paginated(
                self.request.api_context,
                show_all=False,
                unprocessed_only=True,
                limit=100,
                offset=0,
            )
        if self.request.wants_json:
            docs = formatted_get_docs(self, "/queue-domains/process.json")
            docs["extra"] = {
                "queue.count": self.QueueDomains_count,
                "queue.items_100": [i.as_json for i in queue_items],
            }
            return docs

        return render_to_response(
            "/admin/queue_domains-process.mako",
            {
                "AcmeAccount_GlobalDefault": self.dbAcmeAccount_GlobalDefault,
                "AcmeAccountProviders": self.dbAcmeAccountProviders,
                "QueueDomain_Count": self.QueueDomains_count,
                "QueueDomain_100": queue_items,
            },
            self.request,
        )

    def _process__submit(self):
        try:
            if not self.QueueDomains_count:
                raise errors.DisplayableError("No items in the Domain Queue to process")

            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_QueueDomains_process, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            processing_strategy = formStash.results["processing_strategy"]
            private_key_cycle__renewal = formStash.results["private_key_cycle__renewal"]
            max_domains_per_certificate = formStash.results[
                "max_domains_per_certificate"
            ]

            (acmeAccountSelection, privateKeySelection) = form_utils.form_key_selection(
                self.request,
                formStash,
                require_contact=None,
            )

            dbAcmeOrder = lib_db.queues.queue_domains__process(
                self.request.api_context,
                dbAcmeAccount=acmeAccountSelection.AcmeAccount,
                dbPrivateKey=privateKeySelection.PrivateKey,
                private_key_strategy__requested=privateKeySelection.private_key_strategy__requested,
                processing_strategy=processing_strategy,
                private_key_cycle__renewal=private_key_cycle__renewal,
                max_domains_per_certificate=max_domains_per_certificate,
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "AcmeOrder": dbAcmeOrder.as_json,
                }
            return HTTPSeeOther(
                "%s/queue-domains?result=success&operation=processed&acme-order-id=%s"
                % (
                    self.request.registry.settings["app_settings"]["admin_prefix"],
                    dbAcmeOrder.id,
                )
            )
        except (
            errors.AcmeError,
            errors.DisplayableError,
            errors.DomainVerificationError,
        ) as exc:
            # return, don't raise
            # we still commit the bookkeeping
            if self.request.wants_json:
                return {"result": "error", "error": exc.as_querystring}
            return HTTPSeeOther(
                "%s/queue-domains?result=error&error=%s&operation=processed"
                % (
                    self.request.registry.settings["app_settings"]["admin_prefix"],
                    exc.as_querystring,
                )
            )
        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._process__print)

        except Exception as exc:
            self.request.api_context.pyramid_transaction_rollback()
            if self.request.wants_json:
                return {"result": "error", "error": str(exc)}
            raise


class View_Focus(Handler):
    dbQueueDomain = None

    def _focus(self):
        if self.dbQueueDomain is None:
            dbQueueDomain = lib_db.get.get__QueueDomain__by_id(
                self.request.api_context,
                self.request.matchdict["id"],
                eagerload_log=True,
            )
            if not dbQueueDomain:
                raise HTTPNotFound("the item was not found")
            self.dbQueueDomain = dbQueueDomain
            self._focus_item = dbQueueDomain
            self._focus_url = "%s/queue-domain/%s" % (
                self.request.registry.settings["app_settings"]["admin_prefix"],
                self.dbQueueDomain.id,
            )
        return self.dbQueueDomain

    @view_config(
        route_name="admin:queue_domain:focus", renderer="/admin/queue_domain-focus.mako"
    )
    @view_config(route_name="admin:queue_domain:focus|json", renderer="json")
    @docify(
        {
            "endpoint": "/queue-domain/{ID}.json",
            "section": "queue-domain",
            "about": """queue-domain focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/queue-domain/1.json",
        }
    )
    def focus(self):
        dbQueueDomain = self._focus()
        if self.request.wants_json:
            return {"result": "success", "QueueDomain": dbQueueDomain.as_json}
        return {"project": "peter_sslers", "QueueDomain": dbQueueDomain}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:queue_domain:focus:mark", renderer=None)
    @view_config(route_name="admin:queue_domain:focus:mark|json", renderer="json")
    @docify(
        {
            "endpoint": "/queue-domain/{ID}/mark.json",
            "section": "queue-domain",
            "about": """QueueDomain focus: mark""",
            "POST": True,
            "GET": None,
            "example": "curl {ADMIN_PREFIX}/queue-domain/1/mark.json",
            "instructions": [
                """curl --form 'action=active' {ADMIN_PREFIX}/queue-domain/1/mark.json""",
            ],
            "form_fields": {"action": "the intended action"},
            "valid_options": {"action": ["cancel"]},
        }
    )
    def focus_mark(self):
        dbQueueDomain = self._focus()
        if self.request.method == "POST":
            return self._focus_mark__submit(dbQueueDomain)
        return self._focus_mark__print(dbQueueDomain)

    def _focus_mark__print(self, dbQueueDomain):
        if self.request.wants_json:
            return formatted_get_docs(self, "/queue-domain/{ID}/mark.json")
        url_post_required = "%s?result=error&error=post+required&operation=mark" % (
            self._focus_url
        )
        return HTTPSeeOther(url_post_required)

    def _focus_mark__submit(self, dbQueueDomain):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_QueueDomain_mark, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            action = formStash.results["action"]
            event_type = model_utils.OperationsEventType.from_string(
                "QueueDomain__mark"
            )
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["queue_domain.id"] = dbQueueDomain.id
            event_payload_dict["action"] = formStash.results["action"]

            # bookkeeping
            dbOperationsEvent = lib_db.logger.log__OperationsEvent(
                self.request.api_context, event_type, event_payload_dict
            )

            event_status = False
            if action == "cancel":
                if not dbQueueDomain.is_active:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(field="action", message="Already cancelled")

                lib_db.update.update_QueuedDomain_dequeue(
                    self.request.api_context,
                    dbQueueDomain,
                    dbOperationsEvent=dbOperationsEvent,
                    event_status="QueueDomain__mark__cancelled",
                    action="de-queued",
                )
            else:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(field="action", message="invalid `action")

            self.request.api_context.dbSession.flush(
                objects=[dbQueueDomain, dbOperationsEvent]
            )

            if self.request.wants_json:
                return {"result": "success", "QueueDomain": dbQueueDomain.as_json}

            url_success = "%s?result=success&operation=mark&action=%s" % (
                self._focus_url,
                action,
            )
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            url_failure = "%s?result=error&error=%s&operation=mark&action=%s" % (
                self._focus_url,
                errors.formstash_to_querystring(formStash),
                action,
            )
            raise HTTPSeeOther(url_failure)
