# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPSeeOther

# stdlib
import datetime
import json
import pdb

# pypi
import six
import sqlalchemy

# localapp
from .. import lib
from ..lib import docs
from ..lib import formhandling
from ..lib.forms import Form_API_Domain_enable
from ..lib.forms import Form_API_Domain_disable
from ..lib.forms import Form_API_Domain_certificate_if_needed
from ..lib import form_utils as form_utils
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...lib import utils_nginx
from ...lib import utils_redis
from ...model import objects as model_objects
from ...model import utils as model_utils


# ==============================================================================


class ViewAdminApi(Handler):

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api", renderer="/admin/api.mako")
    def index(self):
        return {
            "project": "peter_sslers",
            "api_endpoints": docs.api_endpoints,
            "json_capable": docs.json_capable,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:ca_certificate_probes:probe", renderer=None)
    @view_config(
        route_name="admin:api:ca_certificate_probes:probe|json", renderer="json"
    )
    def ca_certificate_probes__probe(self):
        if self.request.wants_json:
            if self.request.method != "POST":
                return docs.json_docs_post_only

        operations_event = lib_db.actions.ca_certificate_probe(self.request.api_context)

        if self.request.wants_json:
            return {
                "result": "success",
                "operations_event": {
                    "id": operations_event.id,
                    "is_certificates_discovered": operations_event.event_payload_json[
                        "is_certificates_discovered"
                    ],
                    "is_certificates_updated": operations_event.event_payload_json[
                        "is_certificates_updated"
                    ],
                },
            }
        return HTTPSeeOther(
            "%s/operations/ca-certificate-probes?result=success&event.id=%s"
            % (
                self.request.registry.settings["app_settings"]["admin_prefix"],
                operations_event.id,
            )
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:deactivate_expired", renderer=None)
    @view_config(route_name="admin:api:deactivate_expired|json", renderer="json")
    def deactivate_expired(self):
        if self.request.wants_json:
            if self.request.method != "POST":
                return docs.json_docs_post_only

        operations_event = lib_db.actions.operations_deactivate_expired(
            self.request.api_context
        )
        count_deactivated = operations_event.event_payload_json["count_deactivated"]
        rval = {
            "ServerCertificate": {"expired": count_deactivated,},
            "result": "success",
            "operations_event": operations_event.id,
        }

        if self.request.wants_json:
            return rval

        return HTTPSeeOther(
            "%s/operations/log?result=success&event.id=%s"
            % (
                self.request.registry.settings["app_settings"]["admin_prefix"],
                operations_event.id,
            )
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:update_recents", renderer=None)
    @view_config(route_name="admin:api:update_recents|json", renderer="json")
    def update_recents(self):
        if self.request.wants_json:
            if self.request.method != "POST":
                return docs.json_docs_post_only
        operations_event = lib_db.actions.operations_update_recents(
            self.request.api_context
        )
        if self.request.wants_json:
            return {"result": "success", "operations_event": operations_event.id}
        return HTTPSeeOther(
            "%s/operations/log?result=success&event.id=%s"
            % (
                self.request.registry.settings["app_settings"]["admin_prefix"],
                operations_event.id,
            )
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:domain:enable", renderer="json")
    def domain_enable(self):
        if self.request.method == "POST":
            return self._domain_enable__submit()
        return self._domain_enable__print()

    def _domain_enable__print(self):
        return {
            "instructions": """Submit `domain_names` via `POST`""",
            "form_fields": {
                "domain_names": "[required] a comma separated list of fully qualified domain names."
            },
        }

    def _domain_enable__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_API_Domain_enable, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            # this function checks the domain names match a simple regex
            domain_names = utils.domains_from_string(formStash.results["domain_names"])
            if not domain_names:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(
                    field="domain_names", message="Found no domain names"
                )
            api_results = lib_db.actions.api_domains__enable(
                self.request.api_context, domain_names
            )
            return {"result": "success", "domain_results": api_results}

        except formhandling.FormInvalid as exc:
            return {"result": "error", "form_errors": formStash.errors}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:domain:disable", renderer="json")
    def domain_disable(self):
        if self.request.method == "POST":
            return self._domain_disable__submit()
        return self._domain_disable__print()

    def _domain_disable__print(self):
        return {
            "instructions": """Submit `domain_names` via `POST`""",
            "form_fields": {
                "domain_names": "[required] a comma separated list of fully qualified domain names."
            },
        }

    def _domain_disable__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_API_Domain_disable, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            # this function checks the domain names match a simple regex
            domain_names = utils.domains_from_string(formStash.results["domain_names"])
            if not domain_names:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(
                    field="domain_names", message="Found no domain names"
                )

            api_results = lib_db.actions.api_domains__disable(
                self.request.api_context, domain_names
            )
            return {"result": "success", "domain_results": api_results}

        except formhandling.FormInvalid as exc:
            return {"result": "error", "form_errors": formStash.errors}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:domain:certificate-if-needed", renderer="json")
    def domain_certificate_if_needed(self):
        self._load_AcmeAccount_GlobalDefault()
        self._load_AcmeAccountProviders()
        if self.request.method == "POST":
            return self._domain_certificate_if_needed__submit()
        return self._domain_certificate_if_needed__print()

    def _domain_certificate_if_needed__print(self):
        return {
            "instructions": [
                """POST domain_names for certificates.  curl --form 'account_key_option=account_key_reuse' --form 'account_key_reuse=ff00ff00ff00ff00' 'private_key_option=private_key_reuse' --form 'private_key_reuse=ff00ff00ff00ff00' %s/api/domain/certificate-if-needed.json"""
                % self.request.admin_url
            ],
            "requirements": [
                "Submit corresponding field(s) to account_key_option. If `account_key_file` is your intent, submit either PEM+ProviderID or the three LetsEncrypt Certbot files."
            ],
            "form_fields": {
                "domain_names": "required; a comma separated list of domain names to process",
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
                "acme_account_provider_id": {
                    i.id: "%s (%s)" % (i.name, i.url)
                    for i in self.dbAcmeAccountProviders
                },
                "account_key_option": model_utils.AcmeAccontKey_options_a,
                "processing_strategy": model_utils.AcmeOrder_ProcessingStrategy.OPTIONS_IMMEDIATE,
                "private_key_option": model_utils.PrivateKey_options_a,
                "AcmeAccount_GlobalDefault": self.dbAcmeAccount_GlobalDefault.as_json
                if self.dbAcmeAccount_GlobalDefault
                else None,
                "private_key_cycle__renewal": model_utils.PrivateKeyCycle._options_AcmeOrder_private_key_cycle,
            },
        }

    def _domain_certificate_if_needed__submit(self):
        """
        much of this logic is shared with /acme-order/new/freeform
        """
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_API_Domain_certificate_if_needed,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            # this function checks the domain names match a simple regex
            domain_names = utils.domains_from_string(formStash.results["domain_names"])
            if not domain_names:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(
                    field="domain_names", message="Found no domain names"
                )

            if len(domain_names) != 1:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(
                    field="domain_names",
                    message="This endpoint currently supports only 1 domain name",
                )

            acmeAccountSelection = form_utils.parse_AcmeAccountSelection(
                self.request,
                formStash,
                account_key_option=formStash.results["account_key_option"],
                require_contact=None,
            )
            if acmeAccountSelection.selection == "upload":
                key_create_args = acmeAccountSelection.upload_parsed.getcreate_args
                key_create_args["event_type"] = "AcmeAccount__insert"
                key_create_args[
                    "acme_account_key_source_id"
                ] = model_utils.AcmeAccountKeySource.from_string("imported")
                (dbAcmeAccount, _is_created,) = lib_db.getcreate.getcreate__AcmeAccount(
                    self.request.api_context, **key_create_args
                )
                acmeAccountSelection.AcmeAccount = dbAcmeAccount

            privateKeySelection = form_utils.parse_PrivateKeySelection(
                self.request,
                formStash,
                private_key_option=formStash.results["private_key_option"],
            )

            if privateKeySelection.selection == "upload":
                key_create_args = privateKeySelection.upload_parsed.getcreate_args
                key_create_args["event_type"] = "PrivateKey__insert"
                key_create_args[
                    "private_key_source_id"
                ] = model_utils.PrivateKeySource.from_string("imported")
                key_create_args[
                    "private_key_type_id"
                ] = model_utils.PrivateKeyType.from_string("standard")
                (
                    dbPrivateKey,
                    _is_created,
                ) = lib_db.getcreate.getcreate__PrivateKey__by_pem_text(
                    self.request.api_context, **key_create_args
                )
                privateKeySelection.PrivateKey = dbPrivateKey

            elif privateKeySelection.selection in (
                "generate",
                "private_key_for_account_key",
            ):
                pass

            else:
                formStash.fatal_field(
                    field="private_key_option",
                    message="Could not load the default private key",
                )

            # TODO - include an offset of the last domain added, so there isn't a race condition
            processing_strategy = formStash.results["processing_strategy"]
            private_key_cycle__renewal = formStash.results["private_key_cycle__renewal"]

            api_results = lib_db.actions.api_domains__certificate_if_needed(
                self.request.api_context,
                domain_names=domain_names,
                private_key_cycle__renewal=private_key_cycle__renewal,
                private_key_strategy__requested=privateKeySelection.private_key_strategy__requested,
                processing_strategy=processing_strategy,
                dbAcmeAccount=acmeAccountSelection.AcmeAccount,
                dbPrivateKey=privateKeySelection.PrivateKey,
            )
            return {"result": "success", "domain_results": api_results}

        except (formhandling.FormInvalid, errors.DisplayableError) as exc:
            message = "There was an error with your form."
            if isinstance(exc, errors.DisplayableError):
                message += " " + str(exc)
            return {"result": "error", "form_errors": formStash.errors}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    @view_config(route_name="admin:api:redis:prime", renderer=None)
    @view_config(route_name="admin:api:redis:prime|json", renderer="json")
    def redis_prime(self):
        if self.request.wants_json:
            if self.request.method != "POST":
                return docs.json_docs_post_only

        self._ensure_redis()

        prime_style = utils_redis.redis_prime_style(self.request)
        if not prime_style:
            raise ValueError("invalid `redis.prime_style`")
        redis_client = utils_redis.redis_connection_from_registry(self.request)
        redis_timeouts = utils_redis.redis_timeouts_from_registry(self.request)

        total_primed = {"cacert": 0, "cert": 0, "pkey": 0, "domain": 0}

        dbEvent = None
        if prime_style == "1":
            """
            first priming style
            --
            the redis datastore will look like this:

                r['d:foo.example.com'] = {'c': '1', 'p': '1', 'i' :'99'}  # certid, pkeyid, chainid
                r['d:foo2.example.com'] = {'c': '2', 'p': '1', 'i' :'99'}  # certid, pkeyid, chainid
                r['c1'] = CERT.PEM  # (c)ert
                r['c2'] = CERT.PEM
                r['p2'] = PKEY.PEM  # (p)rivate
                r['i99'] = CACERT.PEM  # (i)ntermediate cert

            to assemble the data for `foo.example.com`:

                * (c, p, i) = r.hmget('d:foo.example.com', 'c', 'p', 'i')
                ** returns {'c': '1', 'p': '1', 'i': '99'}
                * cert = r.get('c1')
                * pkey = r.get('p1')
                * chain = r.get('i99')
                * fullchain = cert + "\n" + chain
            """
            # prime the CACertificates that are active
            offset = 0
            limit = 100
            while True:
                active_certs = lib_db.get.get__CACertificate__paginated(
                    self.request.api_context,
                    offset=offset,
                    limit=limit,
                    active_only=True,
                )
                if not active_certs:
                    # no certs
                    break
                for dbCACertificate in active_certs:
                    total_primed["cacert"] += 1
                    is_primed = utils_redis.redis_prime_logic__style_1_CACertificate(
                        redis_client, dbCACertificate, redis_timeouts
                    )
                if len(active_certs) < limit:
                    # no more
                    break
                offset += limit

            # prime PrivateKeys that are active
            offset = 0
            limit = 100
            while True:
                lib_db.get.get__PrivateKey__paginated(
                    self.request.api_context,
                    offset=0,
                    limit=100,
                    active_usage_only=False,
                )
                active_keys = lib_db.get.get__PrivateKey__paginated(
                    self.request.api_context,
                    offset=offset,
                    limit=limit,
                    active_usage_only=True,
                )
                if not active_keys:
                    # no keys
                    break
                for dbPrivateKey in active_keys:
                    total_primed["pkey"] += 1
                    is_primed = utils_redis.redis_prime_logic__style_1_PrivateKey(
                        redis_client, dbPrivateKey, redis_timeouts
                    )

                if len(active_keys) < limit:
                    # no more
                    break
                offset += limit

            # prime Domains
            offset = 0
            limit = 100
            while True:
                active_domains = lib_db.get.get__Domain__paginated(
                    self.request.api_context,
                    offset=offset,
                    limit=limit,
                    active_certs_only=True,
                )
                if not active_domains:
                    # no domains
                    break
                for dbDomain in active_domains:
                    # favor the multi:
                    total_primed["domain"] += 1
                    total_primed["cert"] += 1
                    is_primed = utils_redis.redis_prime_logic__style_1_Domain(
                        redis_client, dbDomain, redis_timeouts
                    )

                if len(active_domains) < limit:
                    # no more
                    break
                offset += limit

        elif prime_style == "2":
            """
            first priming style
            --
            the redis datastore will look like this:

                r['foo.example.com'] = {'f': 'FullChain', 'p': 'PrivateKey'}
                r['foo2.example.com'] = {'f': 'FullChain', 'p': 'PrivateKey'}

            to assemble the data for `foo.example.com`:

                * (f, p) = r.hmget('foo.example.com', 'f', 'p')
            """

            # prime Domains
            offset = 0
            limit = 100
            while True:
                active_domains = lib_db.get.get__Domain__paginated(
                    self.request.api_context,
                    offset=offset,
                    limit=limit,
                    active_certs_only=True,
                )
                if not active_domains:
                    # no domains
                    break
                for dbDomain in active_domains:
                    # favor the multi:
                    total_primed["domain"] += 1
                    total_primed["cert"] += 1
                    is_primed = utils_redis.redis_prime_logic__style_2_domain(
                        redis_client, dbDomain, redis_timeouts
                    )

                if len(active_domains) < limit:
                    # no more
                    break
                offset += limit

        event_payload_dict = utils.new_event_payload_dict()
        event_payload_dict["prime_style"] = prime_style
        event_payload_dict["total_primed"] = total_primed
        dbEvent = lib_db.logger.log__OperationsEvent(
            self.request.api_context,
            model_utils.OperationsEventType.from_string("operations__redis_prime"),
            event_payload_dict,
        )
        if self.request.wants_json:
            return {
                "result": "success",
                "operations_event": {
                    "id": dbEvent.id,
                    "total_primed": dbEvent.event_payload_json["total_primed"],
                },
            }
        return HTTPSeeOther(
            "%s/operations/redis?result=success&operation=redis_prime&event.id=%s"
            % (
                self.request.registry.settings["app_settings"]["admin_prefix"],
                dbEvent.id,
            )
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:nginx:cache_flush", renderer=None)
    @view_config(route_name="admin:api:nginx:cache_flush|json", renderer="json")
    def admin_nginx_cache_flush(self):
        # ???: This endpoint will allow JSON GET ?
        self._ensure_nginx()
        success, dbEvent, servers_status = utils_nginx.nginx_flush_cache(
            self.request, self.request.api_context
        )
        if self.request.wants_json:
            return {
                "result": "success",
                "operations_event": {"id": dbEvent.id},
                "servers_status": servers_status,
            }
        return HTTPSeeOther(
            "%s/operations/nginx?result=success&operation=nginx_cache_flush&event.id=%s"
            % (
                self.request.registry.settings["app_settings"]["admin_prefix"],
                dbEvent.id,
            )
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:nginx:status|json", renderer="json")
    def admin_nginx_status(self):
        # ???: This endpoint will allow JSON GET ?
        self._ensure_nginx()
        servers_status = utils_nginx.nginx_status(
            self.request, self.request.api_context
        )
        return {"result": "success", "servers_status": servers_status}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:queue_certificates:update", renderer=None)
    @view_config(route_name="admin:api:queue_certificates:update|json", renderer="json")
    def queue_certificate_update(self):
        try:
            if self.request.wants_json:
                if self.request.method != "POST":
                    return {
                        "instructions": """POST required""",
                    }
            queue_results = lib_db.queues.queue_certificates__update(
                self.request.api_context
            )
            if self.request.wants_json:
                return {"result": "success", "results": queue_results}
            return HTTPSeeOther(
                "%s/queue-certificates?result=success&operation=update&results=%s"
                % (
                    self.request.registry.settings["app_settings"]["admin_prefix"],
                    json.dumps(queue_results, sort_keys=True),
                )
            )
        except Exception as exc:
            self.request.api_context.pyramid_transaction_rollback()
            if self.request.wants_json:
                return {"result": "error", "error": exc.as_querystring}
            raise
            return HTTPSeeOther(
                "%s/queue-certificates?result=error&error=%s&operation=update"
                % (
                    self.request.registry.settings["app_settings"]["admin_prefix"],
                    str(exc),
                )
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:queue_certificates:process", renderer=None)
    @view_config(
        route_name="admin:api:queue_certificates:process|json", renderer="json"
    )
    def queue_certificate_process(self):
        try:
            if self.request.wants_json:
                if self.request.method != "POST":
                    return {
                        "instructions": """POST required""",
                    }
            queue_results = lib_db.queues.queue_certificates__process(
                self.request.api_context
            )
            if self.request.wants_json:
                return {"result": "success", "queue_results": queue_results}
            if queue_results:
                queue_results = json.dumps(queue_results, sort_keys=True)
            return HTTPSeeOther(
                "%s/queue-certificates?result=success&operation=process&results=%s"
                % (
                    self.request.registry.settings["app_settings"]["admin_prefix"],
                    json.dumps(queue_results, sort_keys=True),
                )
            )
        except Exception as exc:
            self.request.api_context.pyramid_transaction_rollback()
            if self.request.wants_json:
                return {"result": "error", "error": exc.as_querystring}
            raise
            return HTTPSeeOther(
                "%s/queue-certificates?result=error&error=%s&operation=process"
                % (
                    self.request.registry.settings["app_settings"]["admin_prefix"],
                    str(exc),
                )
            )
