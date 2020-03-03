# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPSeeOther

# stdlib
import datetime
import json

# pypi
import six
import sqlalchemy
import transaction

# localapp
from .. import lib
from ..lib import formhandling
from ..lib.forms import Form_API_Domain_enable
from ..lib.forms import Form_API_Domain_disable
from ..lib.forms import Form_API_Domain_certificate_if_needed
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...lib import utils_nginx
from ...lib import utils_redis
from ...model import utils as model_utils


# ==============================================================================


class ViewAdmin(Handler):

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api", renderer="/admin/api.mako")
    def api(self):
        return {"project": "peter_sslers"}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:update_recents", renderer=None)
    @view_config(route_name="admin:api:update_recents|json", renderer="json")
    def api_update_recents(self):
        operations_event = lib_db.actions.operations_update_recents(
            self.request.api_context
        )
        if self.request.wants_json:
            return {"result": "success", "operations_event": operations_event.id}
        return HTTPSeeOther(
            "%s/operations/log?result=success&event.id=%s"
            % (self.request.registry.settings["admin_prefix"], operations_event.id)
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:deactivate_expired", renderer=None)
    @view_config(route_name="admin:api:deactivate_expired|json", renderer="json")
    def api_deactivate_expired(self):
        rval = {}
        operations_event = lib_db.actions.operations_deactivate_expired(
            self.request.api_context
        )
        count_deactivated_expired = operations_event.event_payload_json[
            "count_deactivated"
        ]
        rval["ServerCertificate"] = {"expired": count_deactivated_expired}

        rval["result"] = "success"
        rval["operations_event"] = operations_event.id

        if self.request.wants_json:
            return rval

        return HTTPSeeOther(
            "%s/operations/log?result=success&event.id=%s"
            % (self.request.registry.settings["admin_prefix"], operations_event.id)
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:domain:enable", renderer="json")
    def api_domain_enable(self):
        if self.request.method == "POST":
            return self._api_domain_enable__submit()
        return self._api_domain_enable__print()

    def _api_domain_enable__print(self):
        return {
            "instructions": """POST `domain_names""",
            "form_fields": {"domain_names": "required"},
        }

    def _api_domain_enable__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_API_Domain_enable, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            domain_names = utils.domains_from_string(formStash.results["domain_names"])
            if not domain_names:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(
                    field="domain_names", message="Found no domain names"
                )
            api_results = lib_db.actions.api_domains__enable(
                self.request.api_context, domain_names
            )
            return {"result": "success", "domains": api_results}

        except formhandling.FormInvalid as exc:
            return {"result": "error", "form_errors": formStash.errors}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:domain:disable", renderer="json")
    def api_domain_disable(self):
        if self.request.method == "POST":
            return self._api_domain_disable__submit()
        return self._api_domain_disable__print()

    def _api_domain_disable__print(self):
        return {
            "instructions": """POST `domain_names""",
            "form_fields": {"domain_names": "required"},
        }

    def _api_domain_disable__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_API_Domain_disable, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            domain_names = utils.domains_from_string(formStash.results["domain_names"])
            if not domain_names:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(
                    field="domain_names", message="Found no domain names"
                )

            api_results = lib_db.actions.api_domains__disable(
                self.request.api_context, domain_names
            )
            return {"result": "success", "domains": api_results}

        except formhandling.FormInvalid as exc:
            return {"result": "error", "form_errors": formStash.errors}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:domain:certificate-if-needed", renderer="json")
    def api_domain_certificate_if_needed(self):
        if self.request.method == "POST":
            return self._api_domain_certificate_if_needed__submit()
        return self._api_domain_certificate_if_needed__print()

    def _api_domain_certificate_if_needed__print(self):
        return {
            "instructions": """POST `domain_names""",
            "form_fields": {
                "domain_names": "required",
                "account_key_file_pem": "optional",
            },
        }

    def _api_domain_certificate_if_needed__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_API_Domain_certificate_if_needed,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

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

            account_key_pem = None
            if formStash.results["account_key_file_pem"] is not None:
                account_key_pem = formhandling.slurp_file_field(
                    formStash, "account_key_file_pem"
                )
                if six.PY3:
                    if not isinstance(account_key_pem, str):
                        account_key_pem = account_key_pem.decode("utf8")

            api_results = lib_db.actions.api_domains__certificate_if_needed(
                self.request.api_context, domain_names, account_key_pem=account_key_pem
            )
            return {"result": "success", "domains": api_results}

        except (formhandling.FormInvalid, errors.DisplayableError) as exc:
            message = "There was an error with your form."
            if isinstance(exc, errors.DisplayableError):
                message += " " + str(exc)
            return {"result": "error", "form_errors": formStash.errors}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    @view_config(route_name="admin:api:redis:prime", renderer=None)
    @view_config(route_name="admin:api:redis:prime|json", renderer="json")
    def admin_redis_prime(self):
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
                active_keys = lib_db.get.get__PrivateKey__paginated(
                    self.request.api_context,
                    offset=offset,
                    limit=limit,
                    active_only=True,
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
                    active_only=True,
                )
                if not active_domains:
                    # no domains
                    break
                for dbDomain in active_domains:
                    # favor the multi:
                    total_primed["domain"] += 1
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
                    active_only=True,
                )
                if not active_domains:
                    # no domains
                    break
                for domain in active_domains:
                    # favor the multi:
                    total_primed["domain"] += 1
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
            % (self.request.registry.settings["admin_prefix"], dbEvent.id)
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:nginx:cache_flush", renderer=None)
    @view_config(route_name="admin:api:nginx:cache_flush|json", renderer="json")
    def admin_nginx_cache_flush(self):
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
            % (self.request.registry.settings["admin_prefix"], dbEvent.id)
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:nginx:status|json", renderer="json")
    def admin_nginx_status(self):
        self._ensure_nginx()
        servers_status = utils_nginx.nginx_status(
            self.request, self.request.api_context
        )
        return {"result": "success", "servers_status": servers_status}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:ca_certificate_probes:probe", renderer=None)
    @view_config(
        route_name="admin:api:ca_certificate_probes:probe|json", renderer="json"
    )
    def ca_certificate_probes__probe(self):
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
            % (self.request.registry.settings["admin_prefix"], operations_event.id)
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:queue_certificates:update", renderer=None)
    @view_config(route_name="admin:api:queue_certificates:update|json", renderer="json")
    def queue_certificate_update(self):
        try:
            queue_results = lib_db.queues.queue_certificates__update(
                self.request.api_context
            )
            if self.request.wants_json:
                return {"result": "success"}
            return HTTPSeeOther(
                "%s/queue-certificates?update=1"
                % self.request.registry.settings["admin_prefix"]
            )
        except Exception as exc:
            transaction.abort()
            if self.request.wants_json:
                return {"result": "error", "error": exc.to_querystring()}
            raise

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:queue_certificates:process", renderer=None)
    @view_config(
        route_name="admin:api:queue_certificates:process|json", renderer="json"
    )
    def queue_certificate_process(self):
        try:
            queue_results = lib_db.queues.queue_certificates__process(
                self.request.api_context
            )
            if self.request.wants_json:
                return {"result": "success", "queue_results": queue_results}
            if queue_results:
                queue_results = json.dumps(queue_results)
            return HTTPSeeOther(
                "%s/queue-certificates?process=1&results=%s"
                % (self.request.registry.settings["admin_prefix"], queue_results)
            )
        except Exception as exc:
            transaction.abort()
            if self.request.wants_json:
                return {"result": "error", "error": exc.to_querystring()}
            raise
