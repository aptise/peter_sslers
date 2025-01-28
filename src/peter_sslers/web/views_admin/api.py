# stdlib
import logging
from typing import TYPE_CHECKING

# import json

# pypi
from pyramid.httpexceptions import HTTPFound
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.view import view_config

# local
from ..lib import docs
from ..lib import form_utils as form_utils
from ..lib import formhandling
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.forms import Form_API_Domain_autocert
from ..lib.forms import Form_API_Domain_certificate_if_needed
from ..lib.handler import Handler
from ... import __VERSION__
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...lib import utils_nginx
from ...lib import utils_redis
from ...model import utils as model_utils

# ==============================================================================

log = logging.getLogger(__name__)

# ------------------------------------------------------------------------------


class ViewAdminApi(Handler):
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api", renderer="/admin/api.mako")
    def index(self):
        return {
            "project": "peter_sslers",
            "API_DOCS": docs.API_DOCS,
        }

    @view_config(route_name="admin:api:version", renderer="json")
    @view_config(route_name="admin:api:version|json", renderer="json")
    def version(self):
        """
        this route exists to help ensure an API client is operating against
        the correct server.
        """
        version = {
            "version": __VERSION__,
            "config_uri-path": self.request.registry.settings["app_settings"][
                "config_uri-path"
            ],
            "config_uri-contents": self.request.registry.settings["app_settings"][
                "config_uri-contents"
            ],
            "mac_uuid": self.request.registry.settings["app_settings"]["mac_uuid"],
        }
        return version

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:deactivate_expired", renderer=None)
    @view_config(route_name="admin:api:deactivate_expired|json", renderer="json")
    @docify(
        {
            "endpoint": "/api/deactivate-expired.json",
            "section": "api",
            "about": """deactivates expired certificates; runs update-recents""",
            "POST": True,
            "GET": None,
        }
    )
    def deactivate_expired(self):
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(self, "/api/deactivate-expired.json")
            return HTTPSeeOther(
                "%s/operations/log?result=error&operation=api--deactivate-expired&error=POST+required"
                % (self.request.registry.settings["app_settings"]["admin_prefix"],)
            )
        operations_event = lib_db.actions.operations_deactivate_expired(
            self.request.api_context
        )
        count_deactivated = operations_event.event_payload_json["count_deactivated"]
        rval = {
            "CertificateSigned": {
                "expired": count_deactivated,
            },
            "result": "success",
            "operations_event": operations_event.id,
        }

        if self.request.wants_json:
            return rval

        return HTTPSeeOther(
            "%s/operations/log?result=success&operation=api--deactivate-expired&event.id=%s"
            % (
                self.request.registry.settings["app_settings"]["admin_prefix"],
                operations_event.id,
            )
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:update_recents", renderer=None)
    @view_config(route_name="admin:api:update_recents|json", renderer="json")
    @docify(
        {
            "endpoint": "/api/update-recents.json",
            "section": "api",
            "about": """updates the database to reflect the most recent Certificate for each Domain""",
            "POST": True,
            "GET": None,
        }
    )
    def update_recents(self):
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(self, "/api/update-recents.json")
            return HTTPSeeOther(
                "%s/operations/log?result=error&operation=api--update-recents&error=POST+required"
                % (self.request.registry.settings["app_settings"]["admin_prefix"],)
            )
        operations_event = lib_db.actions.operations_update_recents__global(
            self.request.api_context
        )
        if self.request.wants_json:
            return {"result": "success", "operations_event": operations_event.id}
        return HTTPSeeOther(
            "%s/operations/log?result=success&operation=api--update-recents&event.id=%s"
            % (
                self.request.registry.settings["app_settings"]["admin_prefix"],
                operations_event.id,
            )
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:reconcile_cas", renderer=None)
    @view_config(route_name="admin:api:reconcile_cas|json", renderer="json")
    @docify(
        {
            "endpoint": "/api/reconcile-cas.json",
            "section": "api",
            "about": """Reconcile outstanding CertificateCA records by downloading and enrolling the CertificateCA presented in their "AuthorityKeyIdentifier".""",
            "POST": True,
            "GET": None,
        }
    )
    def reconcile_cas(self):
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(self, "/api/reconcile-cas.json")
            return HTTPSeeOther(
                "%s/operations/log?result=error&operation=api--reconcile-cas&error=POST+required"
                % (self.request.registry.settings["app_settings"]["admin_prefix"],)
            )
        operations_event = lib_db.actions.operations_reconcile_cas(
            self.request.api_context
        )
        if self.request.wants_json:
            return {"result": "success", "operations_event": operations_event.id}
        return HTTPSeeOther(
            "%s/operations/log?result=success&operation=api--reconcile-cas&event.id=%s"
            % (
                self.request.registry.settings["app_settings"]["admin_prefix"],
                operations_event.id,
            )
        )


class ViewAdminApi_Domain(Handler):

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:domain:certificate-if-needed", renderer="json")
    @docify(
        {
            "endpoint": "/api/domain/certificate-if-needed.json",
            "section": "api",
            "about": """Initiates a new Certificate provisioning if needed. Supports full control of acme-order properties.""",
            "POST": True,
            "GET": None,
            "instructions": [
                """POST domain_name for certificates.""",
                """curl --form 'domain_name=example.com' --form 'account_key_option=account_key_existing' --form 'account_key_existing=ff00ff00ff00ff00' 'private_key_option=private_key_existing' --form 'private_key_existing=ff00ff00ff00ff00' {ADMIN_PREFIX}/api/domain/certificate-if-needed.json""",
            ],
            "requirements": [
                "Submit corresponding field(s) to account_key_option, e.g. `account_key_existing` or `account_key_global_default`.",
            ],
            "form_fields": {
                "domain_name": "required; a single domain name to process",
                "processing_strategy": "How should the order be processed?",
                "account_key_option": "How is the AcmeAccount specified?",
                "account_key_global_default": "pem_md5 of the Global Default account key. Must/Only submit if `account_key_option==account_key_global_default`",
                "account_key_existing": "pem_md5 of any key. Must/Only submit if `account_key_option==account_key_existing`",
                "private_key_option": "How is the PrivateKey being specified?",
                "private_key_existing": "pem_md5 of existing key",
                "private_key_cycle": "how should the PrivateKey be cycled on renewals?",
            },
            "form_fields_related": [
                ["domain_names_http01", "domain_names_dns01"],
            ],
            "valid_options": {
                "AcmeAccount_GlobalDefault": "{RENDER_ON_REQUEST}",
                # Form_API_Domain_certificate_if_needed
                "processing_strategy": Form_API_Domain_certificate_if_needed.fields[
                    "processing_strategy"
                ].list,
                "private_key_cycle": Form_API_Domain_certificate_if_needed.fields[
                    "private_key_cycle"
                ].list,
                # _form_AcmeAccount_PrivateKey_core
                "account_key_option": Form_API_Domain_certificate_if_needed.fields[
                    "account_key_option"
                ].list,
                "private_key_option": Form_API_Domain_certificate_if_needed.fields[
                    "private_key_option"
                ].list,
                "private_key_generate": Form_API_Domain_certificate_if_needed.fields[
                    "private_key_generate"
                ].list,
            },
        }
    )
    def certificate_if_needed(self):
        self._load_AcmeAccount_GlobalDefault()
        self._load_AcmeServers()
        if self.request.method == "POST":
            return self._certificate_if_needed__submit()
        return self._certificate_if_needed__print()

    def _certificate_if_needed__print(self):
        return formatted_get_docs(self, "/api/domain/certificate-if-needed.json")

    def _certificate_if_needed__submit(self):
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

            domains_challenged = form_utils.form_single_domain_challenge_typed(
                self.request, formStash, challenge_type="http-01"
            )
            # domain_name = domains_challenged["http-01"][0]

            acmeAccountSelection = form_utils.parse_AcmeAccountSelection(
                self.request,
                formStash,
                account_key_option=formStash.results["account_key_option"],
                require_contact=False,
                support_upload=False,
            )
            if TYPE_CHECKING:
                assert acmeAccountSelection.upload_parsed is not None

            privateKeySelection = form_utils.parse_PrivateKeySelection(
                self.request,
                formStash,
                private_key_option=formStash.results["private_key_option"],
            )
            if TYPE_CHECKING:
                assert privateKeySelection.upload_parsed is not None

            if not privateKeySelection.PrivateKey:
                formStash.fatal_field(
                    field="private_key_option",
                    message="Could not load/configure the private key",
                )

            # this is locked to `model_utils.AcmeOrder_ProcessingStrategy.OPTIONS_IMMEDIATE`
            #   which is only `process_single`
            processing_strategy = formStash.results["processing_strategy"]

            # allow anything in model_utils.PrivateKeyCycle._options_RenewalConfiguration_private_key_cycle
            private_key_cycle = formStash.results["private_key_cycle"]

            if TYPE_CHECKING:
                assert acmeAccountSelection.AcmeAccount is not None
                assert privateKeySelection.PrivateKey is not None

            api_results = lib_db.actions.api_domains__certificate_if_needed(
                self.request.api_context,
                dbAcmeAccount=acmeAccountSelection.AcmeAccount,
                dbPrivateKey=privateKeySelection.PrivateKey,
                domains_challenged=domains_challenged,
                private_key_cycle=private_key_cycle,
                key_technology=privateKeySelection.key_technology,
                processing_strategy=processing_strategy,
            )
            return {"result": "success", "domain_results": api_results}

        except (formhandling.FormInvalid, errors.DisplayableError) as exc:
            message = "There was an error with your form."
            if isinstance(exc, errors.DisplayableError):
                message += " " + str(exc)
            return {"result": "error", "form_errors": formStash.errors}

    @view_config(
        route_name="admin:api:domain:autocert",
        renderer="/admin/api-domain-autocert.mako",
    )
    def autocert_html(self):
        self._load_AcmeAccount_GlobalDefault()
        return {
            "project": "peter_sslers",
            "AcmeAccount_GlobalDefault": self.dbAcmeAccount_GlobalDefault,
        }

    @view_config(route_name="admin:api:domain:autocert|json", renderer="json")
    @docify(
        {
            "endpoint": "/api/domain/autocert.json",
            "section": "api",
            "about": """Initiates a new certificate if needed. only accepts a sigle domain name, uses system global defaults""",
            "POST": True,
            "GET": None,
            "system.requires": [
                "dbAcmeAccount_GlobalDefault",
            ],
            "instructions": [
                "POST `domain_name` to automatically attempt a certificate provisioning",
                """curl --form 'domain_name=example.com' {ADMIN_PREFIX}/api/domain/autocert.json""",
            ],
            "form_fields": {
                "domain_name": "required; a single domain name to process",
            },
        }
    )
    def autocert(self):
        self._load_AcmeAccount_GlobalDefault()
        if self.request.method == "POST":
            return self._autocert__submit()
        return self._autocert__print()

    def _autocert__print(self):
        return formatted_get_docs(self, "/api/domain/autocert.json")

    def _autocert__submit(self):
        """
        much of this logic is shared with /acme-order/new/freeform
        """
        # scoping
        dbDomainAutocert = None
        dbAcmeOrder = None
        try:
            log.debug("attempting an autocert")
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_API_Domain_autocert,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            # this ensures only one domain
            domains_challenged = form_utils.form_single_domain_challenge_typed(
                self.request, formStash, challenge_type="http-01"
            )
            # validate it, which may raise `peter_sslers.lib.errors.AcmeDomainsBlocklisted`
            for challenge_, domains_ in domains_challenged.items():
                if domains_:
                    try:
                        lib_db.validate.validate_domain_names(
                            self.request.api_context, domains_
                        )
                    except errors.AcmeDomainsBlocklisted as exc:  # noqa: F841
                        # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                        formStash.fatal_field(
                            field="domain_name",
                            message="This domain_name has been blocklisted",
                        )

            domain_name = domains_challenged["http-01"][0]

            # does the domain exist?
            # we should check to see if it does and has certs
            dbDomain = lib_db.get.get__Domain__by_name(
                self.request.api_context,
                domain_name,
            )
            if dbDomain:
                log.debug("autocert - domain known")
                if dbDomain.has_active_certificates:
                    # exit early if we have active certs
                    rval = dbDomain.as_json_config(id_only=False)
                    rval["result"] = "success"
                    rval["notes"] = "existing certificate(s)"
                    log.debug("autocert - domain known - active certs")
                    return rval

                # sync the database, then check again
                operations_event = lib_db.actions.operations_update_recents__domains(
                    self.request.api_context,
                    dbDomains=[
                        dbDomain,
                    ],
                )
                # commit so we expire the traits
                self.request.api_context.pyramid_transaction_commit()
                # and check again...
                if dbDomain.has_active_certificates:
                    # exit early
                    rval = dbDomain.as_json_config(id_only=False)
                    rval["result"] = "success"
                    rval["notes"] = "existing certificate(s), updated recents"
                    log.debug("autocert - domain known - active certs")
                    return rval

                log.debug("autocert - domain known - attempt autocert")

            if dbDomain:
                dbDomainAutocert = lib_db.get.get__DomainAutocert__by_blockingDomainId(
                    self.request.api_context,
                    dbDomain.id,
                )
                if dbDomainAutocert:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(
                        field="domain_name",
                        message="There is an active or recent autocert attempt for this domain",
                    )

            if not self.dbAcmeAccount_GlobalDefault:
                formStash.fatal_field(
                    field="AcmeAccount",
                    message="You must configure a global AcmeAccount.",
                )

            dbAcmeAccount = self.dbAcmeAccount_GlobalDefault
            assert dbAcmeAccount

            dbPrivateKey = lib_db.get.get__PrivateKey__by_id(
                self.request.api_context, 0
            )
            if not dbPrivateKey:
                formStash.fatal_field(
                    field="PrivateKey",
                    message="Could not load the placeholder PrivateKey.",
                )

            try:
                if not dbDomain:
                    # we need to start with a domain name in order to create the Autocert block
                    (dbDomain, _is_created) = (
                        lib_db.getcreate.getcreate__Domain__by_domainName(
                            self.request.api_context,
                            domain_name,
                            discovery_type="autocert",
                        )
                    )
                    self.request.api_context.pyramid_transaction_commit()

                # TODO: tie in the cert we get?
                dbDomainAutocert = lib_db.create.create__DomainAutocert(
                    self.request.api_context,
                    dbDomain=dbDomain,
                )
                is_duplicate_renewal: bool
                try:
                    dbRenewalConfiguration = lib_db.create.create__RenewalConfiguration(
                        self.request.api_context,
                        dbAcmeAccount=dbAcmeAccount,
                        private_key_cycle_id=model_utils.PrivateKeyCycle.ACCOUNT_DEFAULT,
                        key_technology_id=model_utils.KeyTechnology.ACCOUNT_DEFAULT,
                        domains_challenged=domains_challenged,
                    )
                    is_duplicate_renewal = False  # noqa: F841
                except errors.DuplicateRenewalConfiguration as exc:
                    is_duplicate_renewal = True  # noqa: F841
                    # we could raise exc to abort, but this is likely preferred
                    dbRenewalConfiguration = exc.args[0]

                # run an order
                dbAcmeOrder = lib_db.actions_acme.do__AcmeV2_AcmeOrder__new(
                    self.request.api_context,
                    dbRenewalConfiguration=dbRenewalConfiguration,
                    processing_strategy="process_single",
                    acme_order_type_id=model_utils.AcmeOrderType.AUTOCERT,
                    dbPrivateKey=dbPrivateKey,
                )
                if dbAcmeOrder.acme_status_order == "valid":
                    dbDomain = dbAcmeOrder.unique_fqdn_set.domains[0]
                    if dbDomain is None:
                        raise ValueError("Could not extract `Domain`")
                    operations_event = (  # noqa: F841
                        lib_db.actions.operations_update_recents__domains(
                            self.request.api_context,
                            dbDomains=[
                                dbDomain,
                            ],
                        )
                    )

                    # commit this so the domain will reload
                    self.request.api_context.pyramid_transaction_commit()
                    rval = dbDomain.as_json_config(id_only=False)
                    rval["result"] = "success"
                    rval["notes"] = "new AcmeOrder, valid"
                    rval["AcmeOrder"] = {
                        "id": dbAcmeOrder.id,
                    }

                    # this could be done in a finished-callback?
                    try:
                        utils_redis.prime_redis_domain(self.request, dbDomain)
                    except utils_redis.RedisError as exc:
                        log.debug("autocert - could not prime redis > %s", str(exc))
                        # continue

                    log.debug("autocert - order valid")
                    return rval
                rval = {
                    "result": "error",
                    "notes": "new AcmeOrder, invalid",
                    "Domain": None,
                    "certificate_signed__latest_single": None,
                    "certificate_signed__latest_multi": None,
                    "AcmeOrder": {
                        "id": dbAcmeOrder.id,
                    },
                }
                log.debug("autocert - order invalid")
                return rval
            except Exception as exc:
                # unpack a `errors.AcmeOrderCreatedError` to local vars
                if isinstance(exc, errors.AcmeOrderCreatedError):
                    rval = {
                        "result": "error",
                    }
                    dbAcmeOrder = exc.acme_order
                    if TYPE_CHECKING:
                        assert dbAcmeOrder is not None
                    rval["AcmeOrder"] = {
                        "id": dbAcmeOrder.id,
                    }
                    exc = exc.original_exception
                    if isinstance(exc, errors.AcmeError):
                        rval["error"] = str(exc)

                    return rval

                # ???: should we raise something better?
                log.debug("autocert - order exception")
                raise

        except (formhandling.FormInvalid, errors.DisplayableError) as exc:
            message = "There was an error with your form."
            if isinstance(exc, errors.DisplayableError):
                message += " " + str(exc)
            return {
                "result": "error",
                "form_errors": formStash.errors,
                "Domain": None,
                "certificate_signed__latest_single": None,
                "certificate_signed__latest_multi": None,
            }

        finally:
            if dbDomainAutocert:
                if dbAcmeOrder:
                    # could be success or fail
                    lib_db.update.update_DomainAutocert_with_AcmeOrder(
                        self.request.api_context,
                        dbDomainAutocert,
                        dbAcmeOrder=dbAcmeOrder,
                    )
                else:
                    # this is a fail
                    lib_db.update.update_DomainAutocert_without_AcmeOrder(
                        self.request.api_context,
                        dbDomainAutocert,
                    )


class ViewAdminApi_Redis(Handler):
    @view_config(route_name="admin:api:redis:prime", renderer=None)
    @view_config(route_name="admin:api:redis:prime|json", renderer="json")
    @docify(
        {
            "endpoint": "/api/redis/prime.json",
            "section": "api",
            "about": """Primes the Redis cache""",
            "POST": True,
            "GET": None,
        }
    )
    def prime(self):
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(self, "/api/redis/prime.json")
            return HTTPSeeOther(
                "%s/operations/redis?result=error&operation=api--redis--prime&error=POST+required"
                % (self.request.registry.settings["app_settings"]["admin_prefix"],)
            )

        try:
            # could raise `errors.InvalidRequest("redis is not enabled")`
            self._ensure_redis()
            prime_style = utils_redis.redis_prime_style(self.request)
            if not prime_style:
                raise errors.InvalidRequest("invalid `redis.prime_style`")
            redis_client = utils_redis.redis_connection_from_registry(self.request)
            redis_timeouts = utils_redis.redis_timeouts_from_registry(self.request)

            total_primed = {"certcachain": 0, "cert": 0, "pkey": 0, "domain": 0}

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
                    r['i99'] = CHAIN.PEM  # (i)ntermediate certs

                to assemble the data for `foo.example.com`:

                    * (c, p, i) = r.hmget('d:foo.example.com', 'c', 'p', 'i')
                    ** returns {'c': '1', 'p': '1', 'i': '99'}
                    * cert = r.get('c1')
                    * pkey = r.get('p1')
                    * chain = r.get('i99')
                    * fullchain = cert + "\n" + chain
                """
                # prime the CertificateCAs that are active
                offset = 0
                limit = 100
                while True:
                    active_chains = lib_db.get.get__CertificateCAChain__paginated(
                        self.request.api_context,
                        offset=offset,
                        limit=limit,
                        active_only=True,
                    )
                    if not active_chains:
                        # no certs
                        break
                    for dbCertificateCAChain in active_chains:
                        total_primed["certcachain"] += 1
                        is_primed = (
                            utils_redis.redis_prime_logic__style_1_CertificateCAChain(
                                redis_client, dbCertificateCAChain, redis_timeouts
                            )
                        )
                    if len(active_chains) < limit:
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
                        is_primed = (  # noqa: F841
                            utils_redis.redis_prime_logic__style_2_domain(
                                redis_client, dbDomain, redis_timeouts
                            )
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

        except (errors.InvalidRequest, utils_redis.RedisError) as exc:
            if self.request.wants_json:
                if isinstance(exc, errors.InvalidRequest):
                    msg = exc.args[0]
                else:
                    msg = str(exc)
                return {
                    "result": "error",
                    "error": msg,
                }
            if isinstance(exc, errors.InvalidRequest):
                msg = exc.args[0]
            else:
                msg = str(exc)
            raise HTTPFound(
                "%s/operations/redis?result=error&operation=api--redis--prime&error=%s"
                % (
                    self.request.registry.settings["app_settings"]["admin_prefix"],
                    msg,
                )
            )


class ViewAdminApi_Nginx(Handler):
    @view_config(route_name="admin:api:nginx:cache_flush", renderer=None)
    @view_config(route_name="admin:api:nginx:cache_flush|json", renderer="json")
    @docify(
        {
            "endpoint": "/api/nginx/cache-flush.json",
            "section": "api",
            "about": """Flushes the Nginx cache. This will make background requests to configured Nginx servers, instructing them to flush their cache. """,
            "POST": True,
            "GET": None,
        }
    )
    def cache_flush(self):
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(self, "/api/nginx/cache-flush.json")
            return HTTPSeeOther(
                "%s/operations/nginx?result=error&operation=api--nginx--cache-flush&error=POST+required"
                % (self.request.registry.settings["app_settings"]["admin_prefix"],)
            )
        try:
            # could raise `errors.InvalidRequest("nginx is not enabled")`
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
        except errors.InvalidRequest as exc:
            if self.request.wants_json:
                return {
                    "result": "error",
                    "error": exc.args[0],
                }
            raise HTTPFound(
                "%s/operations/nginx?result=error&operation=api--nginx--cache-flush&error=%s"
                % (
                    self.request.registry.settings["app_settings"]["admin_prefix"],
                    exc.as_querystring,
                )
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:nginx:status|json", renderer="json")
    @docify(
        {
            "endpoint": "/api/nginx/status.json",
            "section": "api",
            "about": """Checks Nginx servers for status via background requests""",
            "POST": True,
            "GET": None,
        }
    )
    def status(self):
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(self, "/api/nginx/status.json")
            return HTTPSeeOther(
                "%s/operations/nginx?result=error&operation=api--nginx--status&error=POST+required"
                % (self.request.registry.settings["app_settings"]["admin_prefix"],)
            )
        try:
            # could raise `errors.InvalidRequest("nginx is not enabled")`
            self._ensure_nginx()
            servers_status = utils_nginx.nginx_status(
                self.request, self.request.api_context
            )
            return {"result": "success", "servers_status": servers_status}
        except errors.InvalidRequest as exc:
            if self.request.wants_json:
                return {
                    "result": "error",
                    "error": exc.args[0],
                }
            raise HTTPFound(
                "%s/operations/nginx?result=error&operation=api--nginx--status&error=%s"
                % (
                    self.request.registry.settings["app_settings"]["admin_prefix"],
                    exc.as_querystring,
                )
            )
