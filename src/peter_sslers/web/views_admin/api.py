# stdlib
import json
import logging
from typing import TYPE_CHECKING

# pypi
import cert_utils
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
from ..lib.forms import Form_API_Domain_disable
from ..lib.forms import Form_API_Domain_enable
from ..lib.handler import Handler
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
    @view_config(route_name="admin:api:domain:enable", renderer="json")
    @docify(
        {
            "endpoint": "/api/domain/enable.json",
            "section": "api",
            "about": """Enables Domain(s) for management.""",
            "POST": True,
            "GET": None,
            "form_fields": {
                "domain_names": "[required] a comma separated list of fully qualified domain names."
            },
        }
    )
    def enable(self):
        if self.request.method == "POST":
            return self._enable__submit()
        return self._enable__print()

    def _enable__print(self):
        return formatted_get_docs(self, "/api/domain/enable.json")

    def _enable__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_API_Domain_enable, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            # this function checks the domain names match a simple regex
            domain_names = cert_utils.utils.domains_from_string(
                formStash.results["domain_names"]
            )
            if not domain_names:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(
                    field="domain_names", message="Found no domain names"
                )
            api_results = lib_db.actions.api_domains__enable(
                self.request.api_context, domain_names
            )
            return {"result": "success", "domain_results": api_results}

        except formhandling.FormInvalid as exc:  # noqa: F841
            return {"result": "error", "form_errors": formStash.errors}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:api:domain:disable", renderer="json")
    @docify(
        {
            "endpoint": "/api/domain/disable.json",
            "section": "api",
            "about": """Disables Domain(s) for management.""",
            "POST": True,
            "GET": None,
            "form_fields": {
                "domain_names": "[required] a comma separated list of fully qualified domain names."
            },
        }
    )
    def disable(self):
        if self.request.method == "POST":
            return self._disable__submit()
        return self._disable__print()

    def _disable__print(self):
        return formatted_get_docs(self, "/api/domain/disable.json")

    def _disable__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_API_Domain_disable, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid()

            # this function checks the domain names match a simple regex
            domain_names = cert_utils.utils.domains_from_string(
                formStash.results["domain_names"]
            )
            if not domain_names:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(
                    field="domain_names", message="Found no domain names"
                )

            api_results = lib_db.actions.api_domains__disable(
                self.request.api_context, domain_names
            )
            return {"result": "success", "domain_results": api_results}

        except formhandling.FormInvalid as exc:  # noqa: F841
            return {"result": "error", "form_errors": formStash.errors}

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
                """curl --form 'account_key_option=account_key_reuse' --form 'account_key_reuse=ff00ff00ff00ff00' 'private_key_option=private_key_reuse' --form 'private_key_reuse=ff00ff00ff00ff00' {ADMIN_PREFIX}/api/domain/certificate-if-needed.json""",
            ],
            "requirements": [
                "Submit corresponding field(s) to account_key_option. If `account_key_file` is your intent, submit either PEM+ProviderID or the three LetsEncrypt Certbot files."
            ],
            "form_fields": {
                "domain_name": "required; a single domain name to process",
                "processing_strategy": "How should the order be processed?",
                "account_key_option": "How is the AcmeAccount specified?",
                "account_key_global_default": "pem_md5 of the Global Default account key. Must/Only submit if `account_key_option==account_key_global_default`",
                "account_key_existing": "pem_md5 of any key. Must/Only submit if `account_key_option==account_key_existing`",
                "account_key_file_pem": "pem of the account key file. Must/Only submit if `account_key_option==account_key_file`",
                "acme_server_id": "account provider. Must/Only submit if `account_key_option==account_key_file` and `account_key_file_pem` is used.",
                "account_key_file_le_meta": "LetsEncrypt Certbot file. Must/Only submit if `account_key_option==account_key_file` and `account_key_file_pem` is not used",
                "account_key_file_le_pkey": "LetsEncrypt Certbot file",
                "account_key_file_le_reg": "LetsEncrypt Certbot file",
                "private_key_option": "How is the PrivateKey being specified?",
                "private_key_existing": "pem_md5 of existing key",
                "private_key_file_pem": "pem to upload",
                "private_key_cycle__renewal": "how should the PrivateKey be cycled on renewals?",
            },
            "form_fields_related": [
                ["account_key_file_pem", "acme_server_id"],
                [
                    "account_key_file_le_meta",
                    "account_key_file_le_pkey",
                    "account_key_file_le_reg",
                ],
            ],
            "valid_options": {
                "acme_server_id": "{RENDER_ON_REQUEST}",
                "account_key_option": model_utils.AcmeAccountKey_options_a,
                "processing_strategy": model_utils.AcmeOrder_ProcessingStrategy.OPTIONS_IMMEDIATE,
                "private_key_option": model_utils.PrivateKey_options_a,
                "AcmeAccount_GlobalDefault": "{RENDER_ON_REQUEST}",
                "private_key_cycle__renewal": model_utils.PrivateKeyCycle._options_AcmeOrder_private_key_cycle,
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
                require_contact=None,
            )
            if TYPE_CHECKING:
                assert acmeAccountSelection.upload_parsed is not None

            if acmeAccountSelection.selection == "upload":
                key_create_args = acmeAccountSelection.upload_parsed.getcreate_args
                key_create_args["event_type"] = "AcmeAccount__insert"
                key_create_args["acme_account_key_source_id"] = (
                    model_utils.AcmeAccountKeySource.from_string("imported")
                )
                (
                    dbAcmeAccount,
                    _is_created,
                ) = lib_db.getcreate.getcreate__AcmeAccount(
                    self.request.api_context, **key_create_args
                )
                acmeAccountSelection.AcmeAccount = dbAcmeAccount

            privateKeySelection = form_utils.parse_PrivateKeySelection(
                self.request,
                formStash,
                private_key_option=formStash.results["private_key_option"],
            )
            if TYPE_CHECKING:
                assert privateKeySelection.upload_parsed is not None

            if privateKeySelection.selection == "upload":
                key_create_args = privateKeySelection.upload_parsed.getcreate_args
                key_create_args["discovery_type"] = "via certificate_if_needed"
                key_create_args["event_type"] = "PrivateKey__insert"
                key_create_args["private_key_source_id"] = (
                    model_utils.PrivateKeySource.from_string("imported")
                )
                key_create_args["private_key_type_id"] = (
                    model_utils.PrivateKeyType.from_string("standard")
                )
                (
                    dbPrivateKey,
                    _is_created,
                ) = lib_db.getcreate.getcreate__PrivateKey__by_pem_text(
                    self.request.api_context, **key_create_args
                )
                privateKeySelection.PrivateKey = dbPrivateKey

            elif privateKeySelection.selection in (
                "generate",
                "account_default",
            ):
                pass

            else:
                formStash.fatal_field(
                    field="private_key_option",
                    message="Could not load the default private key",
                )

            processing_strategy = formStash.results["processing_strategy"]
            private_key_cycle__renewal = formStash.results["private_key_cycle__renewal"]

            if TYPE_CHECKING:
                assert acmeAccountSelection.AcmeAccount is not None
                assert privateKeySelection.PrivateKey is not None

            api_results = lib_db.actions.api_domains__certificate_if_needed(
                self.request.api_context,
                domains_challenged=domains_challenged,
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
            "about": """Initiates a new certificate if needed. only accepts a domain name, uses system defaults""",
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

            domains_challenged = form_utils.form_single_domain_challenge_typed(
                self.request, formStash, challenge_type="http-01"
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
                if not dbDomain.is_active:
                    # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                    formStash.fatal_field(
                        field="domain_name",
                        message="This domain_name has been disabled",
                    )
                if dbDomain.has_active_certificates:
                    # exit early
                    rval = dbDomain.as_json_config(id_only=False, active_only=True)
                    rval["result"] = "success"
                    rval["notes"] = "existing certificate(s)"
                    log.debug("autocert - domain known - active certs")
                    return rval
                else:
                    # sync the database, just be sure
                    operations_event = (
                        lib_db.actions.operations_update_recents__domains(
                            self.request.api_context,
                            dbDomains=[
                                dbDomain,
                            ],
                        )
                    )
                    # commit so we expire the traits
                    self.request.api_context.pyramid_transaction_commit()
                    # and check again...
                    if dbDomain.has_active_certificates:
                        # exit early
                        rval = dbDomain.as_json_config(id_only=False, active_only=True)
                        rval["result"] = "success"
                        rval["notes"] = "existing certificate(s), updated recents"
                        log.debug("autocert - domain known - active certs")
                        return rval

                log.debug("autocert - domain known - attempt autocert")

            # Step 1- is the domain_name blocklisted?
            dbDomainBlocklisted = lib_db.get.get__DomainBlocklisted__by_name(
                self.request.api_context,
                domain_name,
            )
            if dbDomainBlocklisted:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(
                    field="domain_name",
                    message="This domain_name has been blocklisted",
                )

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
                    dbDomain = lib_db.getcreate.getcreate__Domain__by_domainName(
                        self.request.api_context,
                        domain_name,
                        discovery_type="autocert",
                    )[
                        0
                    ]  # (dbDomain, _is_created)
                    self.request.api_context.pyramid_transaction_commit()

                dbDomainAutocert = lib_db.create.create__DomainAutocert(
                    self.request.api_context,
                    dbDomain=dbDomain,
                )

                dbAcmeOrder = lib_db.actions_acme.do__AcmeV2_AcmeOrder__new(
                    self.request.api_context,
                    acme_order_type_id=model_utils.AcmeOrderType.ACME_AUTOMATED_NEW,
                    domains_challenged=domains_challenged,
                    private_key_cycle__renewal="account_default",
                    private_key_strategy__requested="deferred-associate",
                    processing_strategy="process_single",
                    dbAcmeAccount=dbAcmeAccount,
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
                    rval = dbDomain.as_json_config(id_only=False, active_only=True)
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
                    "domain": None,
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
                "domain": None,
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


class ViewAdminApi_QueueCertificate(Handler):
    @view_config(route_name="admin:api:queue_certificates:update", renderer=None)
    @view_config(route_name="admin:api:queue_certificates:update|json", renderer="json")
    @docify(
        {
            "endpoint": "/api/queue-certificates/update.json",
            "section": "api",
            "about": """Updates the certificates queue by inspecting active certificates for pending expiries.""",
            "POST": True,
            "GET": None,
        }
    )
    def update(self):
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(self, "/api/queue-certificates/update.json")
            return HTTPSeeOther(
                "%s/queue-certificates/all?result=error&operation=api--queue-certificates--update&error=POST+required"
                % (self.request.registry.settings["app_settings"]["admin_prefix"],)
            )
        try:
            if self.request.wants_json:
                if self.request.method != "POST":
                    return formatted_get_docs(
                        self, "/api/queue-certificates/update.json"
                    )
            queue_results = lib_db.queues.queue_certificates__update(
                self.request.api_context
            )
            if self.request.wants_json:
                return {"result": "success", "results": queue_results}
            return HTTPSeeOther(
                "%s/queue-certificates/all?result=success&operation=api--queue-certificates--update&results=%s"
                % (
                    self.request.registry.settings["app_settings"]["admin_prefix"],
                    json.dumps(queue_results, sort_keys=True),
                )
            )
        except Exception as exc:
            self.request.api_context.pyramid_transaction_rollback()
            raise
            if self.request.wants_json:
                return {"result": "error", "error": str(exc)}
            return HTTPSeeOther(
                "%s/queue-certificates?result=error&error=%s&operation=api--queue-certificates--update"
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
    @docify(
        {
            "endpoint": "/api/queue-certificates/process.json",
            "section": "api",
            "about": """Processes the QueueCertificates.""",
            "POST": True,
            "GET": None,
        }
    )
    def process(self):
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(self, "/api/queue-certificates/process.json")
            return HTTPSeeOther(
                "%s/queue-certificates/all?result=error&operation=api--queue-certificates--process&error=POST+required"
                % (self.request.registry.settings["app_settings"]["admin_prefix"],)
            )
        try:
            if self.request.wants_json:
                if self.request.method != "POST":
                    return formatted_get_docs(
                        self, "/api/queue-certificates/process.json"
                    )
            queue_results = lib_db.queues.queue_certificates__process(
                self.request.api_context
            )
            if self.request.wants_json:
                return {"result": "success", "queue_results": queue_results}
            _queue_results = ""
            if queue_results:
                _queue_results = json.dumps(queue_results, sort_keys=True)
            return HTTPSeeOther(
                "%s/queue-certificates/all?result=success&operation=api--queue-certificates--process&results=%s"
                % (
                    self.request.registry.settings["app_settings"]["admin_prefix"],
                    json.dumps(_queue_results, sort_keys=True),
                )
            )
        except Exception as exc:
            self.request.api_context.pyramid_transaction_rollback()
            raise
            if self.request.wants_json:
                return {"result": "error", "error": str(exc)}
            return HTTPSeeOther(
                "%s/queue-certificates?result=error&error=%s&operation=api--queue-certificates--process"
                % (
                    self.request.registry.settings["app_settings"]["admin_prefix"],
                    str(exc),
                )
            )
