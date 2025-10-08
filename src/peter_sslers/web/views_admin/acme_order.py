# stdlib
import logging
from typing import Any
from typing import Dict
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING
from urllib.parse import quote_plus

# pypi
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.renderers import render_to_response
from pyramid.view import view_config
from typing_extensions import Literal

# local
from ..lib import form_utils
from ..lib import formhandling
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.forms import Form_AcmeOrder_mark
from ..lib.forms import Form_AcmeOrder_new_freeform
from ..lib.forms import Form_AcmeOrder_retry
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...lib import errors
from ...model import utils as model_utils
from ...model.objects import AcmeOrder

if TYPE_CHECKING:
    from pyramid.request import Request

log = logging.getLogger("peter_sslers.web")

# ==============================================================================


def submit__acme_server_deactivate_authorizations(
    request: "Request",
    dbAcmeOrder: "AcmeOrder",
    acknowledge_transaction_commits: Optional[Literal[True]] = None,
) -> Tuple[AcmeOrder, Optional[Exception]]:
    """
    Returns: AcmeOrder
    """
    try:
        if not acknowledge_transaction_commits:
            raise errors.AcknowledgeTransactionCommitRequired()

        if not dbAcmeOrder.is_can_acme_server_deactivate_authorizations:
            raise errors.InvalidRequest(
                "ACME Server Deactivate Authorizations is not allowed for this AcmeOrder"
            )
        # deactivate the authz
        result = lib_db.actions_acme.do__AcmeV2_AcmeOrder__acme_server_deactivate_authorizations(  # noqa: F841
            request.api_context,
            dbAcmeOrder=dbAcmeOrder,
            transaction_commit=True,
        )
        # then sync the authz
        dbAcmeOrder = (
            lib_db.actions_acme.do__AcmeV2_AcmeOrder__acme_server_sync_authorizations(
                request.api_context,
                dbAcmeOrder=dbAcmeOrder,
                transaction_commit=True,
            )
        )
        # then sync the AcmeOrder
        dbAcmeOrder = lib_db.actions_acme.do__AcmeV2_AcmeOrder__acme_server_sync(
            request.api_context,
            dbAcmeOrder=dbAcmeOrder,
            transaction_commit=True,
        )

        # deactivate any authz potentials
        lib_db.update.update_AcmeOrder_deactivate_AcmeAuthorizationPotentials(
            request.api_context,
            dbAcmeOrder=dbAcmeOrder,
        )

        return dbAcmeOrder, None

    except Exception as exc:
        return dbAcmeOrder, exc


def submit__acme_server_download_certificate(
    request: "Request",
    dbAcmeOrder: "AcmeOrder",
    acknowledge_transaction_commits: Optional[Literal[True]] = None,
) -> Tuple[AcmeOrder, Optional[Exception]]:
    """
    Returns: AcmeOrder
    """
    try:
        if not acknowledge_transaction_commits:
            raise errors.AcknowledgeTransactionCommitRequired()

        if not dbAcmeOrder.is_can_acme_server_download_certificate:
            raise errors.InvalidRequest(
                "ACME Certificate Download is not allowed for this AcmeOrder"
            )

        dbAcmeOrder = lib_db.actions_acme.do__AcmeV2_AcmeOrder__download_certificate(
            request.api_context,
            dbAcmeOrder=dbAcmeOrder,
            transaction_commit=True,
        )

        return dbAcmeOrder, None

    except Exception as exc:
        return dbAcmeOrder, exc


def submit__acme_server_finalize(
    request: "Request",
    dbAcmeOrder: "AcmeOrder",
    acknowledge_transaction_commits: Optional[Literal[True]] = None,
) -> Tuple[AcmeOrder, Optional[Exception]]:
    """
    Returns: AcmeOrder
    """
    try:
        if not acknowledge_transaction_commits:
            raise errors.AcknowledgeTransactionCommitRequired()

        if not dbAcmeOrder.is_can_acme_finalize:
            raise errors.InvalidRequest(
                "ACME Finalize is not allowed for this AcmeOrder"
            )
        dbAcmeOrder = lib_db.actions_acme.do__AcmeV2_AcmeOrder__finalize(
            request.api_context,
            dbAcmeOrder=dbAcmeOrder,
            transaction_commit=True,
        )

        return dbAcmeOrder, None

    except Exception as exc:
        return dbAcmeOrder, exc


def submit__acme_server_sync(
    request: "Request",
    dbAcmeOrder: "AcmeOrder",
    acknowledge_transaction_commits: Optional[Literal[True]] = None,
) -> Tuple[AcmeOrder, Optional[Exception]]:
    """
    Returns: AcmeOrder
    """
    try:
        if not acknowledge_transaction_commits:
            raise errors.AcknowledgeTransactionCommitRequired()

        if not dbAcmeOrder.is_can_acme_server_sync:
            raise errors.InvalidRequest(
                "ACME Server Sync is not allowed for this AcmeOrder"
            )
        dbAcmeOrder = lib_db.actions_acme.do__AcmeV2_AcmeOrder__acme_server_sync(
            request.api_context,
            dbAcmeOrder=dbAcmeOrder,
            transaction_commit=True,
        )
        return dbAcmeOrder, None

    except Exception as exc:
        return dbAcmeOrder, exc


def submit__acme_server_sync_authorizations(
    request: "Request",
    dbAcmeOrder: "AcmeOrder",
    acknowledge_transaction_commits: Optional[Literal[True]] = None,
) -> Tuple[AcmeOrder, Optional[Exception]]:
    """
    Returns: AcmeOrder
    """
    try:
        if not acknowledge_transaction_commits:
            raise errors.AcknowledgeTransactionCommitRequired()

        if not dbAcmeOrder.is_can_acme_server_sync:
            raise errors.InvalidRequest(
                "ACME Server Sync is not allowed for this AcmeOrder"
            )
        # sync the authz
        dbAcmeOrder = (
            lib_db.actions_acme.do__AcmeV2_AcmeOrder__acme_server_sync_authorizations(
                request.api_context,
                dbAcmeOrder=dbAcmeOrder,
                transaction_commit=True,
            )
        )
        # sync the AcmeOrder just to be safe
        dbAcmeOrder = lib_db.actions_acme.do__AcmeV2_AcmeOrder__acme_server_sync(
            request.api_context,
            dbAcmeOrder=dbAcmeOrder,
            transaction_commit=True,
        )
        return dbAcmeOrder, None

    except Exception as exc:
        return dbAcmeOrder, exc


def submit__new_freeform(
    request: "Request",
    acknowledge_transaction_commits: Optional[Literal[True]] = None,
) -> Tuple[AcmeOrder, bool]:
    """
    Creates a RenewalConfiguration and then initiates an AcmeOrder


    IMPORTANT

    the difference between:

        http://127.0.0.1:7201/.well-known/peter_sslers/acme-order/new/freeform
        http://127.0.0.1:7201/.well-known/peter_sslers/renewal-configuration/new

    acme-order/new/freeform
        `private_key_option__primary`
            == "account_default"
                use the acme account's default pkey setting
            == "private_key_generate"
                generate a new key with `private_key_generate__primary`
            == "private_key_existing"
                use a specific key (pem md5) `private_key_existing__primary-pem_md5`

    renewal-configuration/new
        `private_key_technology__primary`
            what kind of key is this generated with?



    """
    if not acknowledge_transaction_commits:
        raise errors.AcknowledgeTransactionCommitRequired()

    (result, formStash) = formhandling.form_validate(
        request,
        schema=Form_AcmeOrder_new_freeform,
        validate_get=False,
    )
    if not result:
        raise formhandling.FormInvalid(formStash)

    # how to handle duplicate challenges for a domain?
    acme_challenge_duplicate_strategy = formStash.results[
        "acme_challenge_duplicate_strategy"
    ]
    acme_challenge_duplicate_strategy_id = (
        model_utils.AcmeChallenge_DuplicateStrategy.from_string(
            acme_challenge_duplicate_strategy
        )
    )
    if (
        acme_challenge_duplicate_strategy_id
        not in model_utils.AcmeChallenge_DuplicateStrategy._options_RenewalConfiguration_id
    ):
        formStash.fatal_field(
            field="acme_challenge_duplicate_strategy", error_field="invalid"
        )

    domains_challenged = form_utils.form_domains_challenge_typed(
        request,
        formStash,
        dbAcmeDnsServer_GlobalDefault=request.api_context.dbAcmeDnsServer_GlobalDefault,
        acme_challenge_duplicate_strategy_id=acme_challenge_duplicate_strategy_id,
    )

    is_duplicate_renewal_configuration = None

    # note: tryBlock- form_key_selection__NewOrderFreeform__primary
    try:
        (acmeAccountSelection__primary, privateKeySelection__primary) = (
            form_utils.form_selections__NewOrderFreeform(
                request,
                formStash,
                context="primary",
                require_contact=False,
                support_upload_AcmeAccount=False,
                support_upload_PrivateKey=False,
            )
        )
        assert acmeAccountSelection__primary.AcmeAccount is not None
        assert privateKeySelection__primary.PrivateKey is not None

        (acmeAccountSelection__backup, privateKeySelection__backup) = (
            form_utils.form_selections__NewOrderFreeform(
                request,
                formStash,
                context="backup",
                require_contact=False,
                support_upload_AcmeAccount=False,
                support_upload_PrivateKey=False,
            )
        )
        if formStash.results["private_key_option__backup"] in (None, "none"):
            assert privateKeySelection__backup.PrivateKey is None
        else:
            assert privateKeySelection__backup.PrivateKey is not None

        # shared
        note = formStash.results["note"]
        processing_strategy = formStash.results["processing_strategy"]

        # PRIMARY cert
        acme_profile__primary = formStash.results["acme_profile__primary"]
        private_key_cycle__primary = formStash.results["private_key_cycle__primary"]
        private_key_cycle_id__primary = model_utils.PrivateKey_Cycle.from_string(
            private_key_cycle__primary
        )
        private_key_technology_id__primary = (
            privateKeySelection__primary.private_key_technology_id
        )

        # BACKUP cert
        acme_profile__backup: Optional[str] = None
        private_key_cycle__backup: Optional[str] = None
        private_key_cycle_id__backup: Optional[int] = None
        private_key_technology_id__backup: Optional[int] = None

        if acmeAccountSelection__backup.AcmeAccount:
            # these are only required if we're doing backup cert

            private_key_option__backup = formStash.results["private_key_option__backup"]
            if private_key_option__backup in (None, "none", ""):
                formStash.fatal_field(
                    field="private_key_option__backup",
                    error_field="Required for Backup Certificates",
                )

            private_key_cycle__backup = formStash.results["private_key_cycle__backup"]
            if not private_key_cycle__backup:
                formStash.fatal_field(
                    field="private_key_cycle__backup",
                    error_field="Required for Backup Certificates",
                )
            private_key_cycle_id__backup = model_utils.PrivateKey_Cycle.from_string(
                private_key_cycle__backup
            )
            private_key_technology_id__backup = (
                privateKeySelection__backup.private_key_technology_id
            )

            acme_profile__backup = formStash.results["acme_profile__backup"]
            private_key_generate__backup = formStash.results[
                "private_key_generate__backup"
            ]
            if private_key_generate__backup:
                private_key_technology_id__backup = (
                    model_utils.KeyTechnology.from_string(private_key_generate__backup)
                )

        # validate PrivateKey Selection
        # raises `formStash.fatal_field` if keys are invalid for this usage
        form_utils.validate_PrivateKeySelection_selected(
            request,
            formStash,
            privateKeySelection__primary,
            privateKeySelection__backup,
        )

        #
        # validate the domains
        #

        domains_all = []
        # check for blocklists here
        # this might be better in the AcmeOrder processor, but the orders are by UniqueFQDNSet
        # this may raise: [errors.AcmeDomainsBlocklisted, errors.AcmeDomainsInvalid]
        for challenge_, domains_ in domains_challenged.items():
            if domains_:
                lib_db.validate.validate_domain_names(request.api_context, domains_)
                if challenge_ == "dns-01":
                    # check to ensure the domains are configured for dns-01
                    # this may raise errors.AcmeDomainsRequireConfigurationAcmeDNS
                    try:
                        lib_db.validate.ensure_domains_dns01(
                            request.api_context, domains_
                        )
                    except errors.AcmeDomainsRequireConfigurationAcmeDNS as exc:
                        # in "experimental" mode, we may want to use specific
                        # acme-dns servers and not the global one
                        if (
                            request.api_context.application_settings["acme_dns_support"]
                            == "experimental"
                        ):
                            raise
                        # in "basic" mode we can just associate these to the global option
                        if not request.api_context.dbAcmeDnsServer_GlobalDefault:
                            formStash.fatal_field(
                                "domain_names_dns01",
                                "No global acme-dns server configured.",
                            )
                        assert (
                            request.api_context.dbAcmeDnsServer_GlobalDefault
                            is not None
                        )
                        # exc.args[0] will be the listing of domains
                        (domainObjects, adnsAccountObjects) = (
                            lib_db.associate.ensure_domain_names_to_acmeDnsServer(
                                request.api_context,
                                exc.args[0],
                                request.api_context.dbAcmeDnsServer_GlobalDefault,
                                discovery_type="via renewal_configuration.new",
                            )
                        )
                domains_all.extend(domains_)

        # create the configuration
        # this will create:
        # * model_utils.RenewableConfig
        # * model_utils.UniquelyChallengedFQDNSet2Domain
        # * model_utils.UniqueFQDNSet
        # note: tryBlock3- create__RenewalConfiguration
        try:
            dbRenewalConfiguration = lib_db.create.create__RenewalConfiguration(
                request.api_context,
                domains_challenged=domains_challenged,
                acme_challenge_duplicate_strategy_id=acme_challenge_duplicate_strategy_id,
                # PRIMARY cert
                dbAcmeAccount__primary=acmeAccountSelection__primary.AcmeAccount,
                private_key_cycle_id__primary=private_key_cycle_id__primary,
                private_key_technology_id__primary=private_key_technology_id__primary,
                acme_profile__primary=acme_profile__primary,
                # BACKUP cert
                dbAcmeAccount__backup=acmeAccountSelection__backup.AcmeAccount,
                private_key_cycle_id__backup=private_key_cycle_id__backup,
                private_key_technology_id__backup=private_key_technology_id__backup,
                acme_profile__backup=acme_profile__backup,
                # misc
                note=note,
            )
            is_duplicate_renewal_configuration = False
        except errors.FieldError as exc:
            formStash.fatal_field(exc.args[0], exc.args[1])

        except errors.DuplicateRenewalConfiguration as exc:
            is_duplicate_renewal_configuration = True
            # we could raise exc to abort, but this is likely preferred
            dbRenewalConfiguration = exc.args[0]

        # commit this
        request.api_context.pyramid_transaction_commit()

        # unused because we're not uploading accounts
        # migrate_a = formStash.results["account__order_default_private_key_technology"]
        # migrate_b = formStash.results["account__order_default_private_key_cycle"]

        # ???: should this be done elsewhere?

        # check for blocklists here
        # this might be better in the AcmeOrder processor, but the orders are by UniqueFQDNSet
        # this may raise: [errors.AcmeDomainsBlocklisted, errors.AcmeDomainsInvalid]
        for challenge_, domains_ in domains_challenged.items():
            if domains_:
                # # already validated in the first loop above
                # lib_db.validate.validate_domain_names(
                #    request.api_context, domains_
                # )
                if challenge_ == "dns-01":
                    # check to ensure the domains are configured for dns-01
                    # this may raise errors.AcmeDomainsRequireConfigurationAcmeDNS
                    lib_db.validate.ensure_domains_dns01(request.api_context, domains_)
        # note: tryBlock- do__AcmeV2_AcmeOrder__new
        try:
            dbAcmeOrder = lib_db.actions_acme.do__AcmeV2_AcmeOrder__new(
                request.api_context,
                dbRenewalConfiguration=dbRenewalConfiguration,
                processing_strategy=processing_strategy,
                acme_order_type_id=model_utils.AcmeOrder_Type.ACME_ORDER_NEW_FREEFORM,
                note=note,
                dbPrivateKey=privateKeySelection__primary.PrivateKey,
                transaction_commit=True,
            )

        except errors.DuplicateAcmeOrder as exc:
            raise formStash.fatal_form(error_main=exc.args[0])

        except errors.FieldError as exc:
            raise formStash.fatal_field(
                field=exc.args[0],
                error_field=exc.args[1],
            )

        except Exception as exc:

            # unpack a `errors.AcmeOrderCreatedError` to local vars
            if isinstance(exc, errors.AcmeOrderCreatedError):
                dbAcmeOrder = exc.acme_order
                exc = exc.original_exception

                formStash.assets["is_duplicate_renewal_configuration"] = True
                formStash.assets["AcmeOrder"] = dbAcmeOrder
                formStash.assets["AcmeOrderCreatedError"] = exc

            formStash.fatal_form(
                error_main="%s" % exc,
            )

        return dbAcmeOrder, is_duplicate_renewal_configuration

    except (errors.ConflictingObject,) as exc:
        formStash.fatal_form(error_main=str(exc))

    except (
        errors.AcmeDomainsInvalid,
        errors.AcmeDomainsBlocklisted,
        errors.AcmeDomainsRequireConfigurationAcmeDNS,
    ) as exc:
        formStash.fatal_form(error_main=str(exc))

    except errors.AcmeDuplicateChallenges as exc:
        formStash.fatal_form(error_main=str(exc))

    except errors.AcmeDnsServerError as exc:  # noqa: F841
        formStash.fatal_form(error_main="Error communicating with the acme-dns server.")

    except (errors.DuplicateRenewalConfiguration,) as exc:
        message = (
            "This appears to be a duplicate of RenewalConfiguration: `%s`."
            % exc.args[0].id
        )
        formStash.fatal_form(error_main=message)

    except (
        errors.AcmeError,
        errors.InvalidRequest,
    ) as exc:
        formStash.fatal_form(error_main=str(exc))

    except errors.UnknownAcmeProfile_Local as exc:  # noqa: F841
        # exc.args: var(matches field), submitted, allowed
        formStash.fatal_field(
            field=exc.args[0],
            error_field="Unknown acme_profile (%s); not one of: %s."
            % (exc.args[1], exc.args[2]),
        )


def submit__process(
    request: "Request",
    dbAcmeOrder: "AcmeOrder",
    acknowledge_transaction_commits: Optional[Literal[True]] = None,
) -> Tuple[AcmeOrder, Optional[Exception]]:
    """
    Returns: AcmeOrder
    """
    try:
        if not acknowledge_transaction_commits:
            raise errors.AcknowledgeTransactionCommitRequired()

        if not dbAcmeOrder.is_can_acme_process:
            raise errors.InvalidRequest(
                "ACME Process is not allowed for this AcmeOrder"
            )

        dbAcmeOrder = lib_db.actions_acme.do__AcmeV2_AcmeOrder__process(
            request.api_context,
            dbAcmeOrder=dbAcmeOrder,
            transaction_commit=True,
        )
        return dbAcmeOrder, None

    except Exception as exc:
        return dbAcmeOrder, exc


def submit__mark(
    request: "Request",
    dbAcmeOrder: "AcmeOrder",
    acknowledge_transaction_commits: Optional[Literal[True]] = None,
) -> Tuple[AcmeOrder, Optional[str]]:
    """
    Returns: Tuple[AcmeOrder, action]
    """
    if not acknowledge_transaction_commits:
        raise errors.AcknowledgeTransactionCommitRequired()

    action = request.params.get("action", None)
    if action == "invalid":
        if not dbAcmeOrder.is_can_mark_invalid:
            raise errors.InvalidRequest("Can not mark this order as 'invalid'.")
        lib_db.actions_acme.updated_AcmeOrder_status(
            request.api_context,
            dbAcmeOrder,
            {
                "status": "invalid",
            },
            transaction_commit=True,
        )

    elif action == "deactivate":
        lib_db.update.update_AcmeOrder_deactivate(
            request.api_context,
            dbAcmeOrder,
            is_manual=True,
        )

    else:
        raise errors.InvalidRequest("invalid `action`")

    return dbAcmeOrder, action


def submit__retry(
    request: "Request",
    dbAcmeOrder: "AcmeOrder",
    acknowledge_transaction_commits: Optional[Literal[True]] = None,
) -> Tuple[Optional[AcmeOrder], Optional[str]]:
    """
    returns [AcmeOrder, error]
    note: AcmeOrder can be returned with an error
    """
    if not acknowledge_transaction_commits:
        raise errors.AcknowledgeTransactionCommitRequired()

    (result, formStash) = formhandling.form_validate(
        request,
        schema=Form_AcmeOrder_retry,
        validate_get=False,
        # allow an empty POST, which will then invoke `if_missing` for the default
        allow_empty=True,
    )
    if not result:
        raise formhandling.FormInvalid(formStash)

    if not dbAcmeOrder.is_can_acme_server_sync:
        formStash.fatal_form(
            error_main="ACME Retry is not allowed for this AcmeOrder (I)"
        )
    if not dbAcmeOrder.is_can_retry:
        formStash.fatal_form(
            error_main="ACME Retry is not allowed for this AcmeOrder (II)"
        )

    acme_order_retry_strategy_id = model_utils.AcmeOrder_RetryStrategy.from_string(
        formStash.results["acme_order_retry_strategy"]
    )

    try:
        dbAcmeOrderNew = lib_db.actions_acme.do__AcmeV2_AcmeOrder__retry(
            request.api_context,
            dbAcmeOrder=dbAcmeOrder,
            acme_order_retry_strategy_id=acme_order_retry_strategy_id,
            transaction_commit=True,
        )
        return dbAcmeOrderNew, None

    except errors.AcmeOrderCreatedError as exc:
        # unpack a `errors.AcmeOrderCreatedError` to local vars
        dbAcmeOrderNew = exc.acme_order
        exc = exc.original_exception
        return dbAcmeOrderNew, exc.args[0]

    except errors.DuplicateAcmeOrder as exc:
        return None, exc.args[0]

    except Exception as exc:
        return None, exc.args[0]


class View_List(Handler):
    @view_config(
        route_name="admin:acme_orders",
    )
    @view_config(
        route_name="admin:acme_orders|json",
    )
    def list_redirect(self):
        url_all = (
            "%s/acme-orders/active"
            % self.request.api_context.application_settings["admin_prefix"]
        )
        if self.request.wants_json:
            url_all = "%s.json" % url_all
        return HTTPSeeOther(url_all)

    @view_config(route_name="admin:acme_orders:all", renderer="/admin/acme_orders.mako")
    @view_config(
        route_name="admin:acme_orders:active", renderer="/admin/acme_orders.mako"
    )
    @view_config(
        route_name="admin:acme_orders:finished", renderer="/admin/acme_orders.mako"
    )
    @view_config(
        route_name="admin:acme_orders:all-paginated", renderer="/admin/acme_orders.mako"
    )
    @view_config(
        route_name="admin:acme_orders:active-paginated",
        renderer="/admin/acme_orders.mako",
    )
    @view_config(
        route_name="admin:acme_orders:finished-paginated",
        renderer="/admin/acme_orders.mako",
    )
    @view_config(route_name="admin:acme_orders:all|json", renderer="json")
    @view_config(route_name="admin:acme_orders:active|json", renderer="json")
    @view_config(route_name="admin:acme_orders:finished|json", renderer="json")
    @view_config(route_name="admin:acme_orders:all-paginated|json", renderer="json")
    @view_config(route_name="admin:acme_orders:active-paginated|json", renderer="json")
    @view_config(
        route_name="admin:acme_orders:finished-paginated|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/acme-orders.json",
            "section": "acme-order",
            "about": """list AcmeOrder(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-orders.json",
        }
    )
    @docify(
        {
            "endpoint": "/acme-orders/{PAGE}.json",
            "section": "acme-order",
            "example": "curl {ADMIN_PREFIX}/acme-orders/1.json",
            "variant_of": "/acme-orders.json",
        }
    )
    @docify(
        {
            "endpoint": "/acme-orders/all.json",
            "section": "acme-order",
            "about": """list AcmeOrder(s) ALL""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-orders/all.json",
        }
    )
    @docify(
        {
            "endpoint": "/acme-orders/all/{PAGE}.json",
            "section": "acme-order",
            "example": "curl {ADMIN_PREFIX}/acme-orders/all/1.json",
            "variant_of": "/acme-orders/all.json",
        }
    )
    @docify(
        {
            "endpoint": "/acme-orders/active.json",
            "section": "acme-order",
            "about": """list AcmeOrder(s) Active""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-orders/active.json",
        }
    )
    @docify(
        {
            "endpoint": "/acme-orders/active/{PAGE}.json",
            "section": "acme-order",
            "example": "curl {ADMIN_PREFIX}/acme-orders/active/1.json",
            "variant_of": "/acme-orders/active.json",
        }
    )
    @docify(
        {
            "endpoint": "/acme-orders/finished.json",
            "section": "acme-order",
            "about": """list AcmeOrder(s) Finished""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-orders/finished.json",
        }
    )
    @docify(
        {
            "endpoint": "/acme-orders/finished/{PAGE}.json",
            "section": "acme-order",
            "example": "curl {ADMIN_PREFIX}/acme-orders/finished/1.json",
            "variant_of": "/acme-orders/finished.json",
        }
    )
    def list(self):
        sidenav_option = None
        active_only = None
        if self.request.matched_route.name in (
            "admin:acme_orders:all",
            "admin:acme_orders:all-paginated",
            "admin:acme_orders:all|json",
            "admin:acme_orders:all-paginated|json",
        ):
            sidenav_option = "all"
            active_only = None
        elif self.request.matched_route.name in (
            "admin:acme_orders:active",
            "admin:acme_orders:active-paginated",
            "admin:acme_orders:active|json",
            "admin:acme_orders:active-paginated|json",
        ):
            sidenav_option = "active"
            active_only = True
        elif self.request.matched_route.name in (
            "admin:acme_orders:finished",
            "admin:acme_orders:finished-paginated",
            "admin:acme_orders:finished|json",
            "admin:acme_orders:finished-paginated|json",
        ):
            sidenav_option = "finished"
            active_only = False

        url_template = "%s/acme-orders/%s/{0}" % (
            self.request.api_context.application_settings["admin_prefix"],
            sidenav_option,
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template

        items_count = lib_db.get.get__AcmeOrder__count(
            self.request.api_context, active_only=active_only
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__AcmeOrder__paginated(
            self.request.api_context,
            active_only=active_only,
            limit=items_per_page,
            offset=offset,
        )
        if self.request.wants_json:
            # admin_url = self.request.admin_url
            return {
                "AcmeOrders": [i.as_json for i in items_paged],
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "AcmeOrders_count": items_count,
            "AcmeOrders": items_paged,
            "pager": pager,
            "sidenav_option": sidenav_option,
        }

    @view_config(
        route_name="admin:acme_orders:active:acme_server:sync",
    )
    @view_config(
        route_name="admin:acme_orders:active:acme_server:sync|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/acme-orders/active/acme-server/sync.json",
            "section": "acme-order",
            "about": """sync AcmeOrders to AcmeServers""",
            "POST": True,
            "GET": None,
        }
    )
    def active_acme_server_sync(self):
        base_url = (
            "%s/acme-orders/active"
            % self.request.api_context.application_settings["admin_prefix"]
        )
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(
                    self, "/acme-orders/active/acme-server/sync.json"
                )
            return HTTPSeeOther(
                "%s?result=error&operation=acme+server+sync&message=HTTP+POST+required"
                % base_url
            )
        # TODO: batch this with limits and offsets?
        items_paged = lib_db.get.get__AcmeOrder__paginated(
            self.request.api_context,
            active_only=True,
            limit=None,
            offset=0,
        )
        _order_ids_pass = []
        _order_ids_fail = []
        for dbAcmeOrder in items_paged:
            try:
                dbAcmeOrder = (
                    lib_db.actions_acme.do__AcmeV2_AcmeOrder__acme_server_sync(
                        self.request.api_context,
                        dbAcmeOrder=dbAcmeOrder,
                        transaction_commit=True,
                    )
                )
                self.request.api_context.pyramid_transaction_commit()
                _order_ids_pass.append(dbAcmeOrder.id)
            except Exception as exc:  # noqa: F841
                _order_ids_fail.append(dbAcmeOrder.id)
        if self.request.wants_json:
            # admin_url = self.request.admin_url
            return {
                "result": "success",
                "AcmeOrderIds.success": _order_ids_pass,
                "AcmeOrderIds.error": _order_ids_fail,
            }
        return HTTPSeeOther(
            "%s?result=success&operation=acme+server+sync&acme_order_ids.success=%s&acme_order_ids.error=%s"
            % (
                base_url,
                ",".join(["%s" % i for i in _order_ids_pass]),
                ",".join(["%s" % i for i in _order_ids_fail]),
            )
        )


# ------------------------------------------------------------------------------


class View_Focus(Handler):
    dbAcmeOrder: Optional[AcmeOrder] = None

    def _focus(self, eagerload_web=False) -> AcmeOrder:
        if self.dbAcmeOrder is None:
            dbAcmeOrder = lib_db.get.get__AcmeOrder__by_id(
                self.request.api_context,
                self.request.matchdict["id"],
                eagerload_web=eagerload_web,
            )
            if not dbAcmeOrder:
                raise HTTPNotFound("the order was not found")
            self.dbAcmeOrder = dbAcmeOrder
            self._focus_url = "%s/acme-order/%s" % (
                self.request.admin_url,
                self.dbAcmeOrder.id,
            )
        return self.dbAcmeOrder

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_order:focus", renderer="/admin/acme_order-focus.mako"
    )
    @view_config(route_name="admin:acme_order:focus|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-order/{ID}.json",
            "section": "acme-order",
            "about": """AcmeOrder focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-order/1.json",
        }
    )
    def focus(self):
        dbAcmeOrder = self._focus(eagerload_web=True)
        if self.request.wants_json:
            return {
                "AcmeOrder": dbAcmeOrder.as_json,
            }
        return {"project": "peter_sslers", "AcmeOrder": dbAcmeOrder}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_order:focus:audit",
        renderer="/admin/acme_order-focus-audit.mako",
    )
    @view_config(route_name="admin:acme_order:focus:audit|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-order/{@id}/audit.json",
            "section": "acme-order",
            "about": """AcmeOrder - audit""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/acme-order/1/audit.json",
        }
    )
    def audit(self):
        dbAcmeOrder = self._focus(eagerload_web=True)
        if TYPE_CHECKING:
            assert dbAcmeOrder is not None
        if self.request.wants_json:
            audit_report: Dict = {
                "result": "success",
                "AuditReport": {
                    "AcmeOrder": {
                        "id": dbAcmeOrder.id,
                        "timestamp_created": dbAcmeOrder.timestamp_created_isoformat,
                        "acme_order_type": dbAcmeOrder.acme_order_type,
                        "acme_order_processing_strategy": dbAcmeOrder.acme_order_processing_strategy,
                        "acme_order_processing_status": dbAcmeOrder.acme_order_processing_status,
                        "is_processing": dbAcmeOrder.is_processing,
                        "acme_status_order": dbAcmeOrder.acme_status_order,
                        "timestamp_expires": dbAcmeOrder.timestamp_expires_isoformat,
                        "private_key_strategy__requested": dbAcmeOrder.private_key_strategy__requested,
                        "private_key_strategy__final": dbAcmeOrder.private_key_strategy__final,
                        "domains": dbAcmeOrder.domains_as_list,
                    },
                    "AcmeAccount": {
                        "id": dbAcmeOrder.acme_account_id,
                        "contact": dbAcmeOrder.acme_account.contact,
                        "order_default_private_key_cycle": dbAcmeOrder.acme_account.order_default_private_key_cycle,
                        "order_default_private_key_technology": dbAcmeOrder.acme_account.order_default_private_key_technology,
                    },
                    "AcmeServer": {
                        "id": dbAcmeOrder.acme_account.acme_server_id,
                        "name": dbAcmeOrder.acme_account.acme_server.name,
                        "url": dbAcmeOrder.acme_account.acme_server.url,
                    },
                    "PrivateKey": {
                        "id": dbAcmeOrder.private_key_id,
                        "private_key_source": dbAcmeOrder.private_key.private_key_source,
                        "private_key_type": dbAcmeOrder.private_key.private_key_type,
                    },
                    "UniqueFQDNSet": {
                        "id": dbAcmeOrder.unique_fqdn_set_id,
                    },
                    "AcmeAuthorizations": [],
                },
            }
            auths_list = []
            for to_acme_authorization in dbAcmeOrder.to_acme_authorizations:
                dbAcmeAuthorization = to_acme_authorization.acme_authorization
                dbAcmeChallenge_http01 = dbAcmeAuthorization.acme_challenge_http_01
                auth_local: Dict = {
                    "AcmeAuthorization": {
                        "id": dbAcmeAuthorization.id,
                        "acme_status_authorization": dbAcmeAuthorization.acme_status_authorization,
                        "timestamp_updated": dbAcmeAuthorization.timestamp_updated_isoformat,
                    },
                    "AcmeChallenges": {},
                    "Domain": None,
                }
                if dbAcmeAuthorization.domain_id:
                    auth_local["Domain"] = {
                        "id": dbAcmeAuthorization.domain_id,
                        "domain_name": dbAcmeAuthorization.domain.domain_name,
                    }
                if dbAcmeChallenge_http01:
                    auth_local["AcmeChallenges"]["http-01"] = {
                        "id": dbAcmeChallenge_http01.id,
                        "acme_status_challenge": dbAcmeChallenge_http01.acme_status_challenge,
                        "timestamp_updated": dbAcmeChallenge_http01.timestamp_updated_isoformat,
                        "keyauthorization": dbAcmeChallenge_http01.keyauthorization,
                    }

                auths_list.append(auth_local)
            audit_report["AuditReport"]["AcmeAuthorizations"] = auths_list
            return audit_report
        return {"project": "peter_sslers", "AcmeOrder": dbAcmeOrder}


class View_Focus_Manipulate(View_Focus):
    @view_config(
        route_name="admin:acme_order:focus:acme_event_logs",
        renderer="/admin/acme_order-focus-acme_event_logs.mako",
    )
    @view_config(
        route_name="admin:acme_order:focus:acme_event_logs-paginated",
        renderer="/admin/acme_order-focus-acme_event_logs.mako",
    )
    def acme_event_logs(self):
        dbAcmeOrder = self._focus(eagerload_web=True)

        items_count = lib_db.get.get__AcmeEventLogs__by_AcmeOrderId__count(
            self.request.api_context, dbAcmeOrder.id
        )
        url_template = "%s/acme-event-logs/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__AcmeEventLogs__by_AcmeOrderId__paginated(
            self.request.api_context,
            dbAcmeOrder.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "AcmeOrder": dbAcmeOrder,
            "AcmeEventLogs_count": items_count,
            "AcmeEventLogs": items_paged,
            "pager": pager,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_order:focus:acme_server:sync", renderer=None)
    @view_config(
        route_name="admin:acme_order:focus:acme_server:sync|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/acme-order/{ID}/acme-server/sync.json",
            "section": "acme-order",
            "about": """AcmeOrder focus: AcmeServer sync""",
            "POST": True,
            "GET": None,
            "instructions": "curl -X {ADMIN_PREFIX}/acme-order/1/acme-server/sync.json",
            "example": "curl -X POST {ADMIN_PREFIX}/acme-order/1/acme-server/sync.json",
        }
    )
    def acme_server_sync(self):
        """
        Acme Refresh should just update the record against the acme server.
        """
        dbAcmeOrder = self._focus(eagerload_web=True)
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(
                    self, "/acme-order/{ID}/acme-server/sync.json"
                )
            return HTTPSeeOther(
                "%s?result=error&operation=acme+server+sync&message=HTTP+POST+required"
                % self._focus_url
            )
        try:
            dbAcmeOrder, exc = submit__acme_server_sync(
                self.request,
                dbAcmeOrder=dbAcmeOrder,
                acknowledge_transaction_commits=True,
            )
            if exc:
                raise exc
            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "acme-server/sync",
                    "AcmeOrder": dbAcmeOrder.as_json,
                }
            return HTTPSeeOther(
                "%s?result=success&operation=acme+server+sync" % self._focus_url
            )
        except Exception as exc:
            error = str(exc)
            if isinstance(exc, (errors.AcmeError, errors.InvalidRequest)):
                error = exc.args[0]
            if self.request.wants_json:
                return {
                    "result": "error",
                    "operation": "acme-server/sync",
                    "error": error,
                }
            return HTTPSeeOther(
                "%s?result=error&error=%s&operation=acme+server+sync"
                % (self._focus_url, quote_plus(error))
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_order:focus:acme_server:sync_authorizations",
        renderer=None,
    )
    @view_config(
        route_name="admin:acme_order:focus:acme_server:sync_authorizations|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-order/{ID}/acme-server/sync-authorizations.json",
            "section": "acme-order",
            "about": """AcmeOrder focus: AcmeServer sync-authorizations""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/acme-order/1/acme-server/sync-authorizations.json",
            "example": "curl -X POST {ADMIN_PREFIX}/acme-order/1/acme-server/sync-authorizations.json",
        }
    )
    def acme_server_sync_authorizations(self):
        """
        sync any auths on the server.
        """
        dbAcmeOrder = self._focus(eagerload_web=True)
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(
                    self,
                    "/acme-order/{ID}/acme-server/sync-authorizations.json",
                )
            return HTTPSeeOther(
                "%s?result=error&operation=acme+server+sync+authorizations&message=HTTP+POST+required"
                % self._focus_url
            )
        try:
            dbAcmeOrder, exc = submit__acme_server_sync_authorizations(
                self.request,
                dbAcmeOrder=dbAcmeOrder,
                acknowledge_transaction_commits=True,
            )
            if exc:
                raise exc
            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "acme-server/sync-authorizations",
                    "AcmeOrder": dbAcmeOrder.as_json,
                }
            return HTTPSeeOther(
                "%s?result=success&operation=acme+server+sync+authorizations"
                % self._focus_url
            )
        except Exception as exc:
            error = str(exc)
            if isinstance(exc, (errors.AcmeError, errors.InvalidRequest)):
                error = exc.args[0]
            if self.request.wants_json:
                return {
                    "result": "error",
                    "operation": "acme-server/sync-authorizations",
                    "error": error,
                }
            return HTTPSeeOther(
                "%s?result=error&error=%s&operation=acme+server+sync+authorizations"
                % (self._focus_url, quote_plus(error))
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_order:focus:acme_server:deactivate_authorizations",
        renderer=None,
    )
    @view_config(
        route_name="admin:acme_order:focus:acme_server:deactivate_authorizations|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-order/{ID}/acme-server/deactivate-authorizations.json",
            "section": "acme-order",
            "about": """AcmeOrder focus: AcmeServer deactivate-authorizations""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/acme-order/1/acme-server/deactivate-authorizations.json",
            "example": "curl -X POST {ADMIN_PREFIX}/acme-order/1/acme-server/deactivate-authorizations.json",
        }
    )
    def acme_server_deactivate_authorizations(self):
        """
        Deactivate any auths on the server.
        Note: Authz are not necessarily bound to a single order, such as with
              LetsEncrypt; therefore, deactivating an AcmeOrder will not
              necessarily deactivate the Authz.
        """
        dbAcmeOrder = self._focus(eagerload_web=True)
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(
                    self,
                    "/acme-order/{ID}/acme-server/deactivate-authorizations.json",
                )
            return HTTPSeeOther(
                "%s?result=error&operation=acme+server+deactivate+authorizations&message=HTTP+POST+required"
                % self._focus_url
            )
        try:
            dbAcmeOrder, exc = submit__acme_server_deactivate_authorizations(
                self.request,
                dbAcmeOrder=dbAcmeOrder,
                acknowledge_transaction_commits=True,
            )
            if exc:
                raise exc
            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "acme-server/deactivate-authorizations",
                    "AcmeOrder": dbAcmeOrder.as_json,
                }
            return HTTPSeeOther(
                "%s?result=success&operation=acme+server+deactivate+authorizations"
                % self._focus_url
            )
        except Exception as exc:
            error = str(exc)
            if isinstance(exc, (errors.AcmeError, errors.InvalidRequest)):
                error = exc.args[0]
            if self.request.wants_json:
                return {
                    "result": "error",
                    "operation": "acme-server/deactivate-authorizations",
                    "error": error,
                }
            return HTTPSeeOther(
                "%s?result=error&error=%s&operation=acme+server+deactivate+authorizations"
                % (self._focus_url, quote_plus(error))
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_order:focus:acme_server:download_certificate",
        renderer=None,
    )
    @view_config(
        route_name="admin:acme_order:focus:acme_server:download_certificate|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/acme-order/{ID}/acme-server/download-certificate.json",
            "section": "acme-order",
            "about": """AcmeOrder focus: AcmeServer download-certificate""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/acme-order/1/acme-server/download-certificate.json",
            "example": "curl -X POST {ADMIN_PREFIX}/acme-order/1/acme-server/download-certificate.json",
        }
    )
    def acme_server_download_certificate(self):
        """
        This endpoint is for Immediately Renewing the AcmeOrder with overrides on the keys
        """
        dbAcmeOrder = self._focus(eagerload_web=True)
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(
                    self,
                    "/acme-order/{ID}/acme-server/download-certificate.json",
                )
            return HTTPSeeOther(
                "%s?result=error&operation=acme+server+download+certificate&message=HTTP+POST+required"
                % self._focus_url
            )
        try:
            dbAcmeOrder, exc = submit__acme_server_download_certificate(
                self.request,
                dbAcmeOrder=dbAcmeOrder,
                acknowledge_transaction_commits=True,
            )
            if exc:
                raise exc
            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "acme-server/download-certificate",
                    "AcmeOrder": dbAcmeOrder.as_json,
                }
            return HTTPSeeOther(
                "%s?result=success&operation=acme+server+download+certificate"
                % self._focus_url
            )
        except Exception as exc:
            error = str(exc)
            if isinstance(exc, (errors.AcmeError, errors.InvalidRequest)):
                error = exc.args[0]
            if self.request.wants_json:
                return {
                    "result": "error",
                    "operation": "acme-server/download-certificate",
                    "error": error,
                }
            return HTTPSeeOther(
                "%s?result=error&error=%s&operation=acme+server+download+certificate"
                % (self._focus_url, quote_plus(error))
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_order:focus:acme_process", renderer=None)
    @view_config(route_name="admin:acme_order:focus:acme_process|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-order/{ID}/acme-process.json",
            "section": "acme-order",
            "about": """AcmeOrder focus: AcmeServer acme-process""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/acme-order/1/acme-process.json",
            "example": "curl -X POST {ADMIN_PREFIX}/acme-order/1/acme-process.json",
        }
    )
    def process_order(self):
        """
        only certain orders can be processed
        """
        dbAcmeOrder = self._focus(eagerload_web=True)
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(self, "/acme-order/{ID}/acme-process.json")
            return HTTPSeeOther(
                "%s?result=error&operation=acme+process&message=HTTP+POST+required"
                % self._focus_url
            )
        try:
            dbAcmeOrder, exc = submit__process(
                self.request,
                dbAcmeOrder=dbAcmeOrder,
                acknowledge_transaction_commits=True,
            )
            if exc:
                raise exc
            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "acme-process",
                    "AcmeOrder": dbAcmeOrder.as_json,
                }
            return HTTPSeeOther(
                "%s?result=success&operation=acme+process" % self._focus_url
            )
        except Exception as exc:
            error = str(exc)
            if isinstance(exc, (errors.AcmeError, errors.InvalidRequest)):
                error = exc.args[0]
            if self.request.wants_json:
                return {
                    "result": "error",
                    "operation": "acme-process",
                    "error": error,
                }
            return HTTPSeeOther(
                "%s?result=error&error=%s&operation=acme+process"
                % (self._focus_url, quote_plus(error))
            )

    @view_config(route_name="admin:acme_order:focus:acme_finalize", renderer=None)
    @view_config(
        route_name="admin:acme_order:focus:acme_finalize|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/acme-order/{ID}/acme-finalize.json",
            "section": "acme-order",
            "about": """AcmeOrder focus: acme-finalize""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/acme-order/1/acme-finalize.json",
            "example": "curl -X POST {ADMIN_PREFIX}/acme-order/1/acme-finalize.json",
        }
    )
    def finalize_order(self):
        """
        only certain orders can be finalized
        """
        dbAcmeOrder = self._focus(eagerload_web=True)
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(self, "/acme-order/{ID}/acme-finalize.json")
            return HTTPSeeOther(
                "%s?result=error&operation=acme+finalize&message=HTTP+POST+required"
                % self._focus_url
            )
        try:
            dbAcmeOrder, exc = submit__acme_server_finalize(
                self.request,
                dbAcmeOrder=dbAcmeOrder,
                acknowledge_transaction_commits=True,
            )
            if exc:
                raise exc
            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "finalize-order",
                    "AcmeOrder": dbAcmeOrder.as_json,
                }
            return HTTPSeeOther(
                "%s?result=success&operation=acme+finalize" % self._focus_url
            )
        except Exception as exc:
            error = str(exc)
            if isinstance(exc, (errors.AcmeError, errors.InvalidRequest)):
                error = exc.args[0]
            if self.request.wants_json:
                return {
                    "result": "error",
                    "operation": "finalize-order",
                    "error": error,
                }
            return HTTPSeeOther(
                "%s?result=error&error=%s&operation=acme+finalize"
                % (self._focus_url, quote_plus(error))
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_order:focus:mark", renderer=None)
    @view_config(route_name="admin:acme_order:focus:mark|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-order/{ID}/mark.json",
            "section": "acme-order",
            "about": """AcmeOrder focus: Mark""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/acme-order/1/mark.json",
            "example": "curl --form 'action=invalid' {ADMIN_PREFIX}/acme-order/1/mark.json",
            "form_fields": {
                "action": "The action",
            },
            "valid_options": {
                "action": Form_AcmeOrder_mark.fields["action"].list,
            },
        }
    )
    def mark_order(self):
        """
        Mark an AcmeOrder
        Note: Authz are not necessarily bound to a single order, such as with
              LetsEncrypt; therefore, deactivating an AcmeOrder will not
              necessarily deactivate the Authz.
        """
        dbAcmeOrder = self._focus(eagerload_web=True)
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(self, "/acme-order/{ID}/mark.json")
            return HTTPSeeOther(
                "%s?result=error&operation=mark&message=HTTP+POST+required"
                % self._focus_url
            )
        action: Optional[str] = None
        try:
            (dbAcmeOrder, action) = submit__mark(
                self.request,
                dbAcmeOrder=dbAcmeOrder,
                acknowledge_transaction_commits=True,
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "mark",
                    "action": action,
                    "AcmeOrder": dbAcmeOrder.as_json,
                }
            return HTTPSeeOther(
                "%s?result=success&operation=mark&action=%s" % (self._focus_url, action)
            )

        except (errors.InvalidRequest, errors.InvalidTransition) as exc:
            if self.request.wants_json:
                return {
                    "result": "error",
                    "operation": "mark",
                    "error": exc.args[0],
                }
            url_failure = "%s?result=error&error=%s&operation=mark" % (
                self._focus_url,
                quote_plus(exc.args[0]),
            )
            if action:
                url_failure = "%s&action=%s" % (url_failure, action)
            return HTTPSeeOther(url_failure)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_order:focus:retry", renderer=None)
    @view_config(route_name="admin:acme_order:focus:retry|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-order/{ID}/retry.json",
            "section": "acme-order",
            "about": """AcmeOrder focus: Retry""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/acme-order/1/retry.json",
            "example": "curl -X POST {ADMIN_PREFIX}/acme-order/1/retry.json",
            "form_fields": {
                "acme_order_retry_strategy": "What is the retry strategy?",
            },
            "valid_options": {
                "acme_order_retry_strategy": Form_AcmeOrder_retry.fields[
                    "acme_order_retry_strategy"
                ].list,
            },
        }
    )
    def retry_order(self):
        """
        Retry should create a new order
        """
        dbAcmeOrder = self._focus(eagerload_web=True)
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(self, "/acme-order/{ID}/retry.json")
            return HTTPSeeOther(
                "%s?result=error&operation=retry&message=HTTP+POST+required"
                % self._focus_url
            )
        try:
            (dbAcmeOrderNew, error) = submit__retry(
                self.request,
                dbAcmeOrder=dbAcmeOrder,
                acknowledge_transaction_commits=True,
            )
            if error:
                if self.request.wants_json:
                    rval: Dict[str, Any] = {
                        "result": "error",
                        "error": error,
                    }
                    if dbAcmeOrderNew:
                        rval["AcmeOrder"] = dbAcmeOrderNew.as_json
                    return rval
                return HTTPSeeOther(
                    "%s/acme-order/%s?result=error&error=%s&operation=retry"
                    % (
                        self.request.admin_url,
                        quote_plus(error),
                        dbAcmeOrderNew.id if dbAcmeOrderNew else dbAcmeOrder.id,
                    )
                )
            if TYPE_CHECKING:
                assert dbAcmeOrderNew
            if self.request.wants_json:
                return {
                    "result": "success",
                    "AcmeOrder": dbAcmeOrderNew.as_json,
                }
            return HTTPSeeOther(
                "%s/acme-order/%s?result=success&operation=retry"
                % (self.request.admin_url, dbAcmeOrderNew.id)
            )
        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {
                    "result": "error",
                    "form_errors": exc.formStash.errors,
                }
            return HTTPSeeOther(
                "%s?result=error&error=%s&operation=retry"
                % (
                    self._focus_url,
                    errors.formstash_to_querystring(exc.formStash),
                )
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# ------------------------------------------------------------------------------


class View_New(Handler):
    @view_config(route_name="admin:acme_order:new:freeform")
    @view_config(route_name="admin:acme_order:new:freeform|json", renderer="json")
    @docify(
        {
            "endpoint": "/acme-order/new/freeform.json",
            "section": "acme-order",
            "about": """AcmeOrder: New Freeform""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/acme-order/new/freeform.json",
            "form_fields": {
                # ALL certs
                "acme_challenge_duplicate_strategy": "How to handle duplicate challenges for a domain.",
                "domain_names_dns01": "required; a comma separated list of domain names to process",
                "domain_names_http01": "required; a comma separated list of domain names to process",
                "note": "A string to associate with the AcmeOrder.",
                "processing_strategy": "How should the order be processed?",
                # primary cert
                "account_key_existing__primary": "pem_md5 of any key. Must/Only submit if `account_key_option__primary==account_key_existing`",
                "account_key_global__primary": "pem_md5 of the Global Default account key. Must/Only submit if `account_key_option__primary==account_key_global__primary`; used to ensure the default did not change.",
                "account_key_option__primary": "How is the AcmeAccount specified?",
                "acme_account_id__primary": "local AcmeAccount id. Must/Only submit if `account_key_option__primary==acme_account_id`",
                "acme_account_url__primary": "AcmeAccount's URL. Must/Only submit if `account_key_option__primary==acme_account_url`",
                "acme_profile__primary": "The name of an ACME Profile on the ACME Server. Leave this blank for no profile. If you want to defer to the AcmeAccount, use the special name `@`.",
                "private_key_cycle__primary": "how should the PrivateKey be cycled on renewals?",
                "private_key_existing__primary": "pem_md5 of existing key",
                "private_key_option__primary": "How is the PrivateKey being specified?",
                "private_key_generate__primary": "What type of key should be used?",
                # backup cert
                "account_key_existing__backup": "pem_md5 of any key. Must/Only submit if `account_key_option__backup==account_key_existing__backup` [Backup Cert]",
                "account_key_global__backup": "pem_md5 of the Global Backup account key. Must/Only submit if `account_key_option__backup==account_key_global__backup` [Backup Cert]",
                "account_key_option__backup": "How is the AcmeAccount specified? [Backup Cert]",
                "acme_account_id__backup": "local id of AcmeAccount. Must/Only submit if `account_key_option__backup==acme_account_id` [Backup Cert]",
                "acme_account_url__backup": "AcmeAccount's URL. Must/Only submit if `account_key_option__backup==acme_account_url` [Backup Cert]",
                "acme_profile__backup": "The name of an ACME Profile on the ACME Server [Backup Cert]. Leave this blank for no profile. If you want to defer to the AcmeAccount, use the special name `@`.",
                "private_key_cycle__backup": "how should the PrivateKey be cycled on renewals?",
                "private_key_existing__backup": "pem_md5 of existing key",
                "private_key_option__backup": "How is the PrivateKey being specified?",
                "private_key_generate__backup": "What type of key should be used?",
            },
            "form_fields_related": [
                ["domain_names_http01", "domain_names_dns01"],
                ["private_key_option__primary", "private_key_existing__primary"],
                [
                    "account_key_existing__primary",
                    "account_key_global__primary",
                    "account_key_option__primary",
                    "acme_account_id__primary",
                    "acme_account_url__primary",
                    "acme_profile__primary",
                    "private_key_cycle__primary",
                    "private_key_existing__primary",
                    "private_key_option__primary",
                    "private_key_generate__primary",
                ],
                [
                    "account_key_existing__backup",
                    "account_key_global__backup",
                    "account_key_option__backup",
                    "acme_account_id__backup",
                    "acme_account_url__backup",
                    "acme_profile__backup",
                    "private_key_cycle__backup",
                    "private_key_existing__backup",
                    "private_key_option__backup",
                    "private_key_generate__backup",
                ],
            ],
            "valid_options": {
                "SystemConfigurations": "{RENDER_ON_REQUEST}",
                "account_key_option__backup": Form_AcmeOrder_new_freeform.fields[
                    "account_key_option__backup"
                ].list,
                "account_key_option__primary": Form_AcmeOrder_new_freeform.fields[
                    "account_key_option__primary"
                ].list,
                "acme_challenge_duplicate_strategy": Form_AcmeOrder_new_freeform.fields[
                    "acme_challenge_duplicate_strategy"
                ].list,
                "private_key_cycle__backup": Form_AcmeOrder_new_freeform.fields[
                    "private_key_cycle__backup"
                ].list,
                "private_key_cycle__primary": Form_AcmeOrder_new_freeform.fields[
                    "private_key_cycle__primary"
                ].list,
                "private_key_option__backup": Form_AcmeOrder_new_freeform.fields[
                    "private_key_option__backup"
                ].list,
                "private_key_option__primary": Form_AcmeOrder_new_freeform.fields[
                    "private_key_option__primary"
                ].list,
                "private_key_generate__backup": Form_AcmeOrder_new_freeform.fields[
                    "private_key_generate__backup"
                ].list,
                "private_key_generate__primary": Form_AcmeOrder_new_freeform.fields[
                    "private_key_generate__primary"
                ].list,
                "processing_strategy": Form_AcmeOrder_new_freeform.fields[
                    "processing_strategy"
                ].list,
            },
            "requirements": [
                "Submit corresponding field(s) to account_key_option, e.g. `account_key_existing` or `account_key_global__primary`.",
                "Submit at least one of `domain_names_http01` or `domain_names_dns01`",
            ],
            "examples": [
                """curl """
                """--form 'account_key_option=account_key_existing' """
                """--form 'account_key_existing=ff00ff00ff00ff00' """
                """--form 'private_key_option=private_key_existing' """
                """--form 'private_key_existing=ff00ff00ff00ff00' """
                """{ADMIN_PREFIX}/acme-order/new/freeform.json""",
            ],
        }
    )
    def new_freeform(self):
        if self.request.method == "POST":
            return self._new_freeform__submit()
        return self._new_freeform__print()

    def _new_freeform__print(self):
        if self.request.wants_json:
            return formatted_get_docs(self, "/acme-order/new/freeform.json")
        return render_to_response(
            "/admin/acme_order-new-freeform.mako",
            {
                "SystemConfiguration_global": self.request.api_context.dbSystemConfiguration_global,
                "AcmeDnsServer_GlobalDefault": self.request.api_context.dbAcmeDnsServer_GlobalDefault,
                "AcmeServers": self.request.api_context.dbAcmeServers,
                "domain_names_http01": self.request.params.get(
                    "domain_names_http01", ""
                ),
                "domain_names_dns01": self.request.params.get("domain_names_dns01", ""),
            },
            self.request,
        )

    def _new_freeform__submit(self):
        """
        Creates a RenewalConfiguration and then initiates an AcmeOrder
        """
        try:
            (dbAcmeOrder, is_duplicate_renewal_configuration) = submit__new_freeform(
                self.request,
                acknowledge_transaction_commits=True,
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "AcmeOrder": dbAcmeOrder.as_json,
                    "is_duplicate_renewal_configuration": is_duplicate_renewal_configuration,
                }
            return HTTPSeeOther(
                "%s/acme-order/%s%s"
                % (
                    self.request.api_context.application_settings["admin_prefix"],
                    dbAcmeOrder.id,
                    (
                        "?is_duplicate_renewal_configuration=true"
                        if is_duplicate_renewal_configuration
                        else ""
                    ),
                )
            )
        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                rval: Dict[str, Any] = {
                    "result": "error",
                    "form_errors": exc.formStash.errors,
                }
                #
                if "AcmeOrder" in exc.formStash.assets:
                    rval["AcmeOrder"] = exc.formStash.assets["AcmeOrder"].as_json
                if "is_duplicate_renewal_configuration" in exc.formStash.assets:
                    rval["is_duplicate_renewal_configuration"] = exc.formStash.assets[
                        "is_duplicate_renewal_configuration"
                    ]
                if "AcmeOrderCreatedError" in exc.formStash.assets:
                    # we don't want the prefix
                    rval["form_errors"]["Error_Main"] = exc.formStash.assets[
                        "AcmeOrderCreatedError"
                    ].args[0]
                return rval
            return formhandling.form_reprint(self.request, self._new_freeform__print)

        except Exception as exc:  # noqa: F841
            raise
            # note: allow this on testing
            # raise
            return HTTPSeeOther(
                "%s/acme-orders/all?result=error&operation=new-freeform"
                % self.request.api_context.application_settings["admin_prefix"]
            )
