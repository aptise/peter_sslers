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
from ..lib import form_utils as form_utils
from ..lib import text as lib_text
from ..lib.handler import Handler, items_per_page
from ..lib.forms import Form_AcmeOrder_new_automated
from ...lib import acme_v2
from ...lib import cert_utils
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...model import utils as model_utils


# ==============================================================================


class ViewAdmin_List(Handler):

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_orders", renderer="/admin/acme_orders.mako")
    @view_config(
        route_name="admin:acme_orders_paginated", renderer="/admin/acme_orders.mako"
    )
    def list(self):
        items_count = lib_db.get.get__AcmeOrder__count(self.request.api_context)
        (pager, offset) = self._paginate(
            items_count,
            url_template="%s/acme-orders/{0}"
            % self.request.registry.settings["admin_prefix"],
        )
        items_paged = lib_db.get.get__AcmeOrder__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        return {
            "project": "peter_sslers",
            "AcmeOrders_count": items_count,
            "AcmeOrders": items_paged,
            "pager": pager,
        }


class ViewAdmin_Focus(Handler):
    def _focus(self, eagerload_web=False):
        dbAcmeOrder = lib_db.get.get__AcmeOrder__by_id(
            self.request.api_context,
            self.request.matchdict["id"],
            eagerload_web=eagerload_web,
        )
        if not dbAcmeOrder:
            raise HTTPNotFound("the order was not found")
        self._focus_url = "%s/acme-order/%s" % (self.request.admin_url, dbAcmeOrder.id,)
        return dbAcmeOrder

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_order:focus", renderer="/admin/acme_order-focus.mako"
    )
    def focus(self):
        dbAcmeOrder = self._focus(eagerload_web=True)
        return {"project": "peter_sslers", "AcmeOrder": dbAcmeOrder}

    @view_config(
        route_name="admin:acme_order:focus:acme_authorizations",
        renderer="/admin/acme_order-focus-acme_authorizations.mako",
    )
    def acme_authorizations(self):
        dbAcmeOrder = self._focus(eagerload_web=True)
        return {"project": "peter_sslers", "AcmeOrder": dbAcmeOrder}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_order:focus:acme_server_sync", renderer=None)
    def acme_server_sync(self):
        """
        Acme Refresh should just update the record against the acme server.
        """
        dbAcmeOrder = self._focus(eagerload_web=True)
        try:
            if not dbAcmeOrder.is_can_acme_server_sync:
                raise errors.InvalidRequest(
                    "ACME Server Sync is not allowed for this AcmeOrder"
                )
            result = lib_db.actions.do__AcmeOrder_AcmeV2__acme_server_sync(
                self.request.api_context, dbAcmeOrder=dbAcmeOrder,
            )
            return HTTPSeeOther(
                "%s?result=success&operation=acme+server+sync+success" % self._focus_url
            )
        except (
            errors.AcmeCommunicationError,
            errors.DomainVerificationError,
            errors.InvalidRequest,
        ) as exc:
            return HTTPSeeOther(
                "%s?error=new-automated&message=%s"
                % (self._focus_url, str(exc).replace("\n", "+").replace(" ", "+"),)
            )

    @view_config(route_name="admin:acme_order:focus:retry", renderer=None)
    def retry_order(self):
        """
        Retry should create a new order
        """
        dbAcmeOrder = self._focus(eagerload_web=True)
        try:
            if not dbAcmeOrder.is_can_acme_server_sync:
                raise errors.InvalidRequest(
                    "ACME Retry is not allowed for this AcmeOrder"
                )
            result = lib_db.actions.do__AcmeOrder_AcmeV2__retry(
                self.request.api_context, dbAcmeOrder=dbAcmeOrder,
            )
            return HTTPSeeOther(
                "%s?result=success&operation=retry+success" % self._focus_url
            )
        except (
            errors.AcmeCommunicationError,
            errors.DomainVerificationError,
            errors.InvalidRequest,
        ) as exc:
            return HTTPSeeOther(
                "%s?error=new-automated&message=%s"
                % (self._focus_url, str(exc).replace("\n", "+").replace(" ", "+"),)
            )

    @view_config(route_name="admin:acme_order:focus:mark", renderer=None)
    def mark_order(self):
        """
        Mark an order
        """
        dbAcmeOrder = self._focus(eagerload_web=True)
        operation = self.request.params.get("operation")
        try:
            if operation == "invalid":
                if not dbAcmeOrder.is_can_mark_invalid:
                    raise errors.InvalidRequest("Can not mark this order as 'invalid'.")
                lib_db.actions.update_AcmeOrder_status(
                    self.request.api_context,
                    dbAcmeOrder,
                    "invalid",
                    transaction_commit=True,
                )
                return HTTPSeeOther(
                    "%s?result=success&operation=invalid" % self._focus_url
                )
            else:
                raise errors.InvalidRequest("invalid `operation`")
        except (errors.InvalidRequest,) as exc:
            return HTTPSeeOther(
                "%s?error=invalid&message=%s"
                % (self._focus_url, str(exc).replace("\n", "+").replace(" ", "+"),)
            )


class ViewAdmin_New(Handler):
    @view_config(route_name="admin:acme_order:new:automated")
    def new_automated(self):
        self._load_AccountKeyDefault()
        self._load_PrivateKeyDefault()
        if self.request.method == "POST":
            return self._new_automated__submit()
        return self._new_automated__print()

    def _new_automated__print(self):
        active_ca = acme_v2.CERTIFICATE_AUTHORITY
        providers = list(model_utils.AcmeAccountProvider.registry.values())
        return render_to_response(
            "/admin/acme_order-new-automated.mako",
            {
                "CERTIFICATE_AUTHORITY": active_ca,
                "AcmeAccountKey_Default": self.dbAcmeAccountKeyDefault,
                "PrivateKey_Default": self.dbPrivateKeyDefault,
                "AcmeAccountProviderOptions": providers,
            },
            self.request,
        )

    def _new_automated__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_AcmeOrder_new_automated, validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            try:
                domain_names = utils.domains_from_string(
                    formStash.results["domain_names"]
                )
            except ValueError as exc:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(
                    field="domain_names", message="invalid domain names detected"
                )

            if not domain_names:
                # `formStash.fatal_field()` will raise `FormFieldInvalid(FormInvalid)`
                formStash.fatal_field(
                    field="domain_names",
                    message="invalid or no valid domain names detected",
                )

            accountKeySelection = form_utils.parse_AccountKeySelection(
                self.request,
                formStash,
                seek_selected=formStash.results["account_key_option"],
            )
            if accountKeySelection.selection == "upload":
                key_create_args = accountKeySelection.upload_parsed.getcreate_args
                (
                    dbAcmeAccountKey,
                    _is_created,
                ) = lib_db.getcreate.getcreate__AcmeAccountKey(
                    self.request.api_context, **key_create_args
                )
                accountKeySelection.AcmeAccountKey = dbAcmeAccountKey

            private_key_pem = form_utils.parse_PrivateKeyPem(self.request, formStash)
            (
                dbPrivateKey,
                _is_created,
            ) = lib_db.getcreate.getcreate__PrivateKey__by_pem_text(
                self.request.api_context, private_key_pem
            )

            try:
                dbAcmeOrder = lib_db.actions.do__AcmeOrder__AcmeV2__automated(
                    self.request.api_context,
                    domain_names=domain_names,
                    dbAcmeAccountKey=accountKeySelection.AcmeAccountKey,
                    dbPrivateKey=dbPrivateKey,
                )
                return HTTPSeeOther(
                    "%s/acme-order/%s"
                    % (self.request.registry.settings["admin_prefix"], dbAcmeOrder.id,)
                )
            except (
                errors.AcmeCommunicationError,
                errors.DomainVerificationError,
                errors.InvalidRequest,
            ) as exc:
                return HTTPSeeOther(
                    "%s/acme-orders?error=new-automated&message=%s"
                    % (
                        self.request.registry.settings["admin_prefix"],
                        str(exc).replace("\n", "+").replace(" ", "+"),
                    )
                )
            except Exception as exc:
                raise
                if self.request.registry.settings["exception_redirect"]:
                    return HTTPSeeOther(
                        "%s/acme-orders?error=new-automated"
                        % self.request.registry.settings["admin_prefix"]
                    )
                raise

        except formhandling.FormInvalid as exc:
            return formhandling.form_reprint(self.request, self._new_automated__print)
