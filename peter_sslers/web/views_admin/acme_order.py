# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther

# stdlib
import json
import pdb

# pypi
import sqlalchemy

# localapp
from .. import lib
from ..lib import formhandling
from ..lib import form_utils as form_utils
from ..lib import text as lib_text
from ..lib.forms import Form_AcmeOrder_new_automated
from ..lib.forms import Form_AcmeOrder_renew_custom
from ..lib.forms import Form_AcmeOrder_renew_quick
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ...lib import acme_v2
from ...lib import cert_utils
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...model import utils as model_utils


# ==============================================================================


class ViewAdmin_List(Handler):
    @view_config(route_name="admin:acme_orders", renderer="/admin/acme_orders.mako")
    @view_config(route_name="admin:acme_orders|json", renderer="json")
    @view_config(
        route_name="admin:acme_orders_paginated", renderer="/admin/acme_orders.mako"
    )
    @view_config(route_name="admin:acme_orders_paginated|json", renderer="json")
    def list(self):
        wants_active = True if self.request.params.get("status") == "active" else False
        if wants_active:
            sidenav_option = "active"
            active_only = True
            if self.request.wants_json:
                url_template = (
                    "%s/acme-orders/{0}.json?status=active"
                    % self.request.registry.settings["admin_prefix"]
                )
            else:
                url_template = (
                    "%s/acme-orders/{0}?status=active"
                    % self.request.registry.settings["admin_prefix"]
                )
        else:
            sidenav_option = "all"
            active_only = False
            if self.request.wants_json:
                url_template = (
                    "%s/acme-orders/{0}.json"
                    % self.request.registry.settings["admin_prefix"]
                )
            else:
                url_template = (
                    "%s/acme-orders/{0}"
                    % self.request.registry.settings["admin_prefix"]
                )

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
            admin_url = self.request.admin_url
            return {
                "AcmeOrders": [i._as_json(admin_url=admin_url) for i in items_paged],
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "AcmeOrders_count": items_count,
            "AcmeOrders": items_paged,
            "pager": pager,
        }


# ------------------------------------------------------------------------------


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
    @view_config(route_name="admin:acme_order:focus|json", renderer="json")
    def focus(self):
        dbAcmeOrder = self._focus(eagerload_web=True)
        if self.request.wants_json:
            return {
                "AcmeOrder": dbAcmeOrder._as_json(admin_url=self.request.admin_url),
            }
        return {"project": "peter_sslers", "AcmeOrder": dbAcmeOrder}


class ViewAdmin_Focus_Manipulate(ViewAdmin_Focus):
    @view_config(
        route_name="admin:acme_order:focus:acme_event_logs",
        renderer="/admin/acme_order-focus-acme_event_logs.mako",
    )
    @view_config(
        route_name="admin:acme_order:focus:acme_event_logs_paginated",
        renderer="/admin/acme_order-focus-acme_event_logs.mako",
    )
    def acme_event_logs(self):
        dbAcmeOrder = self._focus(eagerload_web=True)

        items_count = lib_db.get.get__AcmeEventLogs__by_AcmeOrderId__count(
            self.request.api_context, dbAcmeOrder.id
        )
        (pager, offset) = self._paginate(
            items_count, url_template="%s/acme-event-logs/{0}" % self._focus_url,
        )
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
            result = lib_db.actions_acme.do__AcmeV2_AcmeOrder__acme_server_sync(
                self.request.api_context, dbAcmeOrder=dbAcmeOrder,
            )
            return HTTPSeeOther(
                "%s?result=success&operation=acme+server+sync" % self._focus_url
            )
        except (errors.AcmeError, errors.InvalidRequest,) as exc:
            return HTTPSeeOther(
                "%s?result=error&error=acme+server+sync&message=%s"
                % (self._focus_url, exc.to_querystring())
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_order:focus:acme_server_sync_authorizations",
        renderer=None,
    )
    def acme_server_sync_authorizations(self):
        """
        sync any auths on the server.
        """
        dbAcmeOrder = self._focus(eagerload_web=True)
        try:
            if not dbAcmeOrder.is_can_acme_server_sync:
                raise errors.InvalidRequest(
                    "ACME Server Sync is not allowed for this AcmeOrder"
                )
            result = lib_db.actions_acme.do__AcmeV2_AcmeOrder__acme_server_sync_authorizations(
                self.request.api_context, dbAcmeOrder=dbAcmeOrder,
            )
            return HTTPSeeOther(
                "%s?result=success&operation=acme+server+sync+authorizations"
                % self._focus_url
            )
        except (errors.AcmeError, errors.InvalidRequest,) as exc:
            return HTTPSeeOther(
                "%s?result=error&error=acme+server+sync+authorizations&message=%s"
                % (self._focus_url, exc.to_querystring())
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_order:focus:acme_server_deactivate_authorizations",
        renderer=None,
    )
    def acme_server_deactivate_authorizations(self):
        """
        deactivate any auths on the server.
        """
        dbAcmeOrder = self._focus(eagerload_web=True)
        try:
            if not dbAcmeOrder.is_can_acme_server_deactivate_authorizations:
                raise errors.InvalidRequest(
                    "ACME Server Deactivate Authorizations is not allowed for this AcmeOrder"
                )
            result = lib_db.actions_acme.do__AcmeV2_AcmeOrder__acme_server_deactivate_authorizations(
                self.request.api_context, dbAcmeOrder=dbAcmeOrder,
            )
            return HTTPSeeOther(
                "%s?result=success&operation=acme+server+deactivate+authorizations"
                % self._focus_url
            )
        except (errors.AcmeError, errors.InvalidRequest,) as exc:
            return HTTPSeeOther(
                "%s?result=error&error=acme+server+deactivate+authorizations&message=%s"
                % (self._focus_url, exc.to_querystring())
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_order:focus:process", renderer=None)
    @view_config(route_name="admin:acme_order:focus:process|json", renderer="json")
    def process_order(self):
        """
        only certain orders can be finalized
        """
        dbAcmeOrder = self._focus(eagerload_web=True)
        try:
            if not dbAcmeOrder.is_can_process_authorizations:
                raise errors.InvalidRequest(
                    "ACME Finalize is not allowed for this AcmeOrder"
                )
            (dbAcmeOrder, exc) = lib_db.actions_acme.do__AcmeV2_AcmeOrder__finalize(
                self.request.api_context, dbAcmeOrder=dbAcmeOrder,
            )
            if not exc:
                return HTTPSeeOther(
                    "%s?result=success&operation=finalize+order" % self._focus_url
                )
            raise exc
            # return HTTPSeeOther(
            #    "%s?result=error&error=could+not+finalize&operation=finalize+order" % self._focus_url
            # )
        except (errors.AcmeError, errors.InvalidRequest,) as exc:
            return HTTPSeeOther(
                "%s?result=error&error=finalize&message=%s"
                % (self._focus_url, exc.to_querystring())
            )


    @view_config(route_name="admin:acme_order:focus:finalize", renderer=None)
    @view_config(route_name="admin:acme_order:focus:finalize|json", renderer="json")
    def finalize_order(self):
        """
        only certain orders can be finalized
        """
        dbAcmeOrder = self._focus(eagerload_web=True)
        try:
            if not dbAcmeOrder.is_can_finalize:
                raise errors.InvalidRequest(
                    "ACME Finalize is not allowed for this AcmeOrder"
                )
            (dbAcmeOrder, exc) = lib_db.actions_acme.do__AcmeV2_AcmeOrder__finalize(
                self.request.api_context, dbAcmeOrder=dbAcmeOrder,
            )
            if not exc:
                return HTTPSeeOther(
                    "%s?result=success&operation=finalize+order" % self._focus_url
                )
            raise exc
            # return HTTPSeeOther(
            #    "%s?result=error&error=could+not+finalize&operation=finalize+order" % self._focus_url
            # )
        except (errors.AcmeError, errors.InvalidRequest,) as exc:
            return HTTPSeeOther(
                "%s?result=error&error=finalize&message=%s"
                % (self._focus_url, exc.to_querystring())
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_order:focus:mark", renderer=None)
    @view_config(route_name="admin:acme_order:focus:mark|json", renderer="json")
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
                lib_db.actions_acme.updated_AcmeOrder_status(
                    self.request.api_context,
                    dbAcmeOrder,
                    "invalid",
                    transaction_commit=True,
                )

            elif operation == "deactivate":
                """
                `deactivate` should mark the order as:
                    `is_active = False`
                """
                if dbAcmeOrder.is_active is not True:
                    raise errors.InvalidRequest("This order is not active.")

                # todo: use the api
                dbAcmeOrder.is_active = False
                dbAcmeOrder.timestamp_updated = self.request.api_context.timestamp
                self.request.api_context.dbSession.flush(objects=[dbAcmeOrder])

            elif operation == "renew.auto":
                if dbAcmeOrder.is_auto_renew:
                    raise errors.InvalidRequest("Can not mark this order for renewal.")

                # set the renewal
                dbAcmeOrder.is_auto_renew = True
                # cleanup options
                event_status = "AcmeOrder__mark__renew_auto"

            elif operation == "renew.manual":
                if not dbAcmeOrder.is_auto_renew:
                    raise errors.InvalidRequest(
                        "Can not unmark this order for renewal."
                    )

                # unset the renewal
                dbAcmeOrder.is_auto_renew = False
                # cleanup options
                event_status = "AcmeOrder__mark__renew_manual"

            else:
                raise errors.InvalidRequest("invalid `operation`")

            return HTTPSeeOther(
                "%s?result=success&operation=%s" % (self._focus_url, operation)
            )

        except (errors.InvalidRequest,) as exc:
            return HTTPSeeOther(
                "%s?result=error&error=invalid&message=%s"
                % (self._focus_url, exc.to_querystring())
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

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
            (dbAcmeOrderNew, exc) = lib_db.actions_acme.do__AcmeV2_AcmeOrder__retry(
                self.request.api_context, dbAcmeOrder=dbAcmeOrder,
            )
            retry_url = "%s/acme-order/%s" % (
                self.request.admin_url,
                dbAcmeOrderNew.id,
            )
            if not exc:
                return HTTPSeeOther(
                    "%s?result=success&operation=retry+order" % retry_url
                )
            if isinstance(exc, errors.AcmeError):
                return HTTPSeeOther(
                    "%s?operation=retry+order&error=retry&message=%s"
                    % (retry_url, exc.to_querystring())
                )
            raise exc
        except (errors.AcmeError, errors.InvalidRequest,) as exc:
            return HTTPSeeOther(
                "%s?result=error&error=retry&message=%s"
                % (self._focus_url, exc.to_querystring())
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_order:focus:renew:custom", renderer=None)
    @view_config(route_name="admin:acme_order:focus:renew:custom|json", renderer="json")
    def renew_custom(self):
        """
        This endpoint is for Immediately Renewing the AcmeOrder with overrides on the keys
        """
        self._load_AccountKeyDefault()
        self._load_AcmeAccountProviders()
        self._load_PrivateKeyDefault()
        if self.request.method == "POST":
            return self._renew_custom__submit()
        return self._renew_custom__print()

    def _renew_custom__print(self):
        dbAcmeOrder = self._focus()
        if not dbAcmeOrder.is_renewable_custom:
            raise errors.DisplayableError("This AcmeOrder can not use RenewCustom")
        return render_to_response(
            "/admin/acme_order-focus-renew-custom.mako",
            {
                "AcmeOrder": dbAcmeOrder,
                "AcmeAccountKey_Default": self.dbAcmeAccountKeyDefault,
                "AcmeAccountProviders": self.dbAcmeAccountProviders,
                "PrivateKey_Default": self.dbPrivateKeyDefault,
            },
            self.request,
        )

    def _renew_custom__submit(self):
        dbAcmeOrder = self._focus()
        try:
            if not dbAcmeOrder.is_renewable_custom:
                raise errors.DisplayableError("This AcmeOrder can not use RenewCustom")

            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_AcmeOrder_renew_custom, validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            (accountKeySelection, privateKeySelection) = form_utils.form_key_selection(
                self.request, formStash
            )
            processing_strategy = formStash.results["processing_strategy"]
            (
                dbAcmeOrderNew,
                exc,
            ) = lib_db.actions_acme.do__AcmeV2_AcmeOrder__renew_custom(
                self.request.api_context,
                processing_strategy=processing_strategy,
                dbAcmeOrder=dbAcmeOrder,
                dbAcmeAccountKey=accountKeySelection.AcmeAccountKey,
                dbPrivateKey=privateKeySelection.PrivateKey,
            )
            if exc:
                raise exc
            if self.request.wants_json:
                return {
                    "status": "success",
                    "acme_order": dbAcmeOrderNew.as_json,
                }
            renew_url = "%s/acme-order/%s" % (
                self.request.admin_url,
                dbAcmeOrderNew.id,
            )
            return HTTPSeeOther("%s?result=success&operation=renew+custom" % renew_url)
        except (errors.AcmeError, errors.InvalidRequest,) as exc:
            if self.request.wants_json:
                return {"status": "error", "error": str(exc)}
            url_failure = "%s?result=error&error=%s&operation=renew+custom" % (
                self._focus_url,
                exc.to_querystring(),
            )
            raise HTTPSeeOther(url_failure)
        except formhandling.FormInvalid as exc:
            return formhandling.form_reprint(self.request, self._renew_custom__print)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:acme_order:focus:renew:quick", renderer=None)
    @view_config(route_name="admin:acme_order:focus:renew:quick|json", renderer="json")
    def renew_quick(self):
        """
        This endpoint is for Immediately Renewing the AcmeOrder with this same Account .
        """
        if self.request.method == "POST":
            return self._renew_quick__submit()
        return self._renew_quick__print()

    def _renew_quick__print(self):
        dbAcmeOrder = self._focus()
        if not dbAcmeOrder.is_renewable_quick:
            raise errors.DisplayableError("This AcmeOrder can not use Quick Renew")
        return render_to_response(
            "/admin/acme_order-focus-renew-quick.mako",
            {"AcmeOrder": dbAcmeOrder,},
            self.request,
        )

    def _renew_quick__submit(self):
        dbAcmeOrder = self._focus()
        try:
            if not dbAcmeOrder.is_renewable_quick:
                raise errors.DisplayableError("This AcmeOrder can not use QuickRenew")

            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_AcmeOrder_renew_quick, validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()
            processing_strategy = formStash.results["processing_strategy"]
            (
                dbAcmeOrderNew,
                exc,
            ) = lib_db.actions_acme.do__AcmeV2_AcmeOrder__renew_quick(
                self.request.api_context, dbAcmeOrder=dbAcmeOrder,
                processing_strategy=processing_strategy,
            )
            if exc:
                raise exc
            if self.request.wants_json:
                return {
                    "status": "success",
                    "acme_order": dbAcmeOrderNew.as_json,
                }
            renew_url = "%s/acme-order/%s" % (
                self.request.admin_url,
                dbAcmeOrderNew.id,
            )
            return HTTPSeeOther("%s?result=success&operation=renew+quick" % renew_url)
        except (errors.AcmeError, errors.InvalidRequest,) as exc:
            if self.request.wants_json:
                return {"status": "error", "error": str(exc)}
            url_failure = "%s?result=error&error=%s&operation=renew+quick" % (
                self._focus_url,
                exc.to_querystring(),
            )
            raise HTTPSeeOther(url_failure)
        except formhandling.FormInvalid as exc:
            return formhandling.form_reprint(self.request, self._renew_quick__print)


# ------------------------------------------------------------------------------


class ViewAdmin_New(Handler):
    @view_config(route_name="admin:acme_order:new:automated")
    def new_automated(self):
        self._load_AccountKeyDefault()
        self._load_AcmeAccountProviders()
        self._load_PrivateKeyDefault()
        if self.request.method == "POST":
            return self._new_automated__submit()
        return self._new_automated__print()

    def _new_automated__print(self):
        return render_to_response(
            "/admin/acme_order-new-automated.mako",
            {
                "AcmeAccountKey_Default": self.dbAcmeAccountKeyDefault,
                "AcmeAccountProviders": self.dbAcmeAccountProviders,
                "PrivateKey_Default": self.dbPrivateKeyDefault,
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
                key_create_args["event_type"] = "AcmeAccountKey__insert"
                key_create_args[
                    "acme_account_key_source_id"
                ] = model_utils.AcmeAccountKeySource.from_string("imported")
                (
                    dbAcmeAccountKey,
                    _is_created,
                ) = lib_db.getcreate.getcreate__AcmeAccountKey(
                    self.request.api_context, **key_create_args
                )
                accountKeySelection.AcmeAccountKey = dbAcmeAccountKey

            privateKeySelection = form_utils.parse_PrivateKeySelection(
                self.request,
                formStash,
                seek_selected=formStash.results["private_key_option"],
            )

            if privateKeySelection.selection == "upload":
                key_create_args = privateKeySelection.upload_parsed.getcreate_args
                key_create_args["event_type"] = "PrivateKey__insert"
                key_create_args[
                    "private_key_source_id"
                ] = model_utils.PrivateKeySource.from_string("imported")
                (
                    dbPrivateKey,
                    _is_created,
                ) = lib_db.getcreate.getcreate__PrivateKey__by_pem_text(
                    self.request.api_context, **key_create_args
                )
                privateKeySelection.PrivateKey = dbPrivateKey

            elif privateKeySelection.selection == "generate":
                dbPrivateKey = lib_db.get.get__PrivateKey__by_id(
                    self.request.api_context, 0
                )
                if not dbPrivateKey:
                    formStash.fatal_field(
                        field="private_key_option",
                        message="Could not load the default private key",
                    )
                privateKeySelection.PrivateKey = dbPrivateKey

            processing_strategy = formStash.results["processing_strategy"]
            try:
                (
                    dbAcmeOrder,
                    exc,
                ) = lib_db.actions_acme.do__AcmeV2_AcmeOrder__automated(
                    self.request.api_context,
                    acme_order_type_id=model_utils.AcmeOrderType.ACME_AUTOMATED_NEW,
                    domain_names=domain_names,
                    processing_strategy=processing_strategy,
                    dbAcmeAccountKey=accountKeySelection.AcmeAccountKey,
                    dbPrivateKey=privateKeySelection.PrivateKey,
                )
                if exc:
                    if isinstance(exc, errors.AcmeError):
                        return HTTPSeeOther(
                            "%s/acme-order/%s?result=error&error=new-automated&message=%s"
                            % (
                                self.request.registry.settings["admin_prefix"],
                                dbAcmeOrder.id,
                                exc.to_querystring(),
                            )
                        )
                    raise exc
                return HTTPSeeOther(
                    "%s/acme-order/%s"
                    % (self.request.registry.settings["admin_prefix"], dbAcmeOrder.id,)
                )
            except errors.AcmeDuplicateChallenges as exc:
                formStash.fatal_field(
                    field="domain_names", message=exc.to_querystring()
                )

            except (errors.AcmeError, errors.InvalidRequest,) as exc:
                return HTTPSeeOther(
                    "%s/acme-orders?result=error&error=new-automated&message=%s"
                    % (
                        self.request.registry.settings["admin_prefix"],
                        exc.to_querystring(),
                    )
                )
            except Exception as exc:
                # note: allow this on testing
                # raise
                if self.request.registry.settings["exception_redirect"]:
                    return HTTPSeeOther(
                        "%s/acme-orders?result=error&error=new-automated"
                        % self.request.registry.settings["admin_prefix"]
                    )
                raise

        except formhandling.FormInvalid as exc:
            return formhandling.form_reprint(self.request, self._new_automated__print)
