# stdlib
import logging
from typing import Dict
from typing import Optional
from typing import TYPE_CHECKING

# pypi
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.renderers import render_to_response
from pyramid.view import view_config

# local
from ..lib import form_utils as form_utils
from ..lib import formhandling
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.forms import Form_AcmeOrder_new_freeform
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...lib import errors
from ...model import utils as model_utils
from ...model.objects import AcmeOrder

log = logging.getLogger("peter_sslers.web")

# ==============================================================================


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
            if not dbAcmeOrder.is_can_acme_server_sync:
                raise errors.InvalidRequest(
                    "ACME Server Sync is not allowed for this AcmeOrder"
                )
            dbAcmeOrder = lib_db.actions_acme.do__AcmeV2_AcmeOrder__acme_server_sync(
                self.request.api_context,
                dbAcmeOrder=dbAcmeOrder,
                transaction_commit=True,
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "acme-server/sync",
                    "AcmeOrder": dbAcmeOrder.as_json,
                }
            return HTTPSeeOther(
                "%s?result=success&operation=acme+server+sync" % self._focus_url
            )
        except (
            errors.AcmeError,
            errors.InvalidRequest,
        ) as exc:
            if self.request.wants_json:
                return {
                    "result": "error",
                    "operation": "acme-server/sync",
                    "error": str(exc),
                }
            return HTTPSeeOther(
                "%s?result=error&error=%s&operation=acme+server+sync"
                % (self._focus_url, exc.as_querystring)
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
            if not dbAcmeOrder.is_can_acme_server_sync:
                raise errors.InvalidRequest(
                    "ACME Server Sync is not allowed for this AcmeOrder"
                )
            # sync the authz
            dbAcmeOrder = lib_db.actions_acme.do__AcmeV2_AcmeOrder__acme_server_sync_authorizations(
                self.request.api_context,
                dbAcmeOrder=dbAcmeOrder,
                transaction_commit=True,
            )
            # sync the AcmeOrder just to be safe
            dbAcmeOrder = lib_db.actions_acme.do__AcmeV2_AcmeOrder__acme_server_sync(
                self.request.api_context,
                dbAcmeOrder=dbAcmeOrder,
                transaction_commit=True,
            )
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
        except (
            errors.AcmeError,
            errors.InvalidRequest,
        ) as exc:
            if self.request.wants_json:
                return {
                    "result": "error",
                    "operation": "acme-server/sync-authorizations",
                    "error": str(exc),
                }
            return HTTPSeeOther(
                "%s?result=error&error=%s&operation=acme+server+sync+authorizations"
                % (self._focus_url, exc.as_querystring)
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
        deactivate any auths on the server.
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
            if not dbAcmeOrder.is_can_acme_server_deactivate_authorizations:
                raise errors.InvalidRequest(
                    "ACME Server Deactivate Authorizations is not allowed for this AcmeOrder"
                )
            # deactivate the authz
            result = lib_db.actions_acme.do__AcmeV2_AcmeOrder__acme_server_deactivate_authorizations(  # noqa: F841
                self.request.api_context,
                dbAcmeOrder=dbAcmeOrder,
                transaction_commit=True,
            )
            # then sync the authz
            dbAcmeOrder = lib_db.actions_acme.do__AcmeV2_AcmeOrder__acme_server_sync_authorizations(
                self.request.api_context,
                dbAcmeOrder=dbAcmeOrder,
                transaction_commit=True,
            )
            # then sync the AcmeOrder
            dbAcmeOrder = lib_db.actions_acme.do__AcmeV2_AcmeOrder__acme_server_sync(
                self.request.api_context,
                dbAcmeOrder=dbAcmeOrder,
                transaction_commit=True,
            )

            # deactivate any authz potentials
            lib_db.update.update_AcmeOrder_deactivate_AcmeAuthorizationPotentials(
                self.request.api_context,
                dbAcmeOrder=dbAcmeOrder,
            )

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
        except (
            errors.AcmeError,
            errors.InvalidRequest,
        ) as exc:
            if self.request.wants_json:
                return {
                    "result": "error",
                    "operation": "acme-server/deactivate-authorizations",
                    "error": str(exc),
                }
            return HTTPSeeOther(
                "%s?result=error&error=%s&operation=acme+server+deactivate+authorizations"
                % (self._focus_url, exc.as_querystring)
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
            dbAcmeOrder = (
                lib_db.actions_acme.do__AcmeV2_AcmeOrder__download_certificate(
                    self.request.api_context,
                    dbAcmeOrder=dbAcmeOrder,
                    transaction_commit=True,
                )
            )
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
        except (
            errors.AcmeError,
            errors.InvalidRequest,
        ) as exc:
            if self.request.wants_json:
                return {
                    "result": "error",
                    "operation": "acme-server/download-certificate",
                    "error": str(exc),
                }
            return HTTPSeeOther(
                "%s?result=error&error=%s&operation=acme+server+download+certificate"
                % (self._focus_url, exc.as_querystring)
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
            if not dbAcmeOrder.is_can_acme_process:
                raise errors.InvalidRequest(
                    "ACME Process is not allowed for this AcmeOrder"
                )
            dbAcmeOrder = lib_db.actions_acme.do__AcmeV2_AcmeOrder__process(
                self.request.api_context,
                dbAcmeOrder=dbAcmeOrder,
                transaction_commit=True,
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "acme-process",
                    "AcmeOrder": dbAcmeOrder.as_json,
                }
            return HTTPSeeOther(
                "%s?result=success&operation=acme+process" % self._focus_url
            )
        except (
            errors.AcmeError,
            errors.InvalidRequest,
        ) as exc:
            if self.request.wants_json:
                return {
                    "result": "error",
                    "operation": "acme-process",
                    "error": str(exc),
                }
            return HTTPSeeOther(
                "%s?result=error&error=%s&operation=process+order"
                % (self._focus_url, exc.as_querystring)
            )
        except Exception as exc:
            log.critical("Exception: %s", exc)
            if self.request.wants_json:
                return {
                    "result": "error",
                    "operation": "acme-process",
                    "error": str(exc),
                }
            return HTTPSeeOther(
                "%s?result=error&error=%s&operation=process+order"
                % (self._focus_url, str(exc))
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
            if not dbAcmeOrder.is_can_acme_finalize:
                raise errors.InvalidRequest(
                    "ACME Finalize is not allowed for this AcmeOrder"
                )
            dbAcmeOrder = lib_db.actions_acme.do__AcmeV2_AcmeOrder__finalize(
                self.request.api_context,
                dbAcmeOrder=dbAcmeOrder,
                transaction_commit=True,
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "operation": "finalize-order",
                    "AcmeOrder": dbAcmeOrder.as_json,
                }
            return HTTPSeeOther(
                "%s?result=success&operation=acme+finalize" % self._focus_url
            )
        except (
            errors.AcmeError,
            errors.InvalidRequest,
        ) as exc:
            if self.request.wants_json:
                return {
                    "result": "error",
                    "operation": "finalize-order",
                    "error": str(exc),
                }
            return HTTPSeeOther(
                "%s?result=error&error=%s&operation=acme+finalize"
                % (self._focus_url, exc.as_querystring)
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
                "action": [
                    "invalid",
                    "deactivate",
                ]
            },
        }
    )
    def mark_order(self):
        """
        Mark an order
        """
        dbAcmeOrder = self._focus(eagerload_web=True)
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(self, "/acme-order/{ID}/mark.json")
            return HTTPSeeOther(
                "%s?result=error&operation=mark&message=HTTP+POST+required"
                % self._focus_url
            )
        action = self.request.params.get("action", None)
        try:
            if action == "invalid":
                if not dbAcmeOrder.is_can_mark_invalid:
                    raise errors.InvalidRequest("Can not mark this order as 'invalid'.")
                lib_db.actions_acme.updated_AcmeOrder_status(
                    self.request.api_context,
                    dbAcmeOrder,
                    {
                        "status": "invalid",
                    },
                    transaction_commit=True,
                )

            elif action == "deactivate":
                lib_db.update.update_AcmeOrder_deactivate(
                    self.request.api_context,
                    dbAcmeOrder,
                    is_manual=True,
                )

            else:
                raise errors.InvalidRequest("invalid `action`")

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
                    "error": str(exc),
                }
            url_failure = "%s?result=error&error=%s&operation=mark" % (
                self._focus_url,
                exc.as_querystring,
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
        }
    )
    def retry_order(self):
        """
        Retry should create a new order
        """
        dbAcmeOrder = self._focus(eagerload_web=True)
        try:
            if self.request.method != "POST":
                if self.request.wants_json:
                    return formatted_get_docs(self, "/acme-order/{ID}/retry.json")
            if not dbAcmeOrder.is_can_acme_server_sync:
                raise errors.InvalidRequest(
                    "ACME Retry is not allowed for this AcmeOrder"
                )
            try:
                dbAcmeOrderNew = lib_db.actions_acme.do__AcmeV2_AcmeOrder__retry(
                    self.request.api_context,
                    dbAcmeOrder=dbAcmeOrder,
                    transaction_commit=True,
                )
            except errors.AcmeOrderCreatedError as exc:
                # unpack a `errors.AcmeOrderCreatedError` to local vars
                dbAcmeOrderNew = exc.acme_order
                exc = exc.original_exception
                if self.request.wants_json:
                    return {
                        "result": "error",
                        "error": exc.args[0],
                        "AcmeOrder": dbAcmeOrderNew.as_json,
                    }
                return HTTPSeeOther(
                    "%s/acme-order/%s?result=error&error=%s&opertion=retry+order"
                    % (
                        self.request.admin_url,
                        dbAcmeOrderNew.id,
                        exc.as_querystring,
                    )
                )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "AcmeOrder": dbAcmeOrderNew.as_json,
                }
            return HTTPSeeOther(
                "%s/acme-order/%s?result=success&operation=retry+order"
                % (self.request.admin_url, dbAcmeOrderNew.id)
            )
        except (
            errors.AcmeError,
            errors.InvalidRequest,
        ) as exc:
            if self.request.wants_json:
                return {
                    "result": "error",
                    "error": exc.args[0],
                }
            return HTTPSeeOther(
                "%s?result=error&error=%s&operation=retry+order"
                % (self._focus_url, exc.as_querystring)
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
                "domain_names_http01": "required; a comma separated list of domain names to process",
                "domain_names_dns01": "required; a comma separated list of domain names to process",
                "private_key_option": "How is the PrivateKey being specified?",
                "private_key_existing": "pem_md5 of existing key",
                "processing_strategy": "How should the order be processed?",
                "note": "A string to associate with the AcmeOrder.",
                # primary cert
                "account_key_option": "How is the AcmeAccount specified?",
                "account_key_global_default": "pem_md5 of the Global Default account key. Must/Only submit if `account_key_option==account_key_global_default`; used to ensure the default did not change.",
                "account_key_existing": "pem_md5 of any key. Must/Only submit if `account_key_option==account_key_existing`",
                "acme_account_id": "local AcmeAccount id. Must/Only submit if `account_key_option==acme_account_id`",
                "acme_account_url": "AcmeAccount's URL. Must/Only submit if `account_key_option==acme_account_url`",
                "private_key_cycle__primary": "how should the PrivateKey be cycled on renewals?",
                "acme_profile": """The name of an ACME Profile on the ACME Server.
Leave this blank for no profile.
If you want to defer to the AcmeAccount, use the special name `@`.""",
                # backup cert
                "account_key_option__backup": "How is the AcmeAccount specified? [Backup Cert]",
                "account_key_global__backup": "pem_md5 of the Global Backup account key. Must/Only submit if `account_key_option__backup==account_key_global__backup` [Backup Cert]",
                "account_key_existing__backup": "pem_md5 of any key. Must/Only submit if `account_key_option__backup==account_key_existing__backup` [Backup Cert]",
                "acme_account_id__backup": "local id of AcmeAccount. Must/Only submit if `account_key_option__backup==acme_account_id` [Backup Cert]",
                "acme_account_url__backup": "AcmeAccount's URL. Must/Only submit if `account_key_option__backup==acme_account_url` [Backup Cert]",
                "private_key_cycle__backup": "how should the PrivateKey be cycled on renewals?",
                "acme_profile__backup": """The name of an ACME Profile on the ACME Server [Backup Cert].
Leave this blank for no profile.
If you want to defer to the AcmeAccount, use the special name `@`.""",
            },
            "form_fields_related": [
                ["domain_names_http01", "domain_names_dns01"],
                ["private_key_option", "private_key_existing"],
                [
                    "account_key_option",
                    "account_key_global_default",
                    "account_key_existing",
                    "acme_profile__primary",
                    "acme_account_id",
                    "acme_account_url",
                ],
                [
                    "account_key_option__backup",
                    "account_key_global__backup",
                    "account_key_existing__backup",
                    "acme_profile__backup",
                    "acme_account_id__backup",
                    "acme_account_url",
                ],
            ],
            "valid_options": {
                "SystemConfigurations": "{RENDER_ON_REQUEST}",
                "account_key_option": Form_AcmeOrder_new_freeform.fields[
                    "account_key_option"
                ].list,
                "processing_strategy": Form_AcmeOrder_new_freeform.fields[
                    "processing_strategy"
                ].list,
                "private_key_option": Form_AcmeOrder_new_freeform.fields[
                    "private_key_option"
                ].list,
                "private_key_cycle__primary": Form_AcmeOrder_new_freeform.fields[
                    "private_key_cycle__primary"
                ].list,
                "private_key_cycle__backup": Form_AcmeOrder_new_freeform.fields[
                    "private_key_cycle__backup"
                ].list,
            },
            "requirements": [
                "Submit corresponding field(s) to account_key_option, e.g. `account_key_existing` or `account_key_global_default`.",
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
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_AcmeOrder_new_freeform,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid(formStash)

            domains_challenged = form_utils.form_domains_challenge_typed(
                self.request,
                formStash,
                dbAcmeDnsServer_GlobalDefault=self.request.api_context.dbAcmeDnsServer_GlobalDefault,
            )

            is_duplicate_renewal = None

            try:
                (acmeAccountSelection, privateKeySelection) = (
                    form_utils.form_key_selection(
                        self.request,
                        formStash,
                        require_contact=False,
                        support_upload_AcmeAccount=False,
                        support_upload_PrivateKey=False,
                    )
                )
                assert acmeAccountSelection.AcmeAccount is not None
                assert privateKeySelection.PrivateKey is not None

                acmeAccountSelection_backup = (
                    form_utils.parse_AcmeAccountSelection_backup(
                        self.request,
                        formStash,
                    )
                )

                # shared
                note = formStash.results["note"]
                processing_strategy = formStash.results["processing_strategy"]

                # PRIMARY cert
                acme_profile__primary = formStash.results["acme_profile__primary"]
                private_key_technology_id__primary = (
                    privateKeySelection.private_key_technology_id
                )
                private_key_cycle__primary = formStash.results[
                    "private_key_cycle__primary"
                ]
                private_key_cycle_id__primary = model_utils.PrivateKeyCycle.from_string(
                    private_key_cycle__primary
                )

                # BACKUP cert
                private_key_cycle_id__backup: Optional[int] = None
                private_key_technology_id__backup: Optional[int] = None
                acme_profile__backup: Optional[str] = None
                private_key_technology__backup = formStash.results[
                    "private_key_technology__backup"
                ]
                if private_key_technology__backup:
                    private_key_technology_id__backup = (
                        model_utils.KeyTechnology.from_string(
                            private_key_technology__backup
                        )
                    )
                private_key_cycle__backup = formStash.results[
                    "private_key_cycle__backup"
                ]
                if private_key_cycle__backup:
                    private_key_cycle_id__backup = (
                        model_utils.PrivateKeyCycle.from_string(
                            private_key_cycle__backup
                        )
                    )
                acme_profile__backup = formStash.results["acme_profile__backup"]

                if acmeAccountSelection_backup.AcmeAccount:
                    if not formStash.results["private_key_cycle__backup"]:
                        formStash.fatal_field(
                            field="private_key_cycle__backup",
                            error_field="Required for Backup Accounts",
                        )
                    if not formStash.results["private_key_technology__backup"]:
                        formStash.fatal_field(
                            field="private_key_technology__backup",
                            error_field="Required for Backup Accounts",
                        )
                else:
                    private_key_cycle_id__backup = None
                    private_key_technology_id__backup = None
                    acme_profile__backup = None

                #
                # validate the domains

                domains_all = []
                # check for blocklists here
                # this might be better in the AcmeOrder processor, but the orders are by UniqueFQDNSet
                # this may raise: [errors.AcmeDomainsBlocklisted, errors.AcmeDomainsInvalid]
                for challenge_, domains_ in domains_challenged.items():
                    if domains_:
                        lib_db.validate.validate_domain_names(
                            self.request.api_context, domains_
                        )
                        if challenge_ == "dns-01":
                            # check to ensure the domains are configured for dns-01
                            # this may raise errors.AcmeDomainsRequireConfigurationAcmeDNS
                            try:
                                lib_db.validate.ensure_domains_dns01(
                                    self.request.api_context, domains_
                                )
                            except errors.AcmeDomainsRequireConfigurationAcmeDNS as exc:
                                # in "experimental" mode, we may want to use specific
                                # acme-dns servers and not the global one
                                if (
                                    self.request.api_context.application_settings[
                                        "acme_dns_support"
                                    ]
                                    == "experimental"
                                ):
                                    raise
                                # in "basic" mode we can just associate these to the global option
                                if (
                                    not self.request.api_context.dbAcmeDnsServer_GlobalDefault
                                ):
                                    formStash.fatal_field(
                                        "domain_names_dns01",
                                        "No global acme-dns server configured.",
                                    )
                                assert (
                                    self.request.api_context.dbAcmeDnsServer_GlobalDefault
                                    is not None
                                )
                                # exc.args[0] will be the listing of domains
                                (domainObjects, adnsAccountObjects) = (
                                    lib_db.associate.ensure_domain_names_to_acmeDnsServer(
                                        self.request.api_context,
                                        exc.args[0],
                                        self.request.api_context.dbAcmeDnsServer_GlobalDefault,
                                        discovery_type="via renewal_configuration.new",
                                    )
                                )
                        domains_all.extend(domains_)

                # create the configuration
                # this will create:
                # * model_utils.RenewableConfig
                # * model_utils.UniquelyChallengedFQDNSet2Domain
                # * model_utils.UniqueFQDNSet
                try:
                    dbRenewalConfiguration = lib_db.create.create__RenewalConfiguration(
                        self.request.api_context,
                        domains_challenged=domains_challenged,
                        # PRIMARY cert
                        dbAcmeAccount__primary=acmeAccountSelection.AcmeAccount,
                        private_key_cycle_id__primary=private_key_cycle_id__primary,
                        private_key_technology_id__primary=private_key_technology_id__primary,
                        acme_profile__primary=acme_profile__primary,
                        # BACKUP cert
                        dbAcmeAccount__backup=acmeAccountSelection_backup.AcmeAccount,
                        private_key_cycle_id__backup=private_key_cycle_id__backup,
                        private_key_technology_id__backup=private_key_technology_id__backup,
                        acme_profile__backup=acme_profile__backup,
                        # misc
                        note=note,
                    )
                    is_duplicate_renewal = False
                except errors.DuplicateRenewalConfiguration as exc:
                    is_duplicate_renewal = True
                    # we could raise exc to abort, but this is likely preferred
                    dbRenewalConfiguration = exc.args[0]

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
                        #    self.request.api_context, domains_
                        # )
                        if challenge_ == "dns-01":
                            # check to ensure the domains are configured for dns-01
                            # this may raise errors.AcmeDomainsRequireConfigurationAcmeDNS
                            lib_db.validate.ensure_domains_dns01(
                                self.request.api_context, domains_
                            )
                try:
                    dbAcmeOrder = lib_db.actions_acme.do__AcmeV2_AcmeOrder__new(
                        self.request.api_context,
                        dbRenewalConfiguration=dbRenewalConfiguration,
                        processing_strategy=processing_strategy,
                        acme_order_type_id=model_utils.AcmeOrderType.ACME_ORDER_NEW_FREEFORM,
                        note=note,
                        dbPrivateKey=privateKeySelection.PrivateKey,
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
                        if isinstance(exc, errors.AcmeError):
                            if self.request.wants_json:
                                return {
                                    "result": "error",
                                    "error": str(exc),
                                    "AcmeOrder": dbAcmeOrder.as_json,
                                }
                            return HTTPSeeOther(
                                "%s/acme-order/%s?result=error&error=%s&operation=new+freeform"
                                % (
                                    self.request.registry.settings[
                                        "application_settings"
                                    ]["admin_prefix"],
                                    dbAcmeOrder.id,
                                    exc.as_querystring,
                                )
                            )

                    formStash.fatal_form(
                        error_main="%s" % exc,
                    )

                if self.request.wants_json:
                    return {
                        "result": "success",
                        "AcmeOrder": dbAcmeOrder.as_json,
                        "is_duplicate_renewal_configuration": is_duplicate_renewal,
                    }

                return HTTPSeeOther(
                    "%s/acme-order/%s%s"
                    % (
                        self.request.api_context.application_settings["admin_prefix"],
                        dbAcmeOrder.id,
                        "?is_duplicate_renewal=true" if is_duplicate_renewal else "",
                    )
                )
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
                formStash.fatal_form(
                    error_main="Error communicating with the acme-dns server."
                )

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

                if self.request.wants_json:
                    return {"result": "error", "error": str(exc)}

                return HTTPSeeOther(
                    "%s/acme-orders/all?result=error&error=%s&operation=new+freeform"
                    % (
                        self.request.api_context.application_settings["admin_prefix"],
                        exc.as_querystring,
                    )
                )
            except errors.UnknownAcmeProfile_Local as exc:  # noqa: F841
                # exc.args: var(matches field), submitted, allowed
                formStash.fatal_field(
                    field=exc.args[0],
                    error_field="Unknown acme_profile (%s); not one of: %s."
                    % (exc.args[2], exc.args[2]),
                )

            except formhandling.FormInvalid:
                raise

            except Exception as exc:  # noqa: F841
                return HTTPSeeOther(
                    "%s/acme-orders/all?result=error&operation=new-freeform"
                    % self.request.api_context.application_settings["admin_prefix"]
                )

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._new_freeform__print)
