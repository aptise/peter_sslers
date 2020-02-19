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
from ..lib import text as lib_text
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...model import utils as model_utils
from ...model import objects as model_objects


# ==============================================================================


class ViewAdmin_List(Handler):

    @view_config(
        route_name="admin:certificate_requests",
        renderer="/admin/certificate_requests.mako",
    )
    @view_config(
        route_name="admin:certificate_requests_paginated",
        renderer="/admin/certificate_requests.mako",
    )
    @view_config(route_name="admin:certificate_requests|json", renderer="json")
    @view_config(
        route_name="admin:certificate_requests_paginated|json", renderer="json"
    )
    def list(self):
        items_count = lib_db.get.get__CertificateRequest__count(
            self.request.api_context
        )
        if self.request.wants_json:
            (pager, offset) = self._paginate(
                items_count,
                url_template="%s/certificate-requests/{0}.json"
                % self.request.registry.settings["admin_prefix"],
            )
        else:
            (pager, offset) = self._paginate(
                items_count,
                url_template="%s/certificate-requests/{0}"
                % self.request.registry.settings["admin_prefix"],
            )
        items_paged = lib_db.get.get__CertificateRequest__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        if self.request.wants_json:
            csrs = {csr.id: csr.as_json for csr in items_paged}
            return {
                "CertificateRequests": csrs,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "CertificateRequests_count": items_count,
            "CertificateRequests": items_paged,
            "pager": pager,
        }


class ViewAdmin_Focus(Handler):

    def _focus(self):
        dbCertificateRequest = lib_db.get.get__CertificateRequest__by_id(
            self.request.api_context, self.request.matchdict["id"]
        )
        if not dbCertificateRequest:
            raise HTTPNotFound("invalid CertificateRequest")
        self._focus_item = dbCertificateRequest
        self._focus_url = "%s/certificate-request/%s" % (
            self.request.registry.settings["admin_prefix"],
            dbCertificateRequest.id,
        )
        return dbCertificateRequest

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_request:focus",
        renderer="/admin/certificate_request-focus.mako",
    )
    @view_config(route_name="admin:certificate_request:focus|json", renderer="json")
    def focus(self):
        dbCertificateRequest = self._focus()
        if self.request.wants_json:
            return {"CertificateRequest": dbCertificateRequest.as_json_extended}
        return {
            "project": "peter_sslers",
            "CertificateRequest": dbCertificateRequest,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:certificate_request:focus:raw", renderer="string")
    def focus_raw(self):
        dbCertificateRequest = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbCertificateRequest.csr_pem
        if self.request.matchdict["format"] == "csr":
            self.request.response.content_type = "application/pkcs10"
            return dbCertificateRequest.csr_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbCertificateRequest.csr_pem
        return "cert.pem"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_request:focus:acme_orders",
        renderer="/admin/certificate_request-focus-acme_orders.mako",
    )
    @view_config(
        route_name="admin:certificate_request:focus:acme_orders_paginated",
        renderer="/admin/certificate_request-focus-acme_orders.mako",
    )
    def related__AcmeOrders(self):
        dbCertificateRequest = self._focus()
        items_count = lib_db.get.get__AcmeOrder__by_CertificateRequest__count(
            self.request.api_context, dbCertificateRequest.id
        )
        (pager, offset) = self._paginate(
            items_count,
            url_template="%s/certificate-request/{0}/acme-orders"
            % self.request.registry.settings["admin_prefix"],
        )
        items_paged = lib_db.get.get__AcmeOrder__by_CertificateRequest__paginated(
            self.request.api_context,
            dbCertificateRequest.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "CertificateRequest": dbCertificateRequest,
            "AcmeOrders_count": items_count,
            "AcmeOrders": items_paged,
            "pager": pager,
        }
