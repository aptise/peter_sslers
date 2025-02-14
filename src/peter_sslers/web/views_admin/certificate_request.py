# stdlib
from typing import Optional

# pypi
from pyramid.httpexceptions import HTTPNotFound
from pyramid.view import view_config

# local
from ..lib.docs import docify
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...model.objects import CertificateRequest

# ==============================================================================


class View_List(Handler):
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
    @docify(
        {
            "endpoint": "/certificate-requests.json",
            "section": "certificate-request",
            "about": """list CertificateRequest(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-requests.json",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-requests/{PAGE}.json",
            "section": "certificate-request",
            "example": "curl {ADMIN_PREFIX}/certificate-requests/1.json",
            "variant_of": "/certificate-requests.json",
        }
    )
    def list(self):
        items_count = lib_db.get.get__CertificateRequest__count(
            self.request.api_context
        )
        url_template = (
            "%s/certificate-requests/{0}"
            % self.request.registry.settings["application_settings"]["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        (pager, offset) = self._paginate(items_count, url_template=url_template)
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


class View_Focus(Handler):
    dbCertificateRequest: Optional[CertificateRequest] = None

    def _focus(self) -> CertificateRequest:
        if self.dbCertificateRequest is None:
            dbCertificateRequest = lib_db.get.get__CertificateRequest__by_id(
                self.request.api_context, self.request.matchdict["id"]
            )
            if not dbCertificateRequest:
                raise HTTPNotFound("invalid CertificateRequest")
            self.dbCertificateRequest = dbCertificateRequest
            self._focus_item = dbCertificateRequest
            self._focus_url = "%s/certificate-request/%s" % (
                self.request.registry.settings["application_settings"]["admin_prefix"],
                self.dbCertificateRequest.id,
            )
        return self.dbCertificateRequest

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:certificate_request:focus",
        renderer="/admin/certificate_request-focus.mako",
    )
    @view_config(route_name="admin:certificate_request:focus|json", renderer="json")
    @docify(
        {
            "endpoint": "/certificate-request/{ID}.json",
            "section": "certificate-request",
            "about": """CertificateRequest focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-request/1.json",
        }
    )
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
    @docify(
        {
            "endpoint": "/certificate-request/{ID}/csr.pem",
            "section": "certificate-request",
            "about": """CertificateRequest focus. as PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-request/1/csr.pem",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-request/{ID}/csr.pem.txt",
            "section": "certificate-request",
            "about": """CertificateRequest focus. as PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-request/1/csr..txt",
        }
    )
    @docify(
        {
            "endpoint": "/certificate-request/{ID}/csr.csr",
            "section": "certificate-request",
            "about": """CertificateRequest focus. as PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/certificate-request/1/csr.csr",
        }
    )
    def focus_raw(self):
        """
        for extensions, see `cert_utils.EXTENSION_TO_MIME`
        """
        dbCertificateRequest = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbCertificateRequest.csr_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbCertificateRequest.csr_pem
        elif self.request.matchdict["format"] == "csr":
            self.request.response.content_type = "application/pkcs10"
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
        url_template = (
            "%s/certificate-request/{0}/acme-orders"
            % self.request.registry.settings["application_settings"]["admin_prefix"]
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template)
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
