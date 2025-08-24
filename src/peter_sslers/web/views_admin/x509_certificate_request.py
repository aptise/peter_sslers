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
from ...model.objects import X509CertificateRequest

# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:x509_certificate_requests",
        renderer="/admin/x509_certificate_requests.mako",
    )
    @view_config(
        route_name="admin:x509_certificate_requests-paginated",
        renderer="/admin/x509_certificate_requests.mako",
    )
    @view_config(route_name="admin:x509_certificate_requests|json", renderer="json")
    @view_config(
        route_name="admin:x509_certificate_requests-paginated|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/x509-certificate-requests.json",
            "section": "x509-certificate-request",
            "about": """list X509CertificateRequest(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate-requests.json",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificate-requests/{PAGE}.json",
            "section": "x509-certificate-request",
            "example": "curl {ADMIN_PREFIX}/x509-certificate-requests/1.json",
            "variant_of": "/x509-certificate-requests.json",
        }
    )
    def list(self):
        items_count = lib_db.get.get__X509CertificateRequest__count(
            self.request.api_context
        )
        url_template = (
            "%s/x509-certificate-requests/{0}"
            % self.request.api_context.application_settings["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__X509CertificateRequest__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        if self.request.wants_json:
            csrs = {csr.id: csr.as_json for csr in items_paged}
            return {
                "X509CertificateRequests": csrs,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "X509CertificateRequests_count": items_count,
            "X509CertificateRequests": items_paged,
            "pager": pager,
        }


class View_Focus(Handler):
    dbX509CertificateRequest: Optional[X509CertificateRequest] = None

    def _focus(self) -> X509CertificateRequest:
        if self.dbX509CertificateRequest is None:
            dbX509CertificateRequest = lib_db.get.get__X509CertificateRequest__by_id(
                self.request.api_context, self.request.matchdict["id"]
            )
            if not dbX509CertificateRequest:
                raise HTTPNotFound("invalid X509CertificateRequest")
            self.dbX509CertificateRequest = dbX509CertificateRequest
            self._focus_item = dbX509CertificateRequest
            self._focus_url = "%s/x509-certificate-request/%s" % (
                self.request.api_context.application_settings["admin_prefix"],
                self.dbX509CertificateRequest.id,
            )
        return self.dbX509CertificateRequest

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:x509_certificate_request:focus",
        renderer="/admin/x509_certificate_request-focus.mako",
    )
    @view_config(
        route_name="admin:x509_certificate_request:focus|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/x509-certificate-request/{ID}.json",
            "section": "x509-certificate-request",
            "about": """X509CertificateRequest focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate-request/1.json",
        }
    )
    def focus(self):
        dbX509CertificateRequest = self._focus()
        if self.request.wants_json:
            return {"X509CertificateRequest": dbX509CertificateRequest.as_json_extended}
        return {
            "project": "peter_sslers",
            "X509CertificateRequest": dbX509CertificateRequest,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:x509_certificate_request:focus:raw", renderer="string"
    )
    @docify(
        {
            "endpoint": "/x509-certificate-request/{ID}/csr.pem",
            "section": "x509-certificate-request",
            "about": """X509CertificateRequest focus. as PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate-request/1/csr.pem",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificate-request/{ID}/csr.pem.txt",
            "section": "x509-certificate-request",
            "about": """X509CertificateRequest focus. as PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate-request/1/csr..txt",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificate-request/{ID}/csr.csr",
            "section": "x509-certificate-request",
            "about": """X509CertificateRequest focus. as PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate-request/1/csr.csr",
        }
    )
    def focus_raw(self):
        """
        for extensions, see `cert_utils.EXTENSION_TO_MIME`
        """
        dbX509CertificateRequest = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbX509CertificateRequest.csr_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbX509CertificateRequest.csr_pem
        elif self.request.matchdict["format"] == "csr":
            self.request.response.content_type = "application/pkcs10"
            return dbX509CertificateRequest.csr_pem
        return "cert.pem"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:x509_certificate_request:focus:acme_orders",
        renderer="/admin/x509_certificate_request-focus-acme_orders.mako",
    )
    @view_config(
        route_name="admin:x509_certificate_request:focus:acme_orders-paginated",
        renderer="/admin/x509_certificate_request-focus-acme_orders.mako",
    )
    def related__AcmeOrders(self):
        dbX509CertificateRequest = self._focus()
        items_count = lib_db.get.get__AcmeOrder__by_X509CertificateRequest__count(
            self.request.api_context, dbX509CertificateRequest.id
        )
        url_template = (
            "%s/x509-certificate-request/{0}/acme-orders"
            % self.request.api_context.application_settings["admin_prefix"]
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__AcmeOrder__by_X509CertificateRequest__paginated(
            self.request.api_context,
            dbX509CertificateRequest.id,
            limit=items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "X509CertificateRequest": dbX509CertificateRequest,
            "AcmeOrders_count": items_count,
            "AcmeOrders": items_paged,
            "pager": pager,
        }
