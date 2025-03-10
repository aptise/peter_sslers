# stdlib
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING

# pypi
from pypages import Paginator
from pyramid.httpexceptions import HTTPFound

# localapp
from ...lib import db as lib_db
from ...lib.errors import InvalidRequest
from ...model.objects import CertificateCAPreference


# ==============================================================================

if TYPE_CHECKING:
    from pyramid.request import Request
    from ...model.objects import AcmeAccount


# misc config options
items_per_page = 50


def json_pagination(items_count: int, pager: Paginator) -> Dict:
    """
    return {"pagination": json_pagination(items_count, pager),}
    """
    return {
        "total_items": items_count,
        "page": pager.page_num,
        "page_next": pager.next if pager.has_next else None,
    }


# ==============================================================================


def api_host(request: "Request") -> str:
    """request method"""
    _api_host = request.api_context.application_settings.get("api_host")
    if _api_host:
        return _api_host
    _scheme = request.environ.get("scheme", "http")
    return "%s://%s" % (_scheme, request.environ["HTTP_HOST"])


def admin_url(request: "Request") -> str:
    """request method"""
    return request.api_host + request.api_context.application_settings["admin_prefix"]


def load_CertificateCAPreferences(
    request: "Request",
) -> List["CertificateCAPreference"]:
    """
    loads `model.objects.CertificateCAPreferences` onto the request
    """
    dbCertificateCAPreferences = lib_db.get.get__CertificateCAPreference__paginated(
        request.api_context
    )
    return dbCertificateCAPreferences


# ==============================================================================


class Handler(object):
    """core response class"""

    #: The active :class:`Pyramid.request.Request`
    request: "Request"

    #: The default :class:`model.objects.AcmeAccount`
    dbAcmeAccount_GlobalDefault: Optional["AcmeAccount"] = None
    dbAcmeAccount_GlobalBackup: Optional["AcmeAccount"] = None

    def __init__(self, request: "Request"):
        """
        :param request: A :class:`Pyramid.request.Request` instance.
        """
        self.request = request

    def _paginate(
        self,
        collection_count: int,
        items_per_page: int = items_per_page,
        url_template: str = "/%s",
    ) -> Tuple[Paginator, int]:
        """
        :param collection_count: the number of items in the collection
        :param items_per_page: the number of items per page
        :param url_template: the url of a template which pypages should render the paginator with
        """
        page_requested = (
            1
            if "page" not in self.request.matchdict
            else int(self.request.matchdict["page"])
        )
        pager = Paginator(
            collection_count,
            per_page=items_per_page,
            current=page_requested,
            start=None,
            range_num=10,
        )
        pager.template = url_template
        if page_requested == 0:
            raise HTTPFound(pager.template.format(1))
        if page_requested > pager.page_num:
            if pager.page_num > 0:
                raise HTTPFound(pager.template.format(pager.page_num))
        # return pager, offset
        return pager, ((page_requested - 1) * items_per_page)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _ensure_nginx(self):
        """
        if nginx is not enabled, raise a HTTPFound to the admin dashboard
        """
        if not self.request.api_context.application_settings["enable_nginx"]:
            raise InvalidRequest("nginx is not enabled")

    def _ensure_redis(self):
        """
        if redis is not enabled, raise a HTTPFound to the admin dashboard
        """
        if not self.request.api_context.application_settings["enable_redis"]:
            raise InvalidRequest("redis is not enabled")

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _load_AcmeAccount_GlobalDefault(self):
        """
        Loads the default :class:`model.objects.AcmeAccount` into the view's :attr:`.dbAcmeAccount_GlobalDefault`.
        """
        self.dbAcmeAccount_GlobalDefault = lib_db.get.get__AcmeAccount__GlobalDefault(
            self.request.api_context, active_only=True
        )
        return self.dbAcmeAccount_GlobalDefault

    def _load_AcmeAccount_GlobalBackup(self):
        """
        Loads the default :class:`model.objects.AcmeAccount` into the view's :attr:`.dbAcmeAccount_GlobalBackup`.
        """
        self.dbAcmeAccount_GlobalBackup = lib_db.get.get__AcmeAccount__GlobalBackup(
            self.request.api_context, active_only=True
        )
        return self.dbAcmeAccount_GlobalBackup

    def _load_AcmeDnsServer_GlobalDefault(self):
        """
        Loads the default :class:`model.objects.AcmeDnsServer` into the view's :attr:`.dbAcmeDnsServer_GlobalDefault`.
        """
        self.dbAcmeDnsServer_GlobalDefault = (
            lib_db.get.get__AcmeDnsServer__GlobalDefault(
                self.request.api_context,
            )
        )
        return self.dbAcmeDnsServer_GlobalDefault

    def _load_AcmeServers(self):
        """
        Loads the options for :class:`model.objects.AcmeServer` into the view's :attr:`.dbAcmeServers`.
        """
        self.dbAcmeServers = lib_db.get.get__AcmeServers__paginated(
            self.request.api_context, is_enabled=True
        )
        return self.dbAcmeServers
