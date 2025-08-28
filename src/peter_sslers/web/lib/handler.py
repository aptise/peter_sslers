# stdlib
from typing import Dict
from typing import Tuple
from typing import TYPE_CHECKING

# pypi
from pypages import Paginator
from pyramid.httpexceptions import HTTPFound

# localapp
from ...lib import db as lib_db
from ...model.objects import X509CertificateTrustPreferencePolicy

if TYPE_CHECKING:
    from pyramid.request import Request

# ==============================================================================

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


def load_X509CertificateTrustPreferencePolicy_global(
    request: "Request",
) -> "X509CertificateTrustPreferencePolicy":
    """
    loads `model.objects.X509CertificatePreferencePolicyItems` onto the request
    """
    dbX509CertificateTrustPreferencePolicy = (
        lib_db.get.get__X509CertificateTrustPreferencePolicy__by_name(
            request.api_context,
            "global",
            eagerload_preferences=True,
        )
    )
    assert dbX509CertificateTrustPreferencePolicy is not None
    return dbX509CertificateTrustPreferencePolicy


# ==============================================================================


class Handler(object):
    """core response class"""

    #: The active :class:`Pyramid.request.Request`
    request: "Request"

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
