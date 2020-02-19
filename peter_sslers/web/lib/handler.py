# pyramid
from pyramid.httpexceptions import HTTPFound

# pypi
import pypages

# localapp
from . import text
from ...lib import db


# ==============================================================================


# misc config options
items_per_page = 50


def json_pagination(items_count, pager):
    """
    return {"pagination": json_pagination(items_count, pager),}
    """
    return {
        "total_items": items_count,
        "page": pager.page_num,
        "page_next": pager.next if pager.has_next else None,
    }


# ==============================================================================


class Handler(object):
    """core response class
    """

    #: The active `:class:Pyramid.request.Request`
    request = None

    #: The default :class:`model.objects.AcmeAccountKey`
    dbAcmeAccountKeyDefault = None

    #: The default :class:`model.objects.PrivateKey`
    dbPrivateKeyDefault = None

    def __init__(self, request):
        """
        :param request: A `:class:Pyramid.request.Request` instance.
        """
        self.request = request
        self.request.text_library = text

    def _paginate(
        self, collection_count, items_per_page=items_per_page, url_template=None
    ):
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
        pager = pypages.Paginator(
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
        if not self.request.registry.settings["enable_nginx"]:
            raise HTTPFound(
                "%s?error=no+nginx" % self.request.registry.settings["admin_prefix"]
            )

    def _ensure_redis(self):
        """
        if redis is not enabled, raise a HTTPFound to the admin dashboard
        """
        if not self.request.registry.settings["enable_redis"]:
            raise HTTPFound(
                "%s?error=no+redis" % self.request.registry.settings["admin_prefix"]
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _load_AccountKeyDefault(self):
        """
        Loads the default :class:`model.objects.AcmeAccountKey` into the view's :attr:`.dbAcmeAccountKeyDefault`.
        """
        self.dbAcmeAccountKeyDefault = db.get.get__AcmeAccountKey__default(
            self.request.api_context, active_only=True
        )
        return self.dbAcmeAccountKeyDefault

    def _load_PrivateKeyDefault(self):
        """
        Loads the default :class:`model.objects.PrivateKey` into the view's :attr:`.dbPrivateKeyDefault`.
        """
        self.dbPrivateKeyDefault = db.get.get__PrivateKey__default(
            self.request.api_context, active_only=True
        )
        return self.dbPrivateKeyDefault
