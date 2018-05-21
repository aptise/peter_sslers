# pyramid
from pyramid.httpexceptions import HTTPFound

# pypi
import pyramid_formencode_classic as formhandling
import pypages

# localapp
from . import text
from . import db


# ==============================================================================


# misc config options
items_per_page = 50


# ==============================================================================


class Handler(object):
    """core response class
    """
    request = None

    def __init__(self, request):
        self.request = request
        self.request.formhandling = formhandling
        self.request.text_library = text

    def _paginate(self, collection_count, items_per_page=items_per_page, url_template=None):
        page_requested = 1 if 'page' not in self.request.matchdict else int(self.request.matchdict['page'])
        pager = pypages.Paginator(collection_count,
                                  per_page=items_per_page,
                                  current=page_requested,
                                  start=None,
                                  range_num=10
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
        if not self.request.registry.settings['enable_nginx']:
            raise HTTPFound('%s?error=no_nginx' % self.request.registry.settings['admin_prefix'])

    def _ensure_redis(self):
        if not self.request.registry.settings['enable_redis']:
            raise HTTPFound('%s?error=no_redis' % self.request.registry.settings['admin_prefix'])

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _load_AccountKeyDefault(self):
        self.dbAccountKeyDefault = db.get.get__SslAcmeAccountKey__default(self.request.api_context, active_only=True)
        return self.dbAccountKeyDefault

    def _load_PrivateKeyDefault(self):
        self.dbPrivateKeyDefault = db.get.get__SslPrivateKey__default(self.request.api_context, active_only=True)
        return self.dbPrivateKeyDefault
