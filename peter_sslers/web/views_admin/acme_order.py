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
from ..lib import text as lib_text
from ..lib.handler import Handler, items_per_page
from ...lib import cert_utils
from ...lib import db as lib_db
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
        items_count = lib_db.get.get__SslAcmeOrder__count(self.request.api_context)
        (pager, offset) = self._paginate(
            items_count,
            url_template="%s/acme-orders/{0}"
            % self.request.registry.settings["admin_prefix"],
        )
        items_paged = lib_db.get.get__SslAcmeOrder__paginated(
            self.request.api_context, limit=items_per_page, offset=offset
        )
        return {
            "project": "peter_sslers",
            "SslAcmeOrders_count": items_count,
            "SslAcmeOrders": items_paged,
            "pager": pager,
        }


class ViewAdmin_Focus(Handler):
    def _focus(self, eagerload_web=False):
        dbAcmeOrder = lib_db.get.get__SslAcmeOrder__by_id(
            self.request.api_context,
            self.request.matchdict["id"],
            eagerload_web=eagerload_web,
        )
        if not dbAcmeOrder:
            raise HTTPNotFound("the order was not found")
        self._focus_url = "%s/account-order/%s" % (
            self.request.admin_url,
            dbAcmeOrder.id,
        )
        return dbAcmeOrder

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:acme_order:focus", renderer="/admin/acme_order-focus.mako"
    )
    def focus(self):
        dbAcmeOrder = self._focus(eagerload_web=True)
        return {"project": "peter_sslers", "SslAcmeOrder": dbAcmeOrder}
