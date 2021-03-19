# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response
from pyramid.httpexceptions import HTTPFound

# stdlib
import datetime

# pypi
import pypages
import sqlalchemy

# localapp
from .. import lib
from ..lib.docs import docify

# from ..lib.docs import formatted_get_docs
from ..lib.handler import Handler, items_per_page
from ...lib import db as lib_db
from ...model import utils as model_utils


# ==============================================================================


class ViewAdminOperations(Handler):
    def _parse__event_type(self):
        event_type = self.request.params.get("event_type", None)
        event_type_id = None
        if event_type:
            try:
                event_type_id = model_utils.OperationsEventType.from_string(event_type)
            except AttributeError:
                event_type = None
        return (event_type, event_type_id)

    def _parse__event_type_ids(self):
        """turns the request's `event_type=operations__update_recents__global` into an id."""
        event_type_id = None
        event_type = self.request.params.get("event_type", None)
        if event_type:
            try:
                event_type_id = model_utils.OperationsEventType.from_string(event_type)
            except AttributeError:
                event_type = None
                event_type_id = None
        if event_type_id:
            return (event_type_id,)
        return None

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:operations", renderer=None)
    def operations(self):
        return HTTPFound(
            "%s/operations/log"
            % self.request.registry.settings["app_settings"]["admin_prefix"]
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:operations:log", renderer="/admin/operations-log.mako"
    )
    @view_config(
        route_name="admin:operations:log_paginated",
        renderer="/admin/operations-log.mako",
    )
    def operations_log(self):
        _items_per_page = 25

        (event_type, event_type_id) = self._parse__event_type()
        event_type_ids = (event_type_id,) if event_type_id else None

        items_count = lib_db.get.get__OperationsEvent__count(
            self.request.api_context, event_type_ids=event_type_ids
        )
        _url_template = (
            "%s/operations/log/{0}"
            % self.request.registry.settings["app_settings"]["admin_prefix"]
        )
        if event_type:
            _url_template = "%s/operations/log/{0}?event_type=%s" % (
                self.request.registry.settings["app_settings"]["admin_prefix"],
                event_type,
            )
        (pager, offset) = self._paginate(
            items_count, url_template=_url_template, items_per_page=_items_per_page
        )
        items_paged = lib_db.get.get__OperationsEvent__paginated(
            self.request.api_context,
            event_type_ids=event_type_ids,
            limit=_items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "OperationsEvent__count": items_count,
            "OperationsEvents": items_paged,
            "pager": pager,
            "enable_redis": self.request.registry.settings["app_settings"][
                "enable_redis"
            ],
            "enable_nginx": self.request.registry.settings["app_settings"][
                "enable_nginx"
            ],
            "event_type": event_type,
        }

    @view_config(
        route_name="admin:operations:log:focus",
        renderer="/admin/operations-log-focus.mako",
    )
    def operations_log_focus(self):
        item = lib_db.get.get__OperationsEvent__by_id(
            self.request.api_context, self.request.matchdict["id"], eagerload_log=True
        )
        if not item:
            raise ValueError("no item")
        return {
            "project": "peter_sslers",
            "OperationsEvent": item,
            "enable_redis": self.request.registry.settings["app_settings"][
                "enable_redis"
            ],
            "enable_nginx": self.request.registry.settings["app_settings"][
                "enable_nginx"
            ],
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:operations:redis", renderer="/admin/operations-redis.mako"
    )
    @view_config(
        route_name="admin:operations:redis_paginated",
        renderer="/admin/operations-redis.mako",
    )
    def admin_redis(self):
        self._ensure_redis()

        _items_per_page = 25
        items_count = lib_db.get.get__OperationsEvent__count(
            self.request.api_context,
            event_type_ids=(
                model_utils.OperationsEventType.from_string("operations__redis_prime"),
            ),
        )
        url_template = (
            "%s/operations/redis/log/{0}"
            % self.request.registry.settings["app_settings"]["admin_prefix"]
        )
        (pager, offset) = self._paginate(
            items_count,
            url_template=url_template,
            items_per_page=_items_per_page,
        )
        items_paged = lib_db.get.get__OperationsEvent__paginated(
            self.request.api_context,
            event_type_ids=(
                model_utils.OperationsEventType.from_string("operations__redis_prime"),
            ),
            limit=_items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "OperationsEvent__count": items_count,
            "OperationsEvents": items_paged,
            "pager": pager,
            "enable_redis": self.request.registry.settings["app_settings"][
                "enable_redis"
            ],
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:operations:nginx", renderer="/admin/operations-nginx.mako"
    )
    @view_config(
        route_name="admin:operations:nginx_paginated",
        renderer="/admin/operations-nginx.mako",
    )
    def admin_nginx(self):
        self._ensure_nginx()

        _items_per_page = 25
        _event_type_ids = (
            model_utils.OperationsEventType.from_string(
                "operations__nginx_cache_expire"
            ),
            model_utils.OperationsEventType.from_string(
                "operations__nginx_cache_flush"
            ),
        )
        items_count = lib_db.get.get__OperationsEvent__count(
            self.request.api_context, event_type_ids=_event_type_ids
        )
        url_template = (
            "%s/operations/nginx/log/{0}"
            % self.request.registry.settings["app_settings"]["admin_prefix"]
        )
        (pager, offset) = self._paginate(
            items_count,
            url_template=url_template,
            items_per_page=_items_per_page,
        )
        items_paged = lib_db.get.get__OperationsEvent__paginated(
            self.request.api_context,
            event_type_ids=_event_type_ids,
            limit=_items_per_page,
            offset=offset,
        )
        return {
            "project": "peter_sslers",
            "OperationsEvent__count": items_count,
            "OperationsEvents": items_paged,
            "pager": pager,
            "enable_nginx": self.request.registry.settings["app_settings"][
                "enable_nginx"
            ],
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:operations:object_log",
        renderer="/admin/operations-object_log.mako",
    )
    @view_config(
        route_name="admin:operations:object_log_paginated",
        renderer="/admin/operations-object_log.mako",
    )
    def object_log(self):
        _items_per_page = 25
        items_count = lib_db.get.get__OperationsObjectEvent__count(
            self.request.api_context
        )
        url_template = (
            "%s/operations/object-log/{0}"
            % self.request.registry.settings["app_settings"]["admin_prefix"]
        )
        (pager, offset) = self._paginate(
            items_count,
            url_template=url_template,
            items_per_page=_items_per_page,
        )
        items_paged = lib_db.get.get__OperationsObjectEvent__paginated(
            self.request.api_context, limit=_items_per_page, offset=offset
        )
        return {
            "project": "peter_sslers",
            "OperationsObjectEvent__count": items_count,
            "OperationsObjectEvents": items_paged,
            "pager": pager,
            "enable_redis": self.request.registry.settings["app_settings"][
                "enable_redis"
            ],
            "enable_nginx": self.request.registry.settings["app_settings"][
                "enable_nginx"
            ],
        }

    @view_config(
        route_name="admin:operations:object_log:focus",
        renderer="/admin/operations-object_log-focus.mako",
    )
    def operations_object_log_focus(self):
        item = lib_db.get.get__OperationsObjectEvent__by_id(
            self.request.api_context, self.request.matchdict["id"], eagerload_log=True
        )
        if not item:
            raise ValueError("no item")
        return {
            "project": "peter_sslers",
            "OperationsObjectEvent": item,
            "enable_redis": self.request.registry.settings["app_settings"][
                "enable_redis"
            ],
            "enable_nginx": self.request.registry.settings["app_settings"][
                "enable_nginx"
            ],
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
