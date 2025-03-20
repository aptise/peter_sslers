# stdlib

# pypi
from pyramid.view import view_config

# local
from ..lib.docs import docify
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db

# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:routine_executions", renderer="/admin/routine_executions.mako"
    )
    @view_config(
        route_name="admin:routine_executions-paginated",
        renderer="/admin/routine_executions.mako",
    )
    @view_config(route_name="admin:routine_executions|json", renderer="json")
    @view_config(route_name="admin:routine_executions-paginated|json", renderer="json")
    @docify(
        {
            "endpoint": "/routine-executions.json",
            "section": "routine-executions",
            "about": """list routine_executions(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/routine-executions.json",
        }
    )
    @docify(
        {
            "endpoint": "/routine-executions/{PAGE}.json",
            "section": "routine-executions",
            "example": "curl {ADMIN_PREFIX}/routine-executions/1.json",
            "variant_of": "/routine-executions.json",
        }
    )
    def list(self):
        items_count = lib_db.get.get__RoutineExecution__count(self.request.api_context)
        url_template = (
            "%s/routine-executions/{0}"
            % self.request.api_context.application_settings["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__RoutineExecution__paginated(
            self.request.api_context,
            limit=items_per_page,
            offset=offset,
        )
        if self.request.wants_json:
            _sets = {s.id: s.as_json for s in items_paged}
            return {
                "RoutineExecutions": _sets,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "RoutineExecutions_count": items_count,
            "RoutineExecutions": items_paged,
            "pager": pager,
        }
