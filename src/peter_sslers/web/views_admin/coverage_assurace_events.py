# stdlib
from typing import Optional

# pypi
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.view import view_config

# local
from ..lib import formhandling
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.forms import Form_CoverageAssuranceEvent_mark
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...lib import errors
from ...lib import utils
from ...model import utils as model_utils
from ...model.objects import CoverageAssuranceEvent

# ==============================================================================


class View_List(Handler):
    @view_config(
        route_name="admin:coverage_assurance_events",
    )
    def list_redirect(self):
        url_all = (
            "%s/coverage-assurance-events/all"
            % self.request.registry.settings["application_settings"]["admin_prefix"]
        )
        return HTTPSeeOther(url_all)

    @view_config(
        route_name="admin:coverage_assurance_events:all",
        renderer="/admin/coverage_assurance_events.mako",
    )
    @view_config(
        route_name="admin:coverage_assurance_events:all_paginated",
        renderer="/admin/coverage_assurance_events.mako",
    )
    @view_config(
        route_name="admin:coverage_assurance_events:unresolved",
        renderer="/admin/coverage_assurance_events.mako",
    )
    @view_config(
        route_name="admin:coverage_assurance_events:unresolved_paginated",
        renderer="/admin/coverage_assurance_events.mako",
    )
    @view_config(route_name="admin:coverage_assurance_events:all|json", renderer="json")
    @view_config(
        route_name="admin:coverage_assurance_events:all_paginated|json", renderer="json"
    )
    @view_config(
        route_name="admin:coverage_assurance_events:unresolved|json", renderer="json"
    )
    @view_config(
        route_name="admin:coverage_assurance_events:unresolved_paginated|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/coverage-assurance-events/all.json",
            "section": "coverage-assurance-event",
            "about": """list CoverageAssuranceEvent(s): All""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/coverage-assurance-events/all.json",
        }
    )
    @docify(
        {
            "endpoint": "/coverage-assurance-events/all/{PAGE}.json",
            "section": "coverage-assurance-event",
            "example": "curl {ADMIN_PREFIX}/coverage-assurance-events/all/1.json",
            "variant_of": "/coverage-assurance-events/all.json",
        }
    )
    @docify(
        {
            "endpoint": "/coverage-assurance-events/unresolved.json",
            "section": "coverage-assurance-event",
            "about": """list CoverageAssuranceEvent(s): Unresolved""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/coverage-assurance-events/unresolved.json",
        }
    )
    @docify(
        {
            "endpoint": "/coverage-assurance-events/unresolved/{PAGE}.json",
            "section": "coverage-assurance-event",
            "example": "curl {ADMIN_PREFIX}/coverage-assurance-events/unresolved/1.json",
            "variant_of": "/coverage-assurance-events/unresolved.json",
        }
    )
    def list(self):
        sidenav_option = None
        unresolved_only = None
        if self.request.matched_route.name in (
            "admin:coverage_assurance_events:all",
            "admin:coverage_assurance_events:all_paginated",
        ):
            sidenav_option = "all"
            unresolved_only = False
        elif self.request.matched_route.name in (
            "admin:coverage_assurance_events:unresolved",
            "admin:coverage_assurance_events:unresolved_paginated",
        ):
            sidenav_option = "unresolved"
            unresolved_only = True
        url_template = "%s/coverage-assurance-events/%s/{0}" % (
            self.request.registry.settings["application_settings"]["admin_prefix"],
            "unresolved" if unresolved_only else "all",
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        items_count = lib_db.get.get__CoverageAssuranceEvent__count(
            self.request.api_context, unresolved_only=unresolved_only
        )
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__CoverageAssuranceEvent__paginated(
            self.request.api_context,
            unresolved_only=unresolved_only,
            limit=items_per_page,
            offset=offset,
        )
        if self.request.wants_json:
            return {
                "CoverageAssuranceEvents": [i.as_json for i in items_paged],
                "CoverageAssuranceEvents_count": items_count,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "CoverageAssuranceEvents_count": items_count,
            "CoverageAssuranceEvents": items_paged,
            "sidenav_option": sidenav_option,
            "pager": pager,
        }


class View_Focus(Handler):
    dbCoverageAssuranceEvent: Optional[CoverageAssuranceEvent] = None

    def _focus(self) -> CoverageAssuranceEvent:
        if self.dbCoverageAssuranceEvent is None:
            dbCoverageAssuranceEvent = lib_db.get.get__CoverageAssuranceEvent__by_id(
                self.request.api_context,
                self.request.matchdict["id"],
            )
            if not dbCoverageAssuranceEvent:
                raise HTTPNotFound("the item was not found")
            self.dbCoverageAssuranceEvent = dbCoverageAssuranceEvent
            self._focus_item = dbCoverageAssuranceEvent
            self._focus_url = "%s/coverage-assurance-event/%s" % (
                self.request.registry.settings["application_settings"]["admin_prefix"],
                self.dbCoverageAssuranceEvent.id,
            )
        return self.dbCoverageAssuranceEvent

    @view_config(
        route_name="admin:coverage_assurance_event:focus",
        renderer="/admin/coverage_assurance_event-focus.mako",
    )
    @view_config(
        route_name="admin:coverage_assurance_event:focus|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/coverage-assurance-event/{ID}.json",
            "section": "coverage-assurance-event",
            "about": """CoverageAssuranceEvent focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/coverage-assurance-event/1.json",
        }
    )
    def focus(self):
        dbCoverageAssuranceEvent = self._focus()
        if self.request.wants_json:
            return {
                "CoverageAssuranceEvent": dbCoverageAssuranceEvent.as_json,
            }
        return {
            "project": "peter_sslers",
            "CoverageAssuranceEvent": dbCoverageAssuranceEvent,
        }

    @view_config(
        route_name="admin:coverage_assurance_event:focus:children",
        renderer="/admin/coverage_assurance_event-focus-children.mako",
    )
    @view_config(
        route_name="admin:coverage_assurance_event:focus:children|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/coverage-assurance-event/{ID}/children.json",
            "section": "coverage-assurance-event",
            "about": """CoverageAssuranceEvent focus: children""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/coverage-assurance-event/1/children.json",
        }
    )
    def children(self):
        dbCoverageAssuranceEvent = self._focus()
        items_count = lib_db.get.get__CoverageAssuranceEvent__by_parentId__count(
            self.request.api_context, dbCoverageAssuranceEvent.id
        )
        url_template = "%s/children/{0}" % self._focus_url
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__CoverageAssuranceEvent__by_parentId__paginated(
            self.request.api_context,
            dbCoverageAssuranceEvent.id,
            limit=items_per_page,
            offset=offset,
        )
        if self.request.wants_json:
            return {
                "CoverageAssuranceEvent": dbCoverageAssuranceEvent.as_json,
                "pagination": json_pagination(items_count, pager),
                "CoverageAssuranceEvents_Children_count": items_count,
                "CoverageAssuranceEvents_Children": items_paged,
            }
        return {
            "project": "peter_sslers",
            "CoverageAssuranceEvent": dbCoverageAssuranceEvent,
            "CoverageAssuranceEvents_Children_count": items_count,
            "CoverageAssuranceEvents_Children": items_paged,
            "pager": pager,
        }

    @view_config(route_name="admin:coverage_assurance_event:focus:mark", renderer=None)
    @view_config(
        route_name="admin:coverage_assurance_event:focus:mark|json", renderer="json"
    )
    @docify(
        {
            "endpoint": "/coverage-assurance-event/{ID}/mark.json",
            "section": "coverage-assurance-event",
            "about": """CoverageAssuranceEvent focus: mark""",
            "POST": True,
            "GET": None,
            "example": "curl {ADMIN_PREFIX}/coverage-assurance-event/1/mark.json",
            "instructions": [
                """curl --form 'action=active' {ADMIN_PREFIX}/coverage-assurance-event/1/mark.json""",
            ],
            "form_fields": {
                "action": "the action",
                "resolution": "the intended resolution",
            },
            "valid_options": {
                "resolution": Form_CoverageAssuranceEvent_mark.fields[
                    "resolution"
                ].list,
                "action": "resolved",
            },
        }
    )
    def mark(self):
        dbCoverageAssuranceEvent = self._focus()
        if self.request.method == "POST":
            return self._mark__submit(dbCoverageAssuranceEvent)
        return self._mark__print(dbCoverageAssuranceEvent)

    def _mark__print(self, dbCoverageAssuranceEvent):
        if self.request.wants_json:
            return formatted_get_docs(self, "/coverage-assurance-event/{ID}/mark.json")
        url_post_required = (
            "%s?result=error&error=post+required&operation=mark" % self._focus_url
        )
        return HTTPSeeOther(url_post_required)

    def _mark__submit(self, dbCoverageAssuranceEvent):
        action = self.request.params.get("action")
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_CoverageAssuranceEvent_mark,
                validate_get=False,
            )
            if not result:
                raise formhandling.FormInvalid()

            if action != "resolution":
                # formvalidation should ensure this already
                raise ValueError("`action` MUST be `resolution`")

            resolution = formStash.results["resolution"]
            event_type_id = model_utils.OperationsEventType.from_string(
                "CoverageAssuranceEvent__mark_resolution"
            )
            event_payload_dict = utils.new_event_payload_dict()
            event_payload_dict["coverage_assurance_event.id"] = (
                dbCoverageAssuranceEvent.id
            )
            event_payload_dict["action"] = action
            event_payload_dict["resolution"] = resolution

            try:
                _result = lib_db.update.update_CoverageAssuranceEvent__set_resolution(  # noqa: F841
                    self.request.api_context, dbCoverageAssuranceEvent, resolution
                )
            except errors.InvalidTransition as exc:
                # `formStash.fatal_form(` will raise a `FormInvalid()`
                formStash.fatal_form(message=exc.args[0])

            self.request.api_context.dbSession.flush(objects=[dbCoverageAssuranceEvent])

            # bookkeeping
            dbOperationsEvent = lib_db.logger.log__OperationsEvent(
                self.request.api_context, event_type_id, event_payload_dict
            )
            lib_db.logger._log_object_event(
                self.request.api_context,
                dbOperationsEvent=dbOperationsEvent,
                event_status_id=event_type_id,
                dbCoverageAssuranceEvent=dbCoverageAssuranceEvent,
            )

            if self.request.wants_json:
                return {
                    "result": "success",
                    "CoverageAssuranceEvent": dbCoverageAssuranceEvent.as_json,
                }
            url_success = "%s?result=success&operation=mark&action=%s" % (
                self._focus_url,
                action,
            )
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            url_failure = "%s?result=error&error=%s&operation=mark&action=%s" % (
                self._focus_url,
                errors.formstash_to_querystring(formStash),
                action,
            )
            raise HTTPSeeOther(url_failure)
