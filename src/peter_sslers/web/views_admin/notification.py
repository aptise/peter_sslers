# stdlib
from typing import Optional

# from typing import Dict

# pypi
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.view import view_config

# local
from ..lib import formhandling
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.forms import Form_Notification_mark
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ...lib import db as lib_db
from ...lib import errors
from ...model.objects import Notification

# from ..lib.handler import json_pagination
# from ...lib import utils
# from ...model import utils as model_utils

# ==============================================================================


class View_List(Handler):

    @view_config(
        route_name="admin:notifications:all",
        renderer="/admin/notifications.mako",
    )
    @view_config(
        route_name="admin:notifications:all-paginated",
        renderer="/admin/notifications.mako",
    )
    @view_config(
        route_name="admin:notifications:all|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:notifications:all-paginated|json",
        renderer="json",
    )
    def list(self):
        url_template = "%s/notifications/{0}" % (
            self.request.api_context.application_settings["admin_prefix"],
        )
        items_count = lib_db.get.get__Notification__count(self.request.api_context)
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__Notification__paginated(
            self.request.api_context,
            limit=items_per_page,
            offset=offset,
        )
        if self.request.wants_json:
            return {
                "result": "success",
                "Notifications": [i.as_json for i in items_paged],
            }
        return {
            "project": "peter_sslers",
            "Notifications_count": items_count,
            "Notifications": items_paged,
            "pager": pager,
        }


class View_Focus(Handler):
    dbNotification: Optional[Notification] = None

    def _focus(self) -> Notification:
        if self.dbNotification is None:
            dbNotification = lib_db.get.get__Notification__by_id(
                self.request.api_context,
                self.request.matchdict["id"],
            )
            if not dbNotification:
                raise HTTPNotFound("the order was not found")
            self.dbNotification = dbNotification
            self._focus_url = "%s/notification/%s" % (
                self.request.admin_url,
                self.dbNotification.id,
            )
        return self.dbNotification


class View_Focus_Manipulate(View_Focus):

    @view_config(route_name="admin:notification:focus:mark", renderer=None)
    @view_config(route_name="admin:notification:focus:mark|json", renderer="json")
    @docify(
        {
            "endpoint": "/notification/{ID}/mark.json",
            "section": "notification",
            "about": """Notification: Focus. Mark""",
            "POST": True,
            "GET": None,
            "instructions": "curl --form 'action=active' {ADMIN_PREFIX}/notification/1/mark.json",
            "example": "curl "
            "--form 'action=active' "
            "{ADMIN_PREFIX}/notification/1/mark.json",
            "form_fields": {
                "action": "the intended action",
            },
            "valid_options": {
                "action": Form_Notification_mark.fields["action"].list,
            },
        }
    )
    def focus_mark(self):
        dbNotification = self._focus()  # noqa: F841
        if self.request.method == "POST":
            return self._focus_mark__submit()
        return self._focus_mark__print()

    def _focus_mark__print(self):
        dbNotification = self._focus()  # noqa: F841
        if self.request.wants_json:
            return formatted_get_docs(self, "/notification/{ID}/mark.json")
        url_post_required = "%s?result=error&error=post+required&operation=mark" % (
            self._focus_url
        )
        return HTTPSeeOther(url_post_required)

    def _focus_mark__submit(self):
        dbNotification = self._focus()  # noqa: F841
        action = self.request.params.get("action")
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_Notification_mark,
                validate_get=False,
                # validate_post=False
            )
            if not result:
                raise formhandling.FormInvalid(formStash)

            action = formStash.results["action"]
            try:
                if action == "dismiss":
                    result = lib_db.update.update_Notification__dismiss(
                        self.request.api_context, dbNotification
                    )

                else:
                    raise errors.InvalidTransition("Invalid option")

            except errors.InvalidTransition as exc:
                formStash.fatal_form(error_main=exc.args[0])

            self.request.api_context.dbSession.flush(objects=[dbNotification])

            if self.request.wants_json:
                return {
                    "result": "success",
                    "Notification": dbNotification.as_json,
                    "operation": "mark",
                    "action": action,
                }
            url_success = "%s/notifications?result=success&operation=mark&action=%s" % (
                self.request.admin_url,
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
