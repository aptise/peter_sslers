# stdlib
import tempfile
import time
from typing import Dict
from typing import List
from typing import Literal
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING
from typing import Union
import zipfile

# pypi
import cert_utils
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.renderers import render_to_response
from pyramid.response import Response
from pyramid.view import view_config

# local
from ..lib import formhandling
from ..lib.docs import docify
from ..lib.docs import formatted_get_docs
from ..lib.forms import Form_Certificate_Upload__file
from ..lib.forms import Form_X509Certificate_mark
from ..lib.forms import Form_X509Certificate_search
from ..lib.handler import Handler
from ..lib.handler import items_per_page
from ..lib.handler import json_pagination
from ...lib import db as lib_db
from ...lib import errors
from ...lib import events
from ...lib import utils
from ...lib import utils_nginx
from ...model import utils as model_utils
from ...model.objects import X509Certificate

if TYPE_CHECKING:
    from pyramid.request import Request


# ==============================================================================


def archive_zipfile(
    dbX509Certificate: X509Certificate,
    x509_certificate_trust_chain_id: Optional[int] = None,
) -> tempfile.SpooledTemporaryFile:
    if x509_certificate_trust_chain_id is None:
        x509_certificate_trust_chain_id = (
            dbX509Certificate.x509_certificate_trust_chain_id__preferred
        )

    now = time.localtime(time.time())[:6]
    tmpfile = tempfile.SpooledTemporaryFile()
    with zipfile.ZipFile(tmpfile, "w") as archive:
        # `cert1.pem`
        info = zipfile.ZipInfo("cert%s.pem" % dbX509Certificate.id)
        info.date_time = now
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, dbX509Certificate.cert_pem)

        # `chain1.pem`
        info = zipfile.ZipInfo("chain%s.pem" % dbX509Certificate.id)
        info.date_time = now
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(
            info,
            dbX509Certificate.valid_cert_chain_pem(
                x509_certificate_trust_chain_id=x509_certificate_trust_chain_id
            ),
        )
        # `fullchain1.pem`
        info = zipfile.ZipInfo("fullchain%s.pem" % dbX509Certificate.id)
        info.date_time = now
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(
            info,
            dbX509Certificate.valid_cert_fullchain_pem(
                x509_certificate_trust_chain_id=x509_certificate_trust_chain_id
            ),
        )
        # `privkey1.pem`
        info = zipfile.ZipInfo("privkey%s.pem" % dbX509Certificate.id)
        info.date_time = now
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, dbX509Certificate.private_key.key_pem)
    tmpfile.seek(0)
    return tmpfile


def submit__mark(
    request: "Request",
    dbX509Certificate: "X509Certificate",
    acknowledge_transaction_commits: Optional[Literal[True]] = None,
) -> Tuple["X509Certificate", str]:
    if not acknowledge_transaction_commits:
        raise errors.AcknowledgeTransactionCommitRequired()

    (result, formStash) = formhandling.form_validate(
        request,
        schema=Form_X509Certificate_mark,
        validate_get=False,
        # validate_post=False
    )
    if not result:
        raise formhandling.FormInvalid(formStash)

    action = formStash.results["action"]
    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict["x509_certificate.id"] = dbX509Certificate.id
    event_payload_dict["action"] = action

    event_type = "X509Certificate__mark"

    update_recents = False
    unactivated = False
    activated = False
    event_status: Optional[str] = None

    try:

        if action == "active":
            event_status = lib_db.update.update_X509Certificate__set_active(
                request.api_context, dbX509Certificate
            )
            update_recents = True
            activated = True

        elif action == "inactive":
            event_status = lib_db.update.update_X509Certificate__unset_active(
                request.api_context, dbX509Certificate
            )
            update_recents = True
            unactivated = True

        elif action == "revoked":
            event_status = lib_db.update.update_X509Certificate__set_revoked(
                request.api_context, dbX509Certificate
            )
            update_recents = True
            unactivated = True
            event_type = "X509Certificate__revoke"

        # elif action == "renew_manual":
        #    event_status = lib_db.update.update_X509Certificate__set_renew_manual(
        #        request.api_context, dbX509Certificate
        #    )

        # elif action == "renew_auto":
        #    event_status = lib_db.update.update_X509Certificate__set_renew_auto(
        #        request.api_context, dbX509Certificate
        #    )

        elif action == "unrevoke":
            raise errors.InvalidTransition("Invalid option: `unrevoke`")
            """
            event_status = lib_db.update.update_X509Certificate__unset_revoked(
                request.api_context, dbX509Certificate
            )
            update_recents = True
            activated = None
            """

        else:
            raise errors.InvalidTransition("Invalid option")

    except errors.InvalidTransition as exc:
        formStash.fatal_form(error_main=exc.args[0])

    if TYPE_CHECKING:
        assert isinstance(event_status, str)

    request.api_context.dbSession.flush(objects=[dbX509Certificate])
    request.api_context.pyramid_transaction_commit()

    # bookkeeping
    event_type_id = model_utils.OperationsEventType.from_string(event_type)
    dbOperationsEvent = lib_db.logger.log__OperationsEvent(
        request.api_context, event_type_id, event_payload_dict
    )
    lib_db.logger._log_object_event(
        request.api_context,
        dbOperationsEvent=dbOperationsEvent,
        event_status_id=model_utils.OperationsObjectEventStatus.from_string(
            event_status
        ),
        dbX509Certificate=dbX509Certificate,
    )

    if update_recents:
        event_update = lib_db.actions.operations_update_recents__global(
            request.api_context
        )
        event_update.operations_event_id__child_of = dbOperationsEvent.id
        request.api_context.dbSession.flush(objects=[event_update])

    if unactivated:
        # this will handle requeuing
        events.Certificate_unactivated(request.api_context, dbX509Certificate)

    if activated:
        # nothing to do?
        pass

    return dbX509Certificate, action


class View_List(Handler):
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:x509_certificates",
        renderer="/admin/x509_certificates.mako",
    )
    @view_config(route_name="admin:x509_certificates|json", renderer="json")
    def list_redirect(self):
        url_redirect = (
            "%s/x509-certificates/active"
            % self.request.api_context.application_settings["admin_prefix"]
        )
        if self.request.wants_json:
            url_redirect = "%s.json" % url_redirect
        return HTTPSeeOther(url_redirect)

    @view_config(
        route_name="admin:x509_certificates:all",
        renderer="/admin/x509_certificates.mako",
    )
    @view_config(
        route_name="admin:x509_certificates:all-paginated",
        renderer="/admin/x509_certificates.mako",
    )
    @view_config(
        route_name="admin:x509_certificates:active",
        renderer="/admin/x509_certificates.mako",
    )
    @view_config(
        route_name="admin:x509_certificates:active-paginated",
        renderer="/admin/x509_certificates.mako",
    )
    @view_config(
        route_name="admin:x509_certificates:active_expired",
        renderer="/admin/x509_certificates.mako",
    )
    @view_config(
        route_name="admin:x509_certificates:active_expired-paginated",
        renderer="/admin/x509_certificates.mako",
    )
    @view_config(
        route_name="admin:x509_certificates:expiring",
        renderer="/admin/x509_certificates.mako",
    )
    @view_config(
        route_name="admin:x509_certificates:expiring-paginated",
        renderer="/admin/x509_certificates.mako",
    )
    @view_config(
        route_name="admin:x509_certificates:inactive",
        renderer="/admin/x509_certificates.mako",
    )
    @view_config(
        route_name="admin:x509_certificates:inactive-paginated",
        renderer="/admin/x509_certificates.mako",
    )
    @view_config(
        route_name="admin:x509_certificates:inactive_unexpired",
        renderer="/admin/x509_certificates.mako",
    )
    @view_config(
        route_name="admin:x509_certificates:inactive_unexpired-paginated",
        renderer="/admin/x509_certificates.mako",
    )
    @view_config(route_name="admin:x509_certificates:all|json", renderer="json")
    @view_config(
        route_name="admin:x509_certificates:all-paginated|json", renderer="json"
    )
    @view_config(route_name="admin:x509_certificates:active|json", renderer="json")
    @view_config(
        route_name="admin:x509_certificates:active-paginated|json", renderer="json"
    )
    @view_config(
        route_name="admin:x509_certificates:active_expired|json", renderer="json"
    )
    @view_config(
        route_name="admin:x509_certificates:active_expired-paginated|json",
        renderer="json",
    )
    @view_config(route_name="admin:x509_certificates:expiring|json", renderer="json")
    @view_config(
        route_name="admin:x509_certificates:expiring-paginated|json", renderer="json"
    )
    @view_config(route_name="admin:x509_certificates:inactive|json", renderer="json")
    @view_config(
        route_name="admin:x509_certificates:inactive-paginated|json", renderer="json"
    )
    @view_config(
        route_name="admin:x509_certificates:inactive_unexpired|json", renderer="json"
    )
    @view_config(
        route_name="admin:x509_certificates:inactive_unexpired-paginated|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/x509-certificates/all.json",
            "section": "x509-certificate",
            "about": """list X509Certificate(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificates/all.json",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificates/all/{PAGE}.json",
            "section": "x509-certificate",
            "example": "curl {ADMIN_PREFIX}/x509-certificates/all/1.json",
            "variant_of": "/x509-certificates/all.json",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificates/active.json",
            "section": "x509-certificate",
            "about": """list X509Certificate(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificates/active.json",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificates/active/{PAGE}.json",
            "section": "x509-certificate",
            "example": "curl {ADMIN_PREFIX}/x509-certificates/active/1.json",
            "variant_of": "/x509-certificates/active.json",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificates/active-expired.json",
            "section": "x509-certificate",
            "about": """list X509Certificate(s) Active+Expired""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificates/active-expired.json",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificates/active-expired/{PAGE}.json",
            "section": "x509-certificate",
            "example": "curl {ADMIN_PREFIX}/x509-certificates/active-expired/1.json",
            "variant_of": "/x509-certificates/active-expired.json",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificates/expiring.json",
            "section": "x509-certificate",
            "about": """list X509Certificate(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificates/expiring.json",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificates/expiring/{PAGE}.json",
            "section": "x509-certificate",
            "example": "curl {ADMIN_PREFIX}/x509-certificates/expiring/1.json",
            "variant_of": "/x509-certificates/expiring.json",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificates/inactive.json",
            "section": "x509-certificate",
            "about": """list X509Certificate(s)""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificates/inactive.json",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificates/inactive/{PAGE}.json",
            "section": "x509-certificate",
            "example": "curl {ADMIN_PREFIX}/x509-certificates/inactive/1.json",
            "variant_of": "/x509-certificates/inactive.json",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificates/inactive-unexpired.json",
            "section": "x509-certificate",
            "about": """list X509Certificate(s) Inactive+Unexpired""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificates/inactive-unexpired.json",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificates/inactive-unexpired/{PAGE}.json",
            "section": "x509-certificate",
            "example": "curl {ADMIN_PREFIX}/x509-certificates/inactive-unexpired/1.json",
            "variant_of": "/x509-certificates/inactive.json",
        }
    )
    def list(self):
        expiring_days_ux = self.request.api_context.application_settings[
            "expiring_days_ux"
        ]
        if self.request.matched_route.name in (
            "admin:x509_certificates:expiring",
            "admin:x509_certificates:expiring-paginated",
            "admin:x509_certificates:expiring|json",
            "admin:x509_certificates:expiring-paginated|json",
        ):
            sidenav_option = "expiring"
            url_template = (
                "%s/x509-certificates/expiring/{0}"
                % self.request.api_context.application_settings["admin_prefix"]
            )
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__X509Certificate__count(
                self.request.api_context, days_to_expiry=expiring_days_ux
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__X509Certificate__paginated(
                self.request.api_context,
                days_to_expiry=expiring_days_ux,
                limit=items_per_page,
                offset=offset,
            )
        elif self.request.matched_route.name in (
            "admin:x509_certificates:active",
            "admin:x509_certificates:active-paginated",
            "admin:x509_certificates:active|json",
            "admin:x509_certificates:active-paginated|json",
        ):
            sidenav_option = "active"
            url_template = (
                "%s/x509-certificates/active/{0}"
                % self.request.api_context.application_settings["admin_prefix"]
            )
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__X509Certificate__count(
                self.request.api_context, is_active=True
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__X509Certificate__paginated(
                self.request.api_context,
                is_active=True,
                limit=items_per_page,
                offset=offset,
            )
        elif self.request.matched_route.name in (
            "admin:x509_certificates:active_expired",
            "admin:x509_certificates:active_expired-paginated",
            "admin:x509_certificates:active_expired|json",
            "admin:x509_certificates:active_expired-paginated|json",
        ):
            sidenav_option = "active-expired"
            url_template = (
                "%s/x509-certificates/active-expired/{0}"
                % self.request.api_context.application_settings["admin_prefix"]
            )
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__X509Certificate__count(
                self.request.api_context,
                days_to_expiry=expiring_days_ux,
                is_active=True,
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__X509Certificate__paginated(
                self.request.api_context,
                days_to_expiry=expiring_days_ux,
                is_active=True,
                limit=items_per_page,
                offset=offset,
            )
        elif self.request.matched_route.name in (
            "admin:x509_certificates:inactive",
            "admin:x509_certificates:inactive-paginated",
            "admin:x509_certificates:inactive|json",
            "admin:x509_certificates:inactive-paginated|json",
        ):
            sidenav_option = "inactive"
            url_template = (
                "%s/x509-certificates/inactive/{0}"
                % self.request.api_context.application_settings["admin_prefix"]
            )
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__X509Certificate__count(
                self.request.api_context, is_active=False
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__X509Certificate__paginated(
                self.request.api_context,
                is_active=False,
                limit=items_per_page,
                offset=offset,
            )
        elif self.request.matched_route.name in (
            "admin:x509_certificates:inactive_unexpired",
            "admin:x509_certificates:inactive_unexpired-paginated",
            "admin:x509_certificates:inactive_unexpired|json",
            "admin:x509_certificates:inactive_unexpired-paginated|json",
        ):
            sidenav_option = "inactive-unexpired"
            url_template = (
                "%s/x509-certificates/inactive-unexpired/{0}"
                % self.request.api_context.application_settings["admin_prefix"]
            )
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__X509Certificate__count(
                self.request.api_context, is_active=False, is_unexpired=True
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__X509Certificate__paginated(
                self.request.api_context,
                is_active=False,
                is_unexpired=True,
                limit=items_per_page,
                offset=offset,
            )
        else:
            sidenav_option = "all"
            url_template = (
                "%s/x509-certificates/all/{0}"
                % self.request.api_context.application_settings["admin_prefix"]
            )
            if self.request.wants_json:
                url_template = "%s.json" % url_template
            items_count = lib_db.get.get__X509Certificate__count(
                self.request.api_context
            )
            (pager, offset) = self._paginate(items_count, url_template=url_template)
            items_paged = lib_db.get.get__X509Certificate__paginated(
                self.request.api_context,
                limit=items_per_page,
                offset=offset,
                eagerload_web=True,
            )
        if self.request.matched_route.name.endswith("|json"):
            _certificates = {c.id: c.as_json for c in items_paged}
            return {
                "X509Certificates": _certificates,
                "pagination": json_pagination(items_count, pager),
            }

        return {
            "project": "peter_sslers",
            "X509Certificates_count": items_count,
            "X509Certificates": items_paged,
            "sidenav_option": sidenav_option,
            "expiring_days_ux": expiring_days_ux,
            "pager": pager,
        }

    @view_config(
        route_name="admin:x509_certificates:active_duplicates",
        renderer="/admin/x509_certificates-active_duplicates.mako",
    )
    @view_config(
        route_name="admin:x509_certificates:active_duplicates-paginated",
        renderer="/admin/x509_certificates-active_duplicates.mako",
    )
    @view_config(
        route_name="admin:x509_certificates:active_duplicates|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:x509_certificates:active_duplicates-paginated|json",
        renderer="json",
    )
    def active_duplicates(self):
        """
        undocumented test route
        """
        url_template = (
            "%s/x509-certificates/active-duplicates/{0}"
            % self.request.api_context.application_settings["admin_prefix"]
        )
        if self.request.wants_json:
            url_template = "%s.json" % url_template

        alt_items_per_page = 100

        items_count = lib_db.get.get_X509Certificates_duplicatePairs__count(
            self.request.api_context
        )
        (pager, offset) = self._paginate(
            items_count, url_template=url_template, items_per_page=alt_items_per_page
        )

        items_paged = lib_db.get.get_X509Certificates_duplicatePairs__paginated(
            self.request.api_context,
            limit=alt_items_per_page,
            offset=offset,
        )

        if self.request.matched_route.name.endswith("|json"):
            _certificates = [
                (i[0].as_json_replaces_candidate, i[1].as_json_replaces_candidate)
                for i in items_paged
            ]
            return {
                "X509CertificatesPairs": _certificates,
                "pagination": json_pagination(items_count, pager),
            }

        return {
            "project": "peter_sslers",
            "X509CertificatesPairs": items_paged,
            "pager": pager,
        }


class View_Search(Handler):
    @view_config(
        route_name="admin:x509_certificates:search",
        renderer="/admin/x509_certificates-search.mako",
    )
    @docify(
        {
            "endpoint": "/x509-certificates/search.json",
            "section": "x509-certificate",
            "about": """Search x509-certificates(s)""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/x509-certificates/search.json",
            "example": "curl "
            "--form 'ari_identifier=foo.bar' "
            "{ADMIN_PREFIX}/x509-certificates/search.json",
            "form_fields": {
                "ari_identifier": "the ari.identifier",
                "serial": "the serial",
            },
            "notes": "only one search type is permitted",
        }
    )
    @view_config(route_name="admin:x509_certificates:search|json", renderer="json")
    def search(self):
        self._search_results = {}
        self._search_query = {}
        if self.request.method == "POST":
            return self._search__submit()
        return self._search__print()

    def _search__print(self):
        if self.request.wants_json:
            return formatted_get_docs(self, "/x509-certificates/search.json")
        return render_to_response(
            "/admin/x509_certificates-search.mako",
            {
                "search_results": self._search_results,
                "search_query": self._search_query,
            },
            self.request,
        )

    def _search__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_X509Certificate_search, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid(formStash)

            ari_identifier = formStash.results["ari_identifier"]
            serial = formStash.results["serial"]

            dbX509Certificate: Optional[X509Certificate] = None
            dbX509Certificates: List[X509Certificate] = []
            if ari_identifier:
                dbX509Certificate = lib_db.get.get__X509Certificate__by_ariIdentifier(
                    self.request.api_context,
                    ari_identifier,
                )
            elif serial:
                dbX509Certificates = lib_db.get.get__X509Certificates__by_certSerial(
                    self.request.api_context,
                    serial,
                )

            self._search_results = {
                "X509Certificate": dbX509Certificate,
                "X509Certificates": dbX509Certificates,
            }
            self._search_query = {
                "ari_identifier": ari_identifier,
                "serial": serial,
            }
            if self.request.wants_json:
                return {
                    "result": "success",
                    "search_query": self._search_query,
                    "search_results": {
                        "X509Certificate": (
                            dbX509Certificate.as_json if dbX509Certificate else None
                        ),
                        "X509Certificates": [i.as_json for i in dbX509Certificates],
                    },
                }
            return self._search__print()

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._search__print)


class View_New(Handler):
    @view_config(route_name="admin:x509_certificate:upload")
    @view_config(route_name="admin:x509_certificate:upload|json", renderer="json")
    @docify(
        {
            "endpoint": "/x509-certificate/upload.json",
            "section": "x509-certificate",
            "about": """upload a X509Certificate""",
            "POST": True,
            "GET": None,
            "instructions": """curl {ADMIN_PREFIX}/x509-certificate/upload.json""",
            "example": """curl """
            """--form 'private_key_file_pem=@privkey1.pem' """
            """--form 'certificate_file=@cert1.pem' """
            """--form 'chain_file=@chain1.pem' """
            """{ADMIN_PREFIX}/x509-certificate/upload.json""",
            "form_fields": {
                "private_key_file_pem": "required",
                "chain_file": "required",
                "certificate_file": "required",
            },
        }
    )
    def upload(self):
        if self.request.method == "POST":
            return self._upload__submit()
        return self._upload__print()

    def _upload__print(self):
        if self.request.wants_json:
            return formatted_get_docs(self, "/x509-certificate/upload.json")
        return render_to_response(
            "/admin/x509_certificate-upload.mako", {}, self.request
        )

    def _upload__submit(self):
        try:
            (result, formStash) = formhandling.form_validate(
                self.request, schema=Form_Certificate_Upload__file, validate_get=False
            )
            if not result:
                raise formhandling.FormInvalid(formStash)

            private_key_pem = formhandling.slurp_file_field(
                formStash, "private_key_file_pem"
            )
            if not isinstance(private_key_pem, str):
                private_key_pem = private_key_pem.decode("utf8")
            (
                dbPrivateKey,
                pkey_is_created,
            ) = lib_db.getcreate.getcreate__PrivateKey__by_pem_text(
                self.request.api_context,
                private_key_pem,
                private_key_source_id=model_utils.PrivateKeySource.IMPORTED,
                private_key_type_id=model_utils.PrivateKeyType.STANDARD,
                # TODO: We should infer the above based on the private_key_cycle
                discovery_type="via upload x509_certificate",
            )
            ca_chain_pem = formhandling.slurp_file_field(formStash, "chain_file")
            if not isinstance(ca_chain_pem, str):
                ca_chain_pem = ca_chain_pem.decode("utf8")
            (
                dbX509CertificateTrustChain,
                chain_is_created,
            ) = lib_db.getcreate.getcreate__X509CertificateTrustChain__by_pem_text(
                self.request.api_context,
                ca_chain_pem,
                discovery_type="upload",
            )

            certificate_pem = formhandling.slurp_file_field(
                formStash, "certificate_file"
            )
            if not isinstance(certificate_pem, str):
                certificate_pem = certificate_pem.decode("utf8")

            _certificate_domain_names = cert_utils.parse_cert__domains(
                cert_pem=certificate_pem,
            )
            if not _certificate_domain_names:
                raise ValueError("could not find any domain names in the certificate")
            (
                dbUniqueFQDNSet,
                is_created_fqdn,
            ) = lib_db.getcreate.getcreate__UniqueFQDNSet__by_domains(
                self.request.api_context,
                _certificate_domain_names,
                discovery_type="via upload x509_certificate",
            )

            (
                dbX509Certificate,
                cert_is_created,
            ) = lib_db.getcreate.getcreate__X509Certificate(
                self.request.api_context,
                certificate_pem,
                cert_domains_expected=_certificate_domain_names,
                dbX509CertificateTrustChain=dbX509CertificateTrustChain,
                certificate_type_id=model_utils.CertificateType.RAW_IMPORTED,
                # optionals
                dbUniqueFQDNSet=dbUniqueFQDNSet,
                dbPrivateKey=dbPrivateKey,
                discovery_type="via upload x509_certificate",
                is_active=False,
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "X509Certificate": {
                        "created": cert_is_created,
                        "id": dbX509Certificate.id,
                        "url": "%s/x509-certificate/%s"
                        % (
                            self.request.api_context.application_settings[
                                "admin_prefix"
                            ],
                            dbX509Certificate.id,
                        ),
                    },
                    "X509CertificateTrustChain": {
                        "created": chain_is_created,
                        "id": dbX509CertificateTrustChain.id,
                    },
                    "PrivateKey": {"created": pkey_is_created, "id": dbPrivateKey.id},
                }
            return HTTPSeeOther(
                "%s/x509-certificate/%s"
                % (
                    self.request.api_context.application_settings["admin_prefix"],
                    dbX509Certificate.id,
                )
            )

        except formhandling.FormInvalid as exc:  # noqa: F841
            if self.request.wants_json:
                return {"result": "error", "form_errors": formStash.errors}
            return formhandling.form_reprint(self.request, self._upload__print)


class View_Focus(Handler):
    dbX509Certificate: Optional[X509Certificate] = None

    def _focus(self) -> X509Certificate:
        if self.dbX509Certificate is None:
            dbX509Certificate = lib_db.get.get__X509Certificate__by_id(
                self.request.api_context, self.request.matchdict["id"]
            )
            if not dbX509Certificate:
                raise HTTPNotFound("invalid X509Certificate")
            self.dbX509Certificate = dbX509Certificate
            self._focus_item = dbX509Certificate
            self._focus_url = "%s/x509-certificate/%s" % (
                self.request.api_context.application_settings["admin_prefix"],
                self.dbX509Certificate.id,
            )
        return self.dbX509Certificate

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:x509_certificate:focus",
        renderer="/admin/x509_certificate-focus.mako",
    )
    @view_config(route_name="admin:x509_certificate:focus|json", renderer="json")
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}.json",
            "section": "x509-certificate",
            "about": """X509Certificate focus""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1.json",
        }
    )
    def focus(self):
        dbX509Certificate = self._focus()
        if self.request.wants_json:
            return {"X509Certificate": dbX509Certificate.as_json}
        # x-x509-server-cert
        templating_vars: Dict[str, Union[str, None, X509Certificate, Dict]] = {
            "project": "peter_sslers",
            "X509Certificate": dbX509Certificate,
            "_AriCheck": None,
        }
        if "AriCheck" in self.request.params:
            templating_vars["_AriCheck"] = utils.unurlify(
                self.request.params["AriCheck"]
            )
        return templating_vars

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:x509_certificate:focus:cert:raw", renderer="string")
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/cert.pem",
            "section": "x509-certificate",
            "about": """X509Certificate focus. as PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/cert.pem",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/cert.pem.txt",
            "section": "x509-certificate",
            "about": """X509Certificate focus. as PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/cert.pem.txt",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/cert.cer",
            "section": "x509-certificate",
            "about": """X509Certificate focus. as DER""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/cert.cer",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/cert.crt",
            "section": "x509-certificate",
            "about": """X509Certificate focus. as DER""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/cert.crt",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/cert.der",
            "section": "x509-certificate",
            "about": """X509Certificate focus. as DER""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/cert.der",
        }
    )
    def focus_raw(self):
        """
        for extensions, see `cert_utils.EXTENSION_TO_MIME`
        """
        dbX509Certificate = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbX509Certificate.cert_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbX509Certificate.cert_pem
        elif self.request.matchdict["format"] in ("cer", "crt", "der"):
            as_der = cert_utils.convert_pem_to_der(pem_data=dbX509Certificate.cert_pem)
            response = Response()
            if self.request.matchdict["format"] in ("crt", "der"):
                response.content_type = "application/x-x509-server-cert"
            elif self.request.matchdict["format"] in ("cer",):
                response.content_type = "application/pkix-cert"
            response.body = as_der
            return response
        return "UNSUPPORTED FORMAT"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:x509_certificate:focus:parse|json", renderer="json")
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/parse.json",
            "section": "x509-certificate",
            "about": """X509Certificate focus. parsed""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/parse.json",
        }
    )
    def parse_json(self):
        dbX509Certificate = self._focus()
        return {
            "X509Certificate": {
                "id": dbX509Certificate.id,
                "parsed": cert_utils.parse_cert(cert_pem=dbX509Certificate.cert_pem),
            }
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:x509_certificate:focus:chain:raw", renderer="string")
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/chain.pem",
            "section": "x509-certificate",
            "about": """X509Certificate focus. Chain PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/chain.pem",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/chain.pem.txt",
            "section": "x509-certificate",
            "about": """X509Certificate focus. chain PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/chain.pem.txt",
        }
    )
    def chain(self):
        dbX509Certificate = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbX509Certificate.cert_chain_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbX509Certificate.cert_chain_pem
        return "chain.pem"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:x509_certificate:focus:fullchain:raw", renderer="string"
    )
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/fullchain.pem",
            "section": "x509-certificate",
            "about": """X509Certificate focus. FullChain PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/fullchain.pem",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/fullchain.pem.txt",
            "section": "x509-certificate",
            "about": """X509Certificate focus. FullChain PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/fullchain.pem.txt",
        }
    )
    def fullchain(self):
        dbX509Certificate = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbX509Certificate.cert_fullchain_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbX509Certificate.cert_fullchain_pem
        return "fullchain.pem"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:x509_certificate:focus:privatekey:raw", renderer="string"
    )
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/privkey.pem",
            "section": "x509-certificate",
            "about": """X509Certificate focus. PrivateKey PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/privkey.pem",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/privkey.pem.txt",
            "section": "x509-certificate",
            "about": """X509Certificate focus. PrivateKey PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/privkey.pem.txt",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/privkey.key",
            "section": "x509-certificate",
            "about": """X509Certificate focus. PrivateKey DER""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/privkey.key",
        }
    )
    def privatekey(self):
        dbX509Certificate = self._focus()
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return dbX509Certificate.private_key.key_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return dbX509Certificate.private_key.key_pem
        elif self.request.matchdict["format"] == "key":
            as_der = cert_utils.convert_pem_to_der(
                pem_data=dbX509Certificate.private_key.key_pem
            )
            response = Response()
            response.content_type = "application/pkcs8"
            response.body = as_der
            return response
        return "privatekey.pem"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:x509_certificate:focus:config|json", renderer="json")
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/config.json",
            "section": "x509-certificate",
            "about": """X509Certificate Config""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/config.json",
        }
    )
    def config_json(self):
        dbX509Certificate = self._focus()
        if self.request.params.get("idonly", None):
            rval = dbX509Certificate.config_payload_idonly
        else:
            rval = dbX509Certificate.config_payload
        return rval

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:x509_certificate:focus:config|zip")
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/config.zip",
            "section": "x509-certificate",
            "about": """X509Certificate Config.zip""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/config.zip",
        }
    )
    def config_zip(self):
        """
        generates a certbot style configuration
        note: there is no renderer, because we generate a `Response`
        """
        dbX509Certificate = self._focus()
        try:
            tmpfile = archive_zipfile(dbX509Certificate)
            response = Response(
                content_type="application/zip", body_file=tmpfile, status=200
            )
            response.headers["Content-Disposition"] = (
                "attachment; filename= cert%s.zip" % dbX509Certificate.id
            )
            return response

        except Exception as exc:  # noqa: F841
            return HTTPSeeOther(
                "%s?result=error&error=could+not+generate+zipfile" % self._focus_url
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:x509_certificate:focus:ari_check_history",
        renderer="/admin/x509_certificate-focus-ari_checks.mako",
    )
    @view_config(
        route_name="admin:x509_certificate:focus:ari_check_history-paginated",
        renderer="/admin/x509_certificate-focus-ari_checks.mako",
    )
    @view_config(
        route_name="admin:x509_certificate:focus:ari_check_history|json",
        renderer="json",
    )
    @view_config(
        route_name="admin:x509_certificate:focus:ari_check_history-paginated|json",
        renderer="json",
    )
    def ari_check_history(self):
        dbX509Certificate = self._focus()
        items_count = lib_db.get.get__AriCheck__by_X509CertificateId__count(
            self.request.api_context, dbX509Certificate.id
        )
        url_template = "%s/ari-check-history/{0}" % self._focus_url
        if self.request.wants_json:
            url_template = "%s.json" % url_template
        (pager, offset) = self._paginate(items_count, url_template=url_template)
        items_paged = lib_db.get.get__AriCheck__by_X509CertificateId__paginated(
            self.request.api_context,
            dbX509Certificate.id,
            limit=items_per_page,
            offset=offset,
        )
        if self.request.wants_json:
            _ari_checks = {k.id: k.as_json for k in items_paged}
            return {
                "AriChecks": _ari_checks,
                "pagination": json_pagination(items_count, pager),
            }
        return {
            "project": "peter_sslers",
            "X509Certificate": dbX509Certificate,
            "AriCheck_count": items_count,
            "AriChecks": items_paged,
            "pager": pager,
        }


class View_Focus_via_X509CertificateTrustChain(View_Focus):
    def _focus_via_X509CertificateTrustChain(self):
        dbX509Certificate = self._focus()
        x509_certificate_trust_chain_id = int(self.request.matchdict["id_cachain"])
        if (
            x509_certificate_trust_chain_id
            not in dbX509Certificate.x509_certificate_trust_chain_ids
        ):
            raise HTTPNotFound("invalid X509CertificateTrustChain")
        return (dbX509Certificate, x509_certificate_trust_chain_id)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:x509_certificate:focus:via_x509_certificate_trust_chain:config|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/via-certificate-ca-chain/{ID_CACHAIN}/config.json",
            "section": "x509-certificate",
            "about": """X509Certificate via X509CertificateTrustChain Config.json""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/via-certificate-ca-chain/2/config.json",
        }
    )
    def config_json(self):
        (
            dbX509Certificate,
            x509_certificate_trust_chain_id,
        ) = self._focus_via_X509CertificateTrustChain()
        if self.request.params.get("idonly", None):
            rval = dbX509Certificate.custom_config_payload(
                x509_certificate_trust_chain_id=x509_certificate_trust_chain_id,
                id_only=True,
            )
        else:
            rval = dbX509Certificate.custom_config_payload(
                x509_certificate_trust_chain_id=x509_certificate_trust_chain_id,
                id_only=False,
            )
        return rval

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:x509_certificate:focus:via_x509_certificate_trust_chain:config|zip"
    )
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/via-certificate-ca-chain/{ID_CACHAIN}/config.zip",
            "section": "x509-certificate",
            "about": """X509Certificate via X509CertificateTrustChain Config.zip""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/via-certificate-ca-chain/2/config.zip",
        }
    )
    def config_zip(self):
        (
            dbX509Certificate,
            x509_certificate_trust_chain_id,
        ) = self._focus_via_X509CertificateTrustChain()
        try:
            tmpfile = archive_zipfile(
                dbX509Certificate,
                x509_certificate_trust_chain_id=x509_certificate_trust_chain_id,
            )
            response = Response(
                content_type="application/zip", body_file=tmpfile, status=200
            )
            response.headers["Content-Disposition"] = (
                "attachment; filename= cert%s-chain%s.zip"
                % (
                    dbX509Certificate.id,
                    x509_certificate_trust_chain_id,
                )
            )
            return response

        except Exception as exc:  # noqa: F841
            return HTTPSeeOther(
                "%s?result=error&error=could+not+generate+zipfile" % self._focus_url
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:x509_certificate:focus:via_x509_certificate_trust_chain:chain:raw",
        renderer="string",
    )
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/via-certificate-ca-chain/{ID_CACHAIN}/chain.pem",
            "section": "x509-certificate",
            "about": """X509Certificate via X509CertificateTrustChain Chain-PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/via-certificate-ca-chain/2/chain.pem",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/via-certificate-ca-chain/{ID_CACHAIN}/chain.pem.txt",
            "section": "x509-certificate",
            "about": """X509Certificate via X509CertificateTrustChain Chain-PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/via-certificate-ca-chain/2/chain.pem.txt",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/via-certificate-ca-chain/{ID_CACHAIN}/chain.cer",
            "section": "x509-certificate",
            "about": """X509Certificate via X509CertificateTrustChain Chain-DER""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/via-certificate-ca-chain/2/chain.cer",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/via-certificate-ca-chain/{ID_CACHAIN}/chain.crt",
            "section": "x509-certificate",
            "about": """X509Certificate via X509CertificateTrustChain Chain-DER""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/via-certificate-ca-chain/2/chain.crt",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/via-certificate-ca-chain/{ID_CACHAIN}/chain.der",
            "section": "x509-certificate",
            "about": """X509Certificate via X509CertificateTrustChain Chain-DER""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/via-certificate-ca-chain/2/chain.der",
        }
    )
    def chain(self):
        (
            dbX509Certificate,
            x509_certificate_trust_chain_id,
        ) = self._focus_via_X509CertificateTrustChain()
        cert_chain_pem = dbX509Certificate.valid_cert_chain_pem(
            x509_certificate_trust_chain_id
        )
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return cert_chain_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return cert_chain_pem
        elif self.request.matchdict["format"] in ("cer", "crt", "der"):
            as_der = cert_utils.convert_pem_to_der(pem_data=cert_chain_pem)
            response = Response()
            if self.request.matchdict["format"] in ("crt", "der"):
                response.content_type = "application/x-x509-ca-cert"
            elif self.request.matchdict["format"] in ("cer",):
                response.content_type = "application/pkix-cert"
            response.body = as_der
            return response
        return "chain.pem"

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:x509_certificate:focus:via_x509_certificate_trust_chain:fullchain:raw",
        renderer="string",
    )
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/via-certificate-ca-chain/{ID_CACHAIN}/fullchain.pem",
            "section": "x509-certificate",
            "about": """X509Certificate via X509CertificateTrustChain FullChain-PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/via-certificate-ca-chain/2/fullchain.pem",
        }
    )
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/via-certificate-ca-chain/{ID_CACHAIN}/fullchain.pem.txt",
            "section": "x509-certificate",
            "about": """X509Certificate via X509CertificateTrustChain FullChain-PEM""",
            "POST": None,
            "GET": True,
            "example": "curl {ADMIN_PREFIX}/x509-certificate/1/via-certificate-ca-chain/2/fullchain.pem.txt",
        }
    )
    def fullchain(self):
        (
            dbX509Certificate,
            x509_certificate_trust_chain_id,
        ) = self._focus_via_X509CertificateTrustChain()
        cert_fullchain_pem = dbX509Certificate.valid_cert_fullchain_pem(
            x509_certificate_trust_chain_id
        )
        if self.request.matchdict["format"] == "pem":
            self.request.response.content_type = "application/x-pem-file"
            return cert_fullchain_pem
        elif self.request.matchdict["format"] == "pem.txt":
            return cert_fullchain_pem
        return "fullchain.pem"


class View_Focus_Manipulate(View_Focus):
    @view_config(route_name="admin:x509_certificate:focus:ari_check", renderer=None)
    @view_config(
        route_name="admin:x509_certificate:focus:ari_check|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/ari-check.json",
            "section": "x509-certificate",
            "about": """Checks for ARI info. """,
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/x509-certificate/1/ari-check.json",
            "example": "curl -X POST {ADMIN_PREFIX}/x509-certificate/1/ari-check.json",
        }
    )
    def ari_check(self):
        dbX509Certificate = self._focus()
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(self, "/x509-certificate/{ID}/ari-check.json")
            raise HTTPSeeOther(
                "%s?result=error&operation=ari-check&message=POST+required"
                % self._focus_url
            )
        try:
            # check ARI info
            # ariresult is: None (failure) or Tuple(payload, headers)
            dbAriObject, ari_check_result = lib_db.actions_acme.do__AcmeV2_AriCheck(
                self.request.api_context,
                dbX509Certificate=dbX509Certificate,
                force_check=True,
            )
            if self.request.wants_json:
                return {"result": "success", "AriCheck": dbAriObject.as_json}
            return HTTPSeeOther(
                "%s?result=success&operation=ari-check&AriCheck=%s"
                % (self._focus_url, utils.urlify(dbAriObject.as_json))
            )

        except (
            errors.AcmeAriCheckDeclined,
            errors.AcmeServerError,
            errors.AcmeServerErrorPublic,
        ) as exc:

            msg: str
            if isinstance(exc, errors.AcmeServerError):
                msg = "%s|%s" % (exc.args[0], str(exc.args[2]))
            else:
                msg = str(exc.args[0])

            if self.request.wants_json:
                return {
                    "result": "error",
                    "error": msg,
                }
            raise HTTPSeeOther(
                "%s?result=error&operation=ari-check&error-encoded=%s"
                % (self._focus_url, msg)
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(
        route_name="admin:x509_certificate:focus:nginx_cache_expire", renderer=None
    )
    @view_config(
        route_name="admin:x509_certificate:focus:nginx_cache_expire|json",
        renderer="json",
    )
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/nginx-cache-expire.json",
            "section": "x509-certificate",
            "about": """Flushes the Nginx cache. This will make background requests to configured Nginx servers, instructing them to flush their cache. """,
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/x509-certificate/1/nginx-cache-expire.json",
            "example": "curl -X POST {ADMIN_PREFIX}/x509-certificate/1/nginx-cache-expire.json",
        }
    )
    def nginx_expire(self):
        dbX509Certificate = self._focus()
        if self.request.method != "POST":
            if self.request.wants_json:
                return formatted_get_docs(
                    self, "/x509-certificate/{ID}/nginx-cache-expire.json"
                )
            raise HTTPSeeOther(
                "%s?result=error&operation=nginx-cache-expire&message=POST+required"
                % self._focus_url
            )
        try:
            # could raise `InvalidRequest("nginx is not enabled")`
            self.request.api_context._ensure_nginx()

            dbDomains = [
                c2d.domain for c2d in dbX509Certificate.unique_fqdn_set.to_domains
            ]

            # this will generate it's own log__OperationsEvent
            success, dbEvent = utils_nginx.nginx_expire_cache(
                self.request, self.request.api_context, dbDomains=dbDomains
            )
            if self.request.wants_json:
                return {"result": "success", "operations_event": {"id": dbEvent.id}}
            return HTTPSeeOther(
                "%s?result=success&operation=nginx-cache-expire&event.id=%s"
                % (self._focus_url, dbEvent.id)
            )

        except errors.InvalidRequest as exc:
            if self.request.wants_json:
                return {
                    "result": "error",
                    "error": exc.args[0],
                }
            raise HTTPSeeOther(
                "%s?result=error&operation=nginx-cache-expire&error=nginx+is+not+enabled"
                % self._focus_url
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:x509_certificate:focus:mark", renderer=None)
    @view_config(route_name="admin:x509_certificate:focus:mark|json", renderer="json")
    @docify(
        {
            "endpoint": "/x509-certificate/{ID}/mark.json",
            "section": "x509-certificate",
            "about": """Mark""",
            "POST": True,
            "GET": None,
            "instructions": "curl {ADMIN_PREFIX}/x509-certificate/1/mark.json",
            "examples": [
                """curl """
                """--form 'action=active' """
                """{ADMIN_PREFIX}/x509-certificate/1/mark.json""",
            ],
            "form_fields": {"action": "the intended action"},
            "valid_options": {
                "action": Form_X509Certificate_mark.fields["action"].list,
            },
        }
    )
    def mark(self):
        dbX509Certificate = self._focus()  # noqa: F841
        if self.request.method == "POST":
            return self._focus_mark__submit()
        return self._mark__print()

    def _mark__print(self):
        if self.request.wants_json:
            return formatted_get_docs(self, "/x509-certificate/{ID}/mark.json")
        url_post_required = (
            "%s?result=error&error=post+required&operation=mark" % self._focus_url
        )
        return HTTPSeeOther(url_post_required)

    def _focus_mark__submit(self):
        dbX509Certificate = self._focus()  # noqa: F841
        try:
            action = self.request.params.get(  # needed in case exception is raised
                "action"
            )
            dbX509Certificate, action = submit__mark(
                self.request,
                dbX509Certificate=dbX509Certificate,
                acknowledge_transaction_commits=True,
            )
            if self.request.wants_json:
                return {
                    "result": "success",
                    "X509Certificate": dbX509Certificate.as_json,
                    "operation": "mark",
                    "action": action,
                }
            url_success = "%s?result=success&operation=mark&action=%s" % (
                self._focus_url,
                action,
            )
            return HTTPSeeOther(url_success)

        except formhandling.FormInvalid as exc:
            if self.request.wants_json:
                return {"result": "error", "form_errors": exc.formStash.errors}
            url_failure = "%s?result=error&error=%s&operation=mark&action=%s" % (
                self._focus_url,
                errors.formstash_to_querystring(exc.formStash),
                action,
            )
            raise HTTPSeeOther(url_failure)
