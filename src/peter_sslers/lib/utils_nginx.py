# stdlib
import json
from typing import Dict
from typing import List
from typing import Tuple
from typing import TYPE_CHECKING
from typing import Union

# pypi
import requests

# local
from . import utils
from ..lib.db.logger import log__OperationsEvent
from ..model import utils as model_utils

if TYPE_CHECKING:
    from pyramid.request import Request

    from .context import ApiContext
    from ..model.objects import Domain

# ==============================================================================

DEBUG_CONCEPT = False


class NginxSession(object):
    session: requests.Session

    def __init__(self, request: "Request"):
        """
        :param request: The current Pyramid `request` object
        """
        sess = utils.new_BrowserSession()
        _auth = request.api_context.application_settings.get("nginx.userpass")
        if _auth:
            sess.auth = tuple(_auth.split(":"))  # type: ignore[assignment]

        servers_allow_invalid = request.api_context.application_settings.get(
            "nginx.servers_pool_allow_invalid"
        )
        if servers_allow_invalid:
            sess.verify = False
        else:
            ca_bundle_pem = request.api_context.application_settings.get(
                "nginx.ca_bundle_pem"
            )
            if ca_bundle_pem:
                sess.verify = ca_bundle_pem
            if DEBUG_CONCEPT:
                print("=============================")
                print("ca_bundle_pem", ca_bundle_pem)
                print("=============================")

        self.session = sess

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.session.close()

    def get(self, *args, **kwargs):
        return self.session.get(*args, **kwargs)

    def post(self, *args, **kwargs):
        return self.session.post(*args, **kwargs)


def nginx_flush_cache(
    request: "Request",
    ctx: "ApiContext",
) -> Tuple:
    """
    :param request: The current Pyramid `request` object
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    """
    _reset_path = request.api_context.application_settings["nginx.reset_path"]
    timeout = request.api_context.application_settings["nginx.timeout"]
    with NginxSession(request) as sess:
        rval: Dict[str, Union[List, Dict]] = {
            "errors": [],
            "success": [],
            "servers": {},
        }
        for _server in request.api_context.application_settings["nginx.servers_pool"]:
            status = None
            try:
                reset_url = _server + _reset_path + "/all"
                response = sess.get(reset_url, timeout=timeout)
                if response.status_code == 200:
                    response_json = json.loads(response.text)
                    status = response_json
                    if response_json["result"] != "success":
                        rval["errors"].append(_server)  # type: ignore[union-attr]
                    else:
                        rval["success"].append(_server)  # type: ignore[union-attr]
                else:
                    rval["errors"].append(_server)  # type: ignore[union-attr]
                    status = {
                        "status": "error",
                        "error": "response",
                        "response": {
                            "status_code": response.status_code,
                            "text": response.text,
                        },
                    }
            except Exception as exc:
                rval["errors"].append(_server)  # type: ignore[union-attr]
                status = {
                    "status": "error",
                    "error": "Exception",
                    "Exception": "%s" % str(exc),  # this could be an object
                }
            rval["servers"][_server] = status
    dbEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("operations__nginx_cache_flush"),
    )
    return True, dbEvent, rval


def nginx_status(
    request: "Request",
    ctx: "ApiContext",
) -> Dict:
    """
    returns the status document for each server

    :param request: The current Pyramid `request` object
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    """
    status_path = request.api_context.application_settings["nginx.status_path"]
    timeout = request.api_context.application_settings["nginx.timeout"]
    with NginxSession(request) as sess:
        rval: Dict[str, Union[List, Dict]] = {
            "errors": [],
            "success": [],
            "servers": {},
        }
        for _server in request.api_context.application_settings["nginx.servers_pool"]:
            _status = None
            try:
                status_url = _server + status_path
                response = sess.get(status_url, timeout=timeout)
                if response.status_code == 200:
                    response_json = json.loads(response.text)
                    _status = response_json
                    rval["success"].append(_server)  # type: ignore[union-attr]
                else:
                    rval["errors"].append(_server)  # type: ignore[union-attr]
                    _status = {
                        "status": "error",
                        "error": "response",
                        "response": {
                            "status_code": response.status_code,
                            "text": response.text,
                        },
                    }
            except Exception as exc:
                rval["errors"].append(_server)  # type: ignore[union-attr]
                _status = {
                    "status": "error",
                    "error": "Exception",
                    "Exception": "%s" % str(exc),  # this could be an object
                }
            rval["servers"][_server] = _status
    return rval


def nginx_expire_cache(
    request: "Request", ctx: "ApiContext", dbDomains: List["Domain"]
) -> Tuple:
    """
    :param request: The current Pyramid `request` object
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbDomains:
    """
    if not dbDomains:
        raise ValueError("no domains submitted")
    domain_ids: Dict[str, set] = {"success": set([]), "failure": set([])}
    _reset_path = request.api_context.application_settings["nginx.reset_path"]
    timeout = request.api_context.application_settings["nginx.timeout"]
    with NginxSession(request) as sess:
        for _server in request.api_context.application_settings["nginx.servers_pool"]:
            for domain in dbDomains:
                try:
                    reset_url = (
                        _server + _reset_path + "/domain/%s" % domain.domain_name
                    )
                    response = sess.get(reset_url, timeout=timeout)
                    if response.status_code == 200:
                        response_json = json.loads(response.text)
                        if response_json["result"] == "success":
                            domain_ids["success"].add(domain.id)
                        else:
                            # log the url?
                            domain_ids["failure"].add(domain.id)
                    else:
                        # log the url?
                        domain_ids["failure"].add(domain.id)
                except Exception as exc:  # noqa: F841
                    # log the url?
                    domain_ids["failure"].add(domain.id)

    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict["domain_ids"] = {
        "success": list(domain_ids["success"]),
        "failure": list(domain_ids["failure"]),
    }
    dbEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("operations__nginx_cache_expire"),
        event_payload_dict,
    )
    return True, dbEvent
