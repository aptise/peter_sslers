# stdlib
import json
import logging

# pypi
import requests

# local
from ..model import utils as model_utils
from . import utils
from .. import lib  # for `lib.db.logger`


# ==============================================================================


def new_nginx_session(request):
    """
    :param request: The current Pyramid `request` object
    """
    sess = requests.Session()
    _auth = request.registry.settings["app_settings"].get("nginx.userpass")
    if _auth:
        sess.auth = tuple(_auth.split(":"))
    servers_allow_invalid = request.registry.settings["app_settings"].get(
        "nginx.servers_pool_allow_invalid"
    )
    if servers_allow_invalid:
        sess.verify = False
    return sess


def nginx_flush_cache(request, ctx):
    """
    :param request: The current Pyramid `request` object
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    """
    _reset_path = request.registry.settings["app_settings"]["nginx.reset_path"]
    timeout = request.registry.settings["app_settings"]["nginx.timeout"]
    sess = new_nginx_session(request)
    rval = {"errors": [], "success": [], "servers": {}}
    for _server in request.registry.settings["app_settings"]["nginx.servers_pool"]:
        status = None
        try:
            reset_url = _server + _reset_path + "/all"
            response = sess.get(reset_url, timeout=timeout, verify=False)
            if response.status_code == 200:
                response_json = json.loads(response.text)
                status = response_json
                if response_json["result"] != "success":
                    rval["errors"].append(_server)
                else:
                    rval["success"].append(_server)
            else:
                rval["errors"].append(_server)
                status = {
                    "status": "error",
                    "error": "response",
                    "response": {
                        "status_code": response.status_code,
                        "text": response.text,
                    },
                }
        except Exception as exc:
            rval["errors"].append(_server)
            status = {
                "status": "error",
                "error": "Exception",
                "Exception": "%s" % str(exc),  # this could be an object
            }
        rval["servers"][_server] = status
    dbEvent = lib.db.logger.log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("operations__nginx_cache_flush"),
    )
    return True, dbEvent, rval


def nginx_status(request, ctx):
    """
    returns the status document for each server

    :param request: The current Pyramid `request` object
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    """
    status_path = request.registry.settings["app_settings"]["nginx.status_path"]
    timeout = request.registry.settings["app_settings"]["nginx.timeout"]
    sess = new_nginx_session(request)
    rval = {"errors": [], "success": [], "servers": {}}
    for _server in request.registry.settings["app_settings"]["nginx.servers_pool"]:
        status = None
        try:
            status_url = _server + status_path
            response = sess.get(status_url, timeout=timeout, verify=False)
            if response.status_code == 200:
                response_json = json.loads(response.text)
                status = response_json
                rval["success"].append(_server)
            else:
                rval["errors"].append(_server)
                status = {
                    "status": "error",
                    "error": "response",
                    "response": {
                        "status_code": response.status_code,
                        "text": response.text,
                    },
                }
        except Exception as exc:
            rval["errors"].append(_server)
            status = {
                "status": "error",
                "error": "Exception",
                "Exception": "%s" % str(exc),  # this could be an object
            }
        rval["servers"][_server] = status
    return rval


def nginx_expire_cache(request, ctx, dbDomains=None):
    """
    :param request: The current Pyramid `request` object
    :param ctx: (required) A :class:`lib.utils.ApiContext` instance
    :param dbDomains:
    """
    if not dbDomains:
        raise ValueError("no domains submitted")
    domain_ids = {"success": set([]), "failure": set([])}
    _reset_path = request.registry.settings["app_settings"]["nginx.reset_path"]
    timeout = request.registry.settings["app_settings"]["nginx.timeout"]
    sess = new_nginx_session(request)
    for _server in request.registry.settings["app_settings"]["nginx.servers_pool"]:
        for domain in dbDomains:
            try:
                reset_url = _server + _reset_path + "/domain/%s" % domain.domain_name
                response = sess.get(reset_url, timeout=timeout, verify=False)
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
            except Exception as exc:
                # log the url?
                domain_ids["failure"].add(domain.id)

    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict["domain_ids"] = {
        "success": list(domain_ids["success"]),
        "failure": list(domain_ids["failure"]),
    }
    dbEvent = lib.db.logger.log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("operations__nginx_cache_expire"),
        event_payload_dict,
    )
    return True, dbEvent
