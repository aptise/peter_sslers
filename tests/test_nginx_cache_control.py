import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests

from peter_sslers.lib import utils_nginx
from peter_sslers.web.views_admin import api


@pytest.fixture
def nginx(monkeypatch):
    settings = {
        "nginx.servers_pool": ["https://one", "https://two"],
        "nginx.reset_path": "/reset", "nginx.status_path": "/status",
        "nginx.timeout": 3, "nginx.userpass": "user:pass:with:colons",
    }
    request = SimpleNamespace(api_context=SimpleNamespace(application_settings=settings))
    session = Mock()
    monkeypatch.setattr(utils_nginx.utils, "new_BrowserSession", Mock(return_value=session))
    event = SimpleNamespace(id=1)
    logger = Mock(return_value=event)
    monkeypatch.setattr(utils_nginx, "log__OperationsEvent", logger)
    return request, session, logger


def reply(payload=None, status=200):
    response = Mock(status_code=status, text=json.dumps(payload))
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    return response


@pytest.mark.parametrize("failure", [requests.Timeout("timeout"), reply({}, 503), reply([]), reply({"result": "error"})])
def test_flush_reports_partial_failure_and_closes_responses(nginx, failure):
    request, session, _ = nginx
    good = reply({"result": "success"})
    session.get.side_effect = [good, failure]
    success, _, results = utils_nginx.nginx_flush_cache(request, request.api_context)
    assert success is False
    assert results["success"] == ["https://one"]
    assert results["errors"] == ["https://two"]
    assert session.auth == ("user", "pass:with:colons")
    good.__exit__.assert_called_once()
    session.close.assert_called_once()
    if not isinstance(failure, Exception):
        failure.__exit__.assert_called_once()


def test_flush_reports_complete_success(nginx):
    request, session, _ = nginx
    session.get.side_effect = [reply({"result": "success"}), reply({"result": "success"})]
    assert utils_nginx.nginx_flush_cache(request, request.api_context)[0] is True


@pytest.mark.parametrize("reverse", [False, True])
def test_expiry_failure_wins_regardless_of_server_order(nginx, reverse):
    request, session, logger = nginx
    responses = [reply({"result": "success"}), reply({"result": "error"})]
    session.get.side_effect = responses[::-1] if reverse else responses
    domain = SimpleNamespace(id=7, domain_name="example.com")
    success, _ = utils_nginx.nginx_expire_cache(request, request.api_context, [domain])
    assert success is False
    assert logger.call_args.args[2]["domain_ids"] == {"success": [], "failure": [7]}
    for response in responses:
        response.__exit__.assert_called_once()


def test_status_continues_after_network_failure(nginx):
    request, session, _ = nginx
    response = reply({"workers": 4})
    session.get.side_effect = [requests.Timeout("timeout"), response]
    result = utils_nginx.nginx_status(request, request.api_context)
    assert result["errors"] == ["https://one"]
    assert result["success"] == ["https://two"]
    response.__exit__.assert_called_once()


@pytest.mark.parametrize("success", [False, True])
def test_flush_api_exposes_actual_result(monkeypatch, success):
    context = SimpleNamespace(_ensure_nginx=Mock())
    request = SimpleNamespace(method="POST", wants_json=True, api_context=context)
    handler = SimpleNamespace(request=request)
    monkeypatch.setattr(api.utils_nginx, "nginx_flush_cache", Mock(return_value=(
        success, SimpleNamespace(id=1), {"errors": [] if success else ["https://two"]},
    )))
    result = api.ViewAdminApi_Nginx.cache_flush(handler)
    assert result["result"] == ("success" if success else "error")


@pytest.mark.parametrize("operation", ["flush", "status", "expire"])
def test_empty_server_pool_is_not_reported_as_success(nginx, operation):
    request, _, _ = nginx
    request.api_context.application_settings["nginx.servers_pool"] = []
    functions = {
        "flush": utils_nginx.nginx_flush_cache,
        "status": utils_nginx.nginx_status,
        "expire": utils_nginx.nginx_expire_cache,
    }
    args = [request, request.api_context]
    if operation == "expire":
        args.append([SimpleNamespace(id=1, domain_name="example.com")])
    with pytest.raises(utils_nginx.errors.InvalidRequest, match="No nginx servers"):
        functions[operation](*args)


def test_status_rejects_non_object_json(nginx):
    request, session, _ = nginx
    session.get.side_effect = [reply([]), reply({"workers": 4})]
    result = utils_nginx.nginx_status(request, request.api_context)
    assert result["errors"] == ["https://one"]
    assert result["success"] == ["https://two"]


@pytest.mark.parametrize("success", [False, True])
@pytest.mark.parametrize("certificate_view", [False, True])
def test_domain_and_certificate_expiry_views_report_actual_result(monkeypatch, success, certificate_view):
    from peter_sslers.web.views_admin import domain
    from peter_sslers.web.views_admin import x509_certificate

    context = SimpleNamespace(_ensure_nginx=Mock())
    request = SimpleNamespace(method="POST", wants_json=True, api_context=context)
    focus = SimpleNamespace(unique_fqdn_set=SimpleNamespace(to_domains=[]))
    handler = SimpleNamespace(request=request, _focus=Mock(return_value=focus))
    monkeypatch.setattr(utils_nginx, "nginx_expire_cache", Mock(return_value=(success, SimpleNamespace(id=1))))
    if certificate_view:
        result = x509_certificate.View_Focus_Manipulate.nginx_expire(handler)
    else:
        result = domain.View_Focus.nginx_cache_expire(handler)
    assert result["result"] == ("success" if success else "error")
