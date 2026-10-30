from email.message import Message
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.error import HTTPError, URLError

import pytest

from peter_sslers.lib import acme_v2, errors


def headers(**values):
    result = Message()
    for key, value in values.items():
        result[key.replace("_", "-")] = value
    return result


def test_success_response_is_closed(monkeypatch):
    response = SimpleNamespace(read=Mock(return_value=b'{"status":"pending"}'), getcode=Mock(return_value=200), headers=headers(Replay_Nonce="next"), close=Mock())
    monkeypatch.setattr(acme_v2, "urlopen", Mock(return_value=response))
    code, payload, received_headers = acme_v2.url_request(None, "https://ca.example/order")
    assert code == 200 and payload == {"status": "pending"}
    assert received_headers.get("Replay-Nonce") == "next"
    response.close.assert_called_once_with()


@pytest.mark.parametrize("status,body", [(400,b'{"detail":"missing type"}'), (429,b'{"type":"rateLimited"}')])
def test_http_error_preserves_headers_and_closes_body(monkeypatch, status, body):
    stream = BytesIO(body)
    error = HTTPError("https://ca.example/order", status, "error", headers(Retry_After="60"), stream)
    monkeypatch.setattr(acme_v2, "urlopen", Mock(side_effect=error))
    with pytest.raises(errors.AcmeServerError) as caught:
        acme_v2.url_request(None, "https://ca.example/order")
    assert caught.value.args[0] == status
    assert caught.value.args[3].get("Retry-After") == "60"
    assert stream.closed


def test_bad_nonce_has_typed_error_and_replacement_header(monkeypatch):
    error = HTTPError("https://ca.example/order", 400, "error", headers(Replay_Nonce="fresh"), BytesIO(b'{"type":"urn:ietf:params:acme:error:badNonce"}'))
    monkeypatch.setattr(acme_v2, "urlopen", Mock(side_effect=error))
    with pytest.raises(errors.AcmeBadNonce) as caught:
        acme_v2.url_request(None, "https://ca.example/order")
    assert caught.value.args[3].get("Replay-Nonce") == "fresh"


def test_network_failure_is_a_communication_error(monkeypatch):
    monkeypatch.setattr(acme_v2, "urlopen", Mock(side_effect=URLError("unreachable")))
    with pytest.raises(errors.AcmeCommunicationError):
        acme_v2.url_request(None, "https://ca.example/order")


@pytest.fixture
def user(monkeypatch):
    user = object.__new__(acme_v2.AuthenticatedUser)
    user.ctx = None
    user._next_nonce = "initial"
    user.acmeAccount = SimpleNamespace(account_url="https://ca.example/account", acme_server=None)
    user.accountKeyData = object()
    user.acme_directory = {"newNonce": "https://ca.example/nonce"}
    monkeypatch.setattr(acme_v2, "sign_payload", Mock(return_value="signed"))
    return user


def bad_nonce(nonce):
    return errors.AcmeBadNonce(400, "https://ca.example/order", {"type": "badNonce"}, headers(Replay_Nonce=nonce))


def test_bad_nonce_retry_uses_server_replacement_and_resigns(user, monkeypatch):
    send = Mock(side_effect=[bad_nonce("replacement"), (200, {}, headers(Replay_Nonce="next"))])
    monkeypatch.setattr(acme_v2, "url_request", send)
    user._send_signed_request("order", "https://ca.example/order", payload={"test": 1})
    assert [call.kwargs["nonce"] for call in acme_v2.sign_payload.call_args_list] == ["initial", "replacement"]
    assert all(call.args[1] == "https://ca.example/order" for call in send.call_args_list)
    assert user._next_nonce == "next"


@pytest.mark.parametrize("failure", [errors.AcmeCommunicationError("lost connection"), IndexError("unrelated bug")])
def test_failed_request_does_not_reuse_nonce_or_retry_unrelated_errors(user, monkeypatch, failure):
    send = Mock(side_effect=failure)
    monkeypatch.setattr(acme_v2, "url_request", send)
    with pytest.raises(type(failure)):
        user._send_signed_request("order", "https://ca.example/order")
    assert user._next_nonce is None
    assert send.call_count == 1


@pytest.mark.parametrize("replacement", ["", "initial"])
def test_bad_nonce_without_fresh_replacement_is_not_retried(user, monkeypatch, replacement):
    send = Mock(side_effect=bad_nonce(replacement))
    monkeypatch.setattr(acme_v2, "url_request", send)
    with pytest.raises(errors.AcmeCommunicationError, match="fresh Replay-Nonce"):
        user._send_signed_request("order", "https://ca.example/order")
    assert send.call_count == 1
    assert user._next_nonce is None


def test_missing_new_nonce_has_clear_error(user, monkeypatch):
    user._next_nonce = None
    monkeypatch.setattr(acme_v2, "url_request", Mock(return_value=(204, "", headers())))
    with pytest.raises(errors.AcmeCommunicationError, match="missing Replay-Nonce"):
        user._send_signed_request("order", "https://ca.example/order")
    acme_v2.sign_payload.assert_not_called()


def test_bad_nonce_retry_limit_is_bounded(user, monkeypatch):
    monkeypatch.setattr(acme_v2, "MAX_DEPTH", 2)
    send = Mock(side_effect=[bad_nonce("one"), bad_nonce("two"), bad_nonce("three")])
    monkeypatch.setattr(acme_v2, "url_request", send)
    with pytest.raises(ValueError, match="MAX_DEPTH"):
        user._send_signed_request("order", "https://ca.example/order")
    assert send.call_count == 3


@pytest.mark.parametrize("status", [200, 400])
def test_unreadable_response_is_closed_and_reported_as_communication_error(monkeypatch, status):
    if status == 400:
        stream = BytesIO(b"\xff")
        response = HTTPError("https://ca.example/order", 400, "error", headers(), stream)
        monkeypatch.setattr(acme_v2, "urlopen", Mock(side_effect=response))
    else:
        stream = SimpleNamespace(read=Mock(side_effect=OSError("broken stream")), getcode=Mock(return_value=200), headers=headers(), close=Mock())
        monkeypatch.setattr(acme_v2, "urlopen", Mock(return_value=stream))
    with pytest.raises(errors.AcmeCommunicationError):
        acme_v2.url_request(None, "https://ca.example/order")
    if status == 400:
        assert stream.closed
    else:
        stream.close.assert_called_once()


def test_404_keeps_existing_exception_contract_and_closes_body(monkeypatch):
    stream = BytesIO(b'{"type":"notFound"}')
    monkeypatch.setattr(acme_v2, "urlopen", Mock(side_effect=HTTPError("https://ca.example/order", 404, "error", headers(), stream)))
    with pytest.raises(errors.AcmeServer404) as caught:
        acme_v2.url_request(None, "https://ca.example/order")
    assert caught.value.args == (404, {"type": "notFound"})
    assert stream.closed


@pytest.mark.parametrize("as_message", [False, True])
def test_rate_limit_persistence_serializes_real_http_headers(as_message):
    import json
    from peter_sslers.lib.db.create import create__RateLimited

    received = headers(Retry_After="60", Replay_Nonce="fresh") if as_message else {"Retry-After": "60", "Replay-Nonce": "fresh"}
    context = SimpleNamespace(dbSession=Mock())
    record = create__RateLimited(
        context, SimpleNamespace(id=1),
        server_response_body={"type": "rateLimited"}, server_response_headers=received,
    )
    assert json.loads(record.server_response_headers) == {"Retry-After": "60", "Replay-Nonce": "fresh"}
    assert json.loads(record.server_response_body) == {"type": "rateLimited"}
    context.dbSession.add.assert_called_once_with(record)
