"""Safe acme-dns errors and bounded transport preserve the legacy client API."""

import json
from typing import Dict
from unittest.mock import Mock

from pyacmedns.exceptions import AcmeDnsClientException
import pytest
import requests

from peter_sslers.lib import acmedns

SECRET = "dns-api-key-never-print"
ACCOUNT = {"username": "user", "password": SECRET, "subdomain": "subdomain"}


@pytest.fixture
def post(monkeypatch: pytest.MonkeyPatch) -> Mock:
    post = Mock()
    monkeypatch.setattr(acmedns.requests, "post", post)
    return post


def response(status: int, payload: Dict[str, object]) -> Mock:
    result = Mock(status_code=status)
    result.__enter__ = Mock(return_value=result)
    result.__exit__ = Mock(return_value=False)
    result.iter_content.return_value = [json.dumps(payload).encode()]
    return result


def test_registration_returns_credentials_but_uses_bounded_closed_requests(
    post: Mock,
) -> None:
    result = response(
        201, {**ACCOUNT, "fulldomain": "subdomain.example.com", "allowfrom": []}
    )
    post.return_value = result
    credentials = acmedns.new_client("https://dns.example/api/").register_account(None)
    assert credentials["password"] == SECRET
    assert post.call_args.args[0] == "https://dns.example/api/register"
    assert post.call_args.kwargs["timeout"] == (3.05, 10)
    assert post.call_args.kwargs["allow_redirects"] is False
    result.__exit__.assert_called_once()


@pytest.mark.parametrize("status", [301, 302, 307, 308, 400, 403, 500])
def test_failed_updates_never_embed_credentials_request_or_response(
    post: Mock, status: int
) -> None:
    result = response(status, {"detail": SECRET})
    post.return_value = result
    with pytest.raises(AcmeDnsClientException) as error:
        acmedns.new_client("https://dns.example").update_txt_record(
            ACCOUNT, "challenge-secret"
        )
    assert SECRET not in str(error.value)
    assert "challenge-secret" not in str(error.value)
    assert str(status) in str(error.value)
    assert post.call_args.kwargs["headers"]["X-Api-Key"] == SECRET
    assert post.call_args.kwargs["allow_redirects"] is False
    result.__exit__.assert_called_once()


def test_transport_errors_do_not_expose_upstream_exception_text(post: Mock) -> None:
    post.side_effect = requests.Timeout(SECRET)
    with pytest.raises(AcmeDnsClientException) as error:
        acmedns.new_client("https://dns.example").update_txt_record(
            ACCOUNT, "challenge"
        )
    assert SECRET not in str(error.value)
    assert "Timeout" in str(error.value)
    assert error.value.__suppress_context__


def test_registration_response_size_and_shape_are_validated(post: Mock) -> None:
    result = response(201, {})
    post.return_value = result
    with pytest.raises(AcmeDnsClientException, match="required credential fields"):
        acmedns.new_client("https://dns.example").register_account(None)
    result.iter_content.return_value = [b"x" * 65537]
    with pytest.raises(AcmeDnsClientException, match="size limit"):
        acmedns.new_client("https://dns.example").register_account(None)


@pytest.mark.parametrize(
    "url",
    [
        "https://user:secret@dns.example",
        "https://dns.example?token=secret",
        "file:///tmp/api",
        "https://dns.example/#secret",
    ],
)
def test_api_urls_cannot_hide_credentials_or_tokens(url: str) -> None:
    with pytest.raises(ValueError):
        acmedns.new_client(url)
