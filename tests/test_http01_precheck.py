from unittest.mock import Mock

import pytest
import requests

from peter_sslers.lib.acme_v2 import _check_http01_response


@pytest.fixture
def response(monkeypatch):
    response = Mock()
    response.content = b"token.thumbprint\n"
    get = Mock()
    get.return_value.__enter__ = Mock(return_value=response)
    get.return_value.__exit__ = Mock(return_value=False)
    monkeypatch.setattr("peter_sslers.lib.acme_v2.requests.get", get)
    return response, get


def test_http01_accepts_matching_content_with_bounded_waits(response):
    reply, get = response
    _check_http01_response("http://example.com/challenge", "token.thumbprint")
    get.assert_called_once_with("http://example.com/challenge", timeout=(3.05, 10))
    reply.raise_for_status.assert_called_once_with()
    get.return_value.__exit__.assert_called_once()


@pytest.mark.parametrize("body", [b"wrong", b"", b"\xff"])
def test_http01_rejects_invalid_content(response, body):
    reply, _ = response
    reply.content = body
    with pytest.raises(ValueError):
        _check_http01_response("http://example.com/challenge", "token.thumbprint")


def test_http01_rejects_error_status_even_with_matching_content(response):
    reply, _ = response
    reply.raise_for_status.side_effect = requests.HTTPError("503")
    with pytest.raises(requests.HTTPError):
        _check_http01_response("http://example.com/challenge", "token.thumbprint")


def test_http01_propagates_timeout(response):
    _, get = response
    get.side_effect = requests.Timeout("read timed out")
    with pytest.raises(requests.Timeout):
        _check_http01_response("http://example.com/challenge", "token.thumbprint")
