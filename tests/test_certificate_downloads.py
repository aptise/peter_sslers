from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests

from peter_sslers.lib.db import actions


@pytest.fixture
def download(monkeypatch):
    response = Mock(status_code=200, content=b"certificate", headers={})
    get = Mock()
    get.return_value.__enter__ = Mock(return_value=response)
    get.return_value.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(actions.requests, "get", get)
    return get, response


def test_download_preserves_bytes_and_verifies_tls_by_default(download):
    get, response = download
    assert actions._download_certificate("https://ca.example/issuer") == (
        b"certificate", response.headers
    )
    get.assert_called_once_with(
        "https://ca.example/issuer", verify=True, timeout=(3.05, 10)
    )
    get.return_value.__exit__.assert_called_once()


@pytest.mark.parametrize("status", [301, 404, 500])
def test_download_rejects_unsuccessful_status_and_closes_response(download, status):
    get, response = download
    response.status_code = status
    with pytest.raises(ValueError, match="Could not load certificate"):
        actions._download_certificate("https://ca.example/issuer")
    get.return_value.__exit__.assert_called_once()


def test_download_propagates_timeout(download):
    get, _ = download
    get.side_effect = requests.Timeout("read timed out")
    with pytest.raises(requests.Timeout):
        actions._download_certificate("https://ca.example/issuer")


def test_pebble_alternate_download_preserves_ca_verification(monkeypatch):
    server = SimpleNamespace(local_ca_bundle=Mock(return_value="test-ca.pem"))
    session = Mock()
    session.query.return_value.filter.return_value.first.return_value = server
    fetch = Mock(side_effect=[
        (b"first root", {"Link": '<https://localhost/alternate>;rel="alternate"'}),
        (b"alternate root", {}),
    ])
    monkeypatch.setattr(actions, "_download_certificate", fetch)
    create = Mock(return_value=(object(), True))
    monkeypatch.setattr(
        actions.getcreate, "getcreate__X509CertificateTrusted__by_pem_text", create
    )
    context = SimpleNamespace(dbSession=session)
    assert actions.refresh_pebble_ca_certs(context) is True
    assert [call.args[1] for call in create.call_args_list] == [
        "first root", "alternate root"
    ]
    assert fetch.call_count == 2
    for call in fetch.call_args_list:
        assert call.kwargs["verify"] == "test-ca.pem"
    server.local_ca_bundle.assert_called_with(context, force_refresh=True)
