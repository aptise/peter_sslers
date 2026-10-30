from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from peter_sslers.lib.acme_v2 import AuthenticatedUser


@pytest.mark.parametrize("operation", ["deactivate", "key_change"])
def test_account_operations_propagate_transport_errors(operation, monkeypatch):
    user = object.__new__(AuthenticatedUser)
    user.acme_directory = {"keyChange": "https://ca.example/key-change"}
    user._api_account_headers = {"Location": "https://ca.example/account/1"}
    user._send_signed_request = Mock(side_effect=RuntimeError("transport failed"))
    if operation == "deactivate":
        with pytest.raises(RuntimeError, match="transport failed"):
            user.deactivate(SimpleNamespace(), transaction_commit=True)
    else:
        user.accountKeyData = SimpleNamespace(jwk={})
        monkeypatch.setattr("peter_sslers.lib.acme_v2.AccountKeyData", Mock())
        monkeypatch.setattr("peter_sslers.lib.acme_v2.sign_payload_inner", Mock(return_value={}))
        with pytest.raises(RuntimeError, match="transport failed"):
            user.key_change(
                SimpleNamespace(), SimpleNamespace(key_pem="test"), transaction_commit=True
            )
