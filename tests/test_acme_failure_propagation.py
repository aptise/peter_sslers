from __future__ import annotations

from typing import TYPE_CHECKING


from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock

import pytest
from cert_utils.model import AccountKeyData
from requests.structures import CaseInsensitiveDict

from peter_sslers.lib.acme_v2 import AuthenticatedUser
from peter_sslers.model.objects import AcmeAccountKey

if TYPE_CHECKING:
    from peter_sslers.lib.context import ApiContext


@pytest.mark.parametrize("operation", ["deactivate", "key_change"])
def test_account_operations_propagate_transport_errors(
    operation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = object.__new__(AuthenticatedUser)
    user.acme_directory = {"keyChange": "https://ca.example/key-change"}
    user._api_account_headers = CaseInsensitiveDict(
        {"Location": "https://ca.example/account/1"}
    )
    setattr(
        user, "_send_signed_request", Mock(side_effect=RuntimeError("transport failed"))
    )
    if operation == "deactivate":
        with pytest.raises(RuntimeError, match="transport failed"):
            user.deactivate(
                cast("ApiContext", SimpleNamespace()), transaction_commit=True
            )
    else:
        user.accountKeyData = cast(AccountKeyData, SimpleNamespace(jwk={}))
        monkeypatch.setattr("peter_sslers.lib.acme_v2.AccountKeyData", Mock())
        monkeypatch.setattr(
            "peter_sslers.lib.acme_v2.sign_payload_inner", Mock(return_value={})
        )
        with pytest.raises(RuntimeError, match="transport failed"):
            user.key_change(
                cast("ApiContext", SimpleNamespace()),
                cast(AcmeAccountKey, SimpleNamespace(key_pem="test")),
                transaction_commit=True,
            )
