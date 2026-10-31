"""IP issuance policy and typed ACME requests without public network access."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from typing import TYPE_CHECKING
from unittest.mock import Mock

from alembic.migration import MigrationContext
from alembic.operations import Operations
import pytest
import sqlalchemy as sa

from peter_sslers.lib import acme_v2
from peter_sslers.lib import errors
from peter_sslers.lib.identifiers import http_host
from peter_sslers.lib.identifiers import identifier
from peter_sslers.lib.identifiers import name_from_http_host
from peter_sslers.lib.identifiers import validate_ip_policy
from peter_sslers.model.objects import AcmeServer
from . import test_ordering_resilience

if TYPE_CHECKING:
    from peter_sslers.lib.context import ApiContext
    from peter_sslers.model.objects import AcmeAuthorization
    from peter_sslers.model.objects import AcmeChallenge
    from peter_sslers.model.objects import UniqueFQDNSet


ordering_user = test_ordering_resilience.ordering_user


@pytest.mark.parametrize(
    "name",
    [
        "10.0.0.1",
        "192.168.1.2",
        "127.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "192.0.2.1",
        "198.18.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "0.0.0.0",
        "::",
        "::1",
        "fd00::1",
        "fe80::1",
        "ff02::1",
        "2001:db8::1",
    ],
)
def test_nonpublic_ips_are_rejected_before_transport(
    ordering_user: acme_v2.AuthenticatedUser,
    name: str,
) -> None:
    """Default issuer policy catches private and reserved identities locally."""
    send = Mock()
    setattr(ordering_user, "_send_signed_request", send)
    with pytest.raises(errors.InvalidRequest, match="publicly routable"):
        ordering_user.acme_order_new(
            cast("ApiContext", None),
            [name],
            cast("UniqueFQDNSet", None),
            True,
        )
    send.assert_not_called()
    validate_ip_policy([name], require_public_ip=False)


@pytest.mark.parametrize(
    "names,public",
    [
        (["8.8.8.8"], True),
        (["2001:4860:4860::8888"], True),
        (
            [
                "8.8.8.8",
                "1.1.1.1",
                "2001:4860:4860::8888",
                "2606:4700:4700::1111",
                "example.com",
                "example.org",
            ],
            True,
        ),
        (["10.0.0.1", "fd00::1", "example.com"], False),
    ],
)
def test_order_payload_preserves_identifier_types(
    ordering_user: acme_v2.AuthenticatedUser,
    names: list[str],
    public: bool,
) -> None:
    """The private-CA opt-out affects IP policy, not DNS/IP encoding."""
    ordering_user.acmeAccount.acme_server = AcmeServer(require_public_ip=public)
    send = Mock(
        return_value=(201, {"status": "pending"}, {"Location": "https://ca.example/1"})
    )
    setattr(ordering_user, "_send_signed_request", send)
    ordering_user.acme_order_new(
        cast("ApiContext", SimpleNamespace(application_settings={"log.acme": False})),
        names,
        cast("UniqueFQDNSet", SimpleNamespace(id=1)),
        True,
        profile="custom",
    )
    payload = send.call_args.kwargs["payload"]
    assert payload["identifiers"] == [identifier(name) for name in names]
    assert payload["profile"] == "custom"


@pytest.mark.parametrize(
    "name,host",
    [
        ("2001:0db8::1", "[2001:db8::1]"),
        ("10.0.0.1", "10.0.0.1"),
        ("example.com", "example.com"),
    ],
)
def test_http_challenge_url_host(name: str, host: str) -> None:
    """IPv6 literals are URL authorities, not unbracketed host/port pairs."""
    assert http_host(name) == host


def test_migration_defaults_existing_and_new_servers_to_public() -> None:
    """Opt-out is explicit; migration retains server identity on rollback."""
    path = (
        Path(__file__).resolve().parents[1]
        / "alembic/versions/e4a91d6b208f_acme_ip_policy.py"
    )
    spec = importlib.util.spec_from_file_location("ip_policy_migration", path)
    assert spec is not None and spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = sa.create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TABLE acme_server (id INTEGER PRIMARY KEY)"
            )
            connection.exec_driver_sql("INSERT INTO acme_server (id) VALUES (1)")
            with Operations.context(MigrationContext.configure(connection)):
                migration.upgrade()
                connection.exec_driver_sql("INSERT INTO acme_server (id) VALUES (2)")
                assert connection.exec_driver_sql(
                    "SELECT require_public_ip FROM acme_server"
                ).all() == [(1,), (1,)]
                connection.exec_driver_sql(
                    "UPDATE acme_server SET require_public_ip=0 WHERE id=1"
                )
                migration.downgrade()
            assert connection.exec_driver_sql("SELECT id FROM acme_server").all() == [
                (1,),
                (2,),
            ]
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "host,name",
    [
        ("[2001:0db8::1]:5002", "2001:db8::1"),
        ("[::1]", "::1"),
        ("10.0.0.1:5002", "10.0.0.1"),
        ("Example.COM:80", "example.com"),
    ],
)
def test_incoming_http_challenge_identity(host: str, name: str) -> None:
    """HTTP Host parsing preserves IPv6 for challenge lookup."""
    assert name_from_http_host(host) == name


@pytest.mark.parametrize("name", ["10.0.0.1", "2001:db8::1"])
def test_ip_dns01_prepare_and_manual_trigger_are_blocked(
    ordering_user: acme_v2.AuthenticatedUser,
    name: str,
) -> None:
    """A private issuer opt-out never makes DNS-01 valid for an IP."""
    domain = SimpleNamespace(domain_name=name)
    authorization = SimpleNamespace(id=1, domain=domain)
    challenge = SimpleNamespace(
        id=1,
        acme_challenge_type="dns-01",
        domain=domain,
        acme_authorization=authorization,
        challenge_url="https://ca.example/challenge",
    )
    send = Mock()
    setattr(ordering_user, "_send_signed_request", send)
    with pytest.raises(errors.InvalidRequest, match="DNS-01"):
        ordering_user.prepare_acme_challenge(
            cast("ApiContext", None),
            cast("AcmeAuthorization", authorization),
            cast("AcmeChallenge", challenge),
            transaction_commit=True,
        )
    with pytest.raises(errors.InvalidRequest, match="DNS-01"):
        ordering_user.acme_challenge_trigger(
            cast("ApiContext", None),
            cast("AcmeChallenge", challenge),
            update_AcmeAuthorization_status=Mock(),
            update_AcmeChallenge_status=Mock(),
            transaction_commit=True,
        )
    send.assert_not_called()
