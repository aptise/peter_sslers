"""Local IP identities, stable sets, certificate imports and migrations."""

from __future__ import annotations

import datetime
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Generator
from typing import TYPE_CHECKING

from alembic.migration import MigrationContext
from alembic.operations import Operations
import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session
import tldextract

from peter_sslers.lib import errors
from peter_sslers.lib.db import get
from peter_sslers.lib.db import getcreate
from peter_sslers.lib.db import validate
from peter_sslers.lib.identifiers import canonical_name
from peter_sslers.lib.identifiers import names_from_identifiers
from peter_sslers.model import objects as models

if TYPE_CHECKING:
    from peter_sslers.lib.context import ApiContext

NOW = datetime.datetime(2026, 10, 30, tzinfo=datetime.timezone.utc)


@pytest.fixture
def identity_context(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[ApiContext, None, None]:
    """Use real isolated tables and offline public-suffix data."""
    from peter_sslers.lib.context import ApiContext

    monkeypatch.setattr(
        tldextract,
        "extract",
        tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None),
    )
    engine = sa.create_engine("sqlite://")
    for model in (
        models.Domain,
        models.DomainBlocklisted,
        models.OperationsEvent,
        models.OperationsObjectEvent,
        models.UniqueFQDNSet,
        models.UniqueFQDNSet2Domain,
    ):
        model.__table__.create(engine)
    try:
        with Session(engine) as session:
            yield ApiContext(dbSession=session, timestamp=NOW)
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("2001:0DB8:0:0:0:0:0:1", "2001:db8::1"),
        ("10.0.0.1", "10.0.0.1"),
        ("::1", "::1"),
        ("EXAMPLE.com", "example.com"),
        ("fc00::1", "fc00::1"),
    ],
)
def test_normalization_does_not_impose_ca_routing_policy(
    raw: str, expected: str
) -> None:
    assert canonical_name(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "[::1]",
        "fe80::1%eth0",
        "10.0.0.0/8",
        "192.0.2.1:443",
        "192.168.001.1",
        "2001:db8:::1",
    ],
)
def test_non_identity_address_syntax_is_rejected(raw: str) -> None:
    with pytest.raises(ValueError):
        canonical_name(raw)


def test_equivalent_ipv6_spellings_share_domain_and_set_ids(
    identity_context: ApiContext,
) -> None:
    first, new = getcreate.getcreate__UniqueFQDNSet__by_domains(
        identity_context, ["example.com", "10.0.0.1", "2001:0DB8:0:0:0:0:0:1"]
    )
    assert new
    second, new = getcreate.getcreate__UniqueFQDNSet__by_domains(
        identity_context, ["2001:db8::1", "10.0.0.1", "EXAMPLE.COM"]
    )
    assert not new and second.id == first.id
    assert identity_context.dbSession.query(models.Domain).count() == 3
    domain = get.get__Domain__by_name(identity_context, "2001:0db8:0:0::1")
    assert domain is not None and domain.address_type_id == 3
    assert first.dns_names == ["example.com"]
    assert first.ip_addresses == ["10.0.0.1", "2001:db8::1"]
    assert first.as_json["identifiers"] == [
        {"type": "dns", "value": "example.com"},
        {"type": "ip", "value": "10.0.0.1"},
        {"type": "ip", "value": "2001:db8::1"},
    ]


def test_local_models_project_typed_identities_without_renaming_legacy_fields(
    identity_context: ApiContext,
) -> None:
    names, _ = getcreate.getcreate__UniqueFQDNSet__by_domains(
        identity_context, ["10.0.0.1", "example.com"]
    )
    for model in (
        models.AcmeOrder,
        models.RenewalConfiguration,
        models.X509CertificateRequest,
        models.X509Certificate,
        models.UniquelyChallengedFQDNSet,
    ):
        record = model(unique_fqdn_set=names)
        assert record.identifiers == names.identifiers
        assert record.dns_names == ["example.com"]
        assert record.ip_addresses == ["10.0.0.1"]
    assert names.domains_as_list == ["10.0.0.1", "example.com"]


def test_blocklists_use_the_same_canonical_identity(
    identity_context: ApiContext,
) -> None:
    blocked, _ = getcreate.getcreate__DomainBlocklisted__by_domainName(
        identity_context, "2001:0db8:0:0::1"
    )
    assert blocked.domain_name == "2001:db8::1"
    with pytest.raises(errors.AcmeDomainsBlocklisted):
        validate.validate_domain_names(identity_context, ["2001:db8::1"])


def test_dns_san_kind_cannot_be_reinterpreted_as_ip() -> None:
    with pytest.raises(ValueError, match="SAN type"):
        names_from_identifiers([{"type": "dns", "value": "192.0.2.1"}])


def test_dns01_is_not_an_ip_challenge(identity_context: ApiContext) -> None:
    with pytest.raises(errors.InvalidRequest, match="DNS-01"):
        validate.ensure_domains_dns01(identity_context, ["10.0.0.1"])


@pytest.fixture
def migration() -> ModuleType:
    """Load the frozen migration without running application migrations."""
    path = (
        Path(__file__).resolve().parents[1]
        / "alembic/versions/d8b74e3c10a6_ipv6_identities.py"
    )
    spec = importlib.util.spec_from_file_location("ipv6_migration", path)
    assert spec is not None and spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    return migration


def test_ipv6_constraint_migration_preserves_expression_index_and_refuses_lossy_downgrade(
    migration: ModuleType,
) -> None:
    engine = sa.create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TABLE domain (id INTEGER PRIMARY KEY, domain_name TEXT, address_type_id INTEGER,"
                " registered TEXT, suffix TEXT, CONSTRAINT ck_domain__domain_type_check CHECK ("
                + migration.OLD
                + "))"
            )
            connection.exec_driver_sql(
                "CREATE UNIQUE INDEX uidx_domain ON domain (lower(domain_name))"
            )
            connection.exec_driver_sql(
                "INSERT INTO domain VALUES (1,'example.com',1,'example','com'),(2,'10.0.0.1',2,NULL,NULL)"
            )
            with Operations.context(MigrationContext.configure(connection)):
                migration.upgrade()
                connection.exec_driver_sql(
                    "INSERT INTO domain VALUES (3,'2001:db8::1',3,NULL,NULL)"
                )
                with pytest.raises(ValueError, match="IPv6"):
                    migration.downgrade()
                connection.exec_driver_sql("DELETE FROM domain WHERE id=3")
                migration.downgrade()
            assert connection.exec_driver_sql(
                "SELECT id, domain_name FROM domain ORDER BY id"
            ).all() == [(1, "example.com"), (2, "10.0.0.1")]
            assert connection.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE name='uidx_domain'"
            ).first()
            with pytest.raises(sa.exc.IntegrityError):
                connection.exec_driver_sql(
                    "INSERT INTO domain VALUES (4,'EXAMPLE.COM',1,'example','com')"
                )
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "rows",
    [
        [(1, "2001:db8:0::1", 3), (2, "2001:0db8::1", 3)],
        [(1, "192.168.001.1", 2)],
        [(1, "10.0.0.1", 1)],
    ],
)
def test_migration_refuses_ambiguous_or_invalid_data_before_ddl(
    migration: ModuleType, rows: list[tuple[int, str, int]]
) -> None:
    engine = sa.create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TABLE domain (id INTEGER PRIMARY KEY, domain_name TEXT, address_type_id INTEGER,"
                " registered TEXT, suffix TEXT, CONSTRAINT ck_domain__domain_type_check CHECK ("
                + migration.NEW
                + "))"
            )
            for identity, name, kind in rows:
                connection.execute(
                    sa.text(
                        "INSERT INTO domain VALUES (:id,:name,:kind,:registered,:suffix)"
                    ),
                    {
                        "id": identity,
                        "name": name,
                        "kind": kind,
                        "registered": "example" if kind == 1 else None,
                        "suffix": "com" if kind == 1 else None,
                    },
                )
            before = connection.exec_driver_sql(
                "SELECT sql FROM sqlite_master WHERE name='domain'"
            ).scalar_one()
            with Operations.context(MigrationContext.configure(connection)):
                with pytest.raises(ValueError):
                    migration.upgrade()
            assert (
                connection.exec_driver_sql(
                    "SELECT sql FROM sqlite_master WHERE name='domain'"
                ).scalar_one()
                == before
            )
            assert connection.exec_driver_sql(
                "SELECT count(*) FROM domain"
            ).scalar_one() == len(rows)
    finally:
        engine.dispose()


@pytest.mark.parametrize("dns", [False, True])
def test_real_csr_and_certificate_import_keep_private_ip_sans(
    identity_context: ApiContext,
    dns: bool,
) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import ipaddress

    from peter_sslers.lib.db import create
    from peter_sslers.model.meta import metadata

    metadata.create_all(identity_context.dbSession.get_bind())
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Internal CA")])
    san_values: list[x509.GeneralName] = [
        x509.IPAddress(ipaddress.ip_address("10.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("fd00::1")),
    ]
    names = ["10.0.0.1", "fd00::1"]
    if dns:
        san_values.append(x509.DNSName("example.com"))
        names.append("example.com")
    sans = x509.SubjectAlternativeName(san_values)
    csr_pem = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(sans, False)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    private_key, _ = getcreate.getcreate__PrivateKey__by_pem_text(
        identity_context, key_pem, 2, 1
    )
    csr = create.create__X509CertificateRequest(
        identity_context, csr_pem, 1, private_key, names
    )
    cert_pem = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(5)
        .not_valid_before(NOW)
        .not_valid_after(NOW + datetime.timedelta(days=14))
        .add_extension(sans, False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False
        )
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )
    certificate = create.create__X509Certificate(
        identity_context,
        cert_pem,
        names,
        models.X509CertificateTrustChain(id=1),
        certificate_type_id=1,
        dbX509CertificateRequest=csr,
        dbPrivateKey=private_key,
    )
    assert certificate.identifiers == csr.identifiers
    assert certificate.ip_addresses == ["10.0.0.1", "fd00::1"]
    assert certificate.dns_names == (["example.com"] if dns else [])
    assert certificate.unique_fqdn_set_id == csr.unique_fqdn_set_id
