from __future__ import annotations

from typing import TYPE_CHECKING


import datetime
from types import SimpleNamespace
from typing import Generator
from typing import Optional
from typing import Set

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session
from typing_extensions import Self

from peter_sslers.lib.db import get
from peter_sslers.model.objects import Domain
from peter_sslers.model.objects import X509Certificate
from peter_sslers.model.objects import objects

if TYPE_CHECKING:
    from peter_sslers.lib.context import ApiContext


UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 10, 29, 12, tzinfo=UTC)


def test_expiry_properties_follow_clock_on_same_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Clock(datetime.datetime):
        current = NOW

        @classmethod
        def now(cls, tz: Optional[datetime.tzinfo] = None) -> Self:
            return cls.fromtimestamp(cls.current.timestamp(), tz=tz)

    monkeypatch.setattr(
        objects, "datetime", SimpleNamespace(datetime=Clock, timezone=datetime.timezone)
    )
    certificate = X509Certificate(timestamp_not_after=NOW + datetime.timedelta(days=5))
    assert certificate.days_to_expiry == 5
    assert certificate.days_to_expiry__label == "warning"
    assert certificate.is_expired is False
    Clock.current = NOW + datetime.timedelta(days=6)
    assert certificate.days_to_expiry == -1
    assert certificate.days_to_expiry__label == "danger"
    assert certificate.is_expired is True
    certificate.timestamp_not_after = NOW + datetime.timedelta(days=20)
    assert certificate.is_expired is False
    assert certificate.days_to_expiry__label == "success"


@pytest.fixture
def context() -> Generator[ApiContext, None, None]:
    from peter_sslers.lib.context import ApiContext

    engine = sa.create_engine("sqlite://")
    Domain.__table__.create(engine)
    X509Certificate.__table__.create(engine)
    with Session(engine) as session:
        for identity, days, active in [
            (1, -1, True),
            (2, 0, True),
            (3, 10, True),
            (4, -2, False),
            (5, -3, True),
        ]:
            session.execute(
                sa.insert(X509Certificate).values(
                    id=identity,
                    timestamp_created=NOW,
                    timestamp_not_before=NOW,
                    timestamp_not_after=NOW + datetime.timedelta(days=days),
                    key_technology_id=4,
                    cert_pem=str(identity),
                    cert_pem_md5=str(identity),
                    spki_sha256="key",
                    fingerprint_sha1="fingerprint",
                    cert_subject="subject",
                    cert_issuer="issuer",
                    duration_hours=24,
                    is_active=active,
                    unique_fqdn_set_id=1,
                    cert_serial=str(identity),
                    private_key_id=1,
                    certificate_type_id=1,
                    operations_event_id__created=1,
                )
            )
            session.execute(
                sa.insert(Domain).values(
                    id=identity,
                    domain_name=f"{identity}.example.com",
                    address_type_id=1,
                    registered="example",
                    suffix="com",
                    timestamp_created=NOW,
                    operations_event_id__created=1,
                    x509_certificate_id__latest_single=identity,
                )
            )
        session.commit()
        yield ApiContext(dbSession=session, timestamp=NOW)
    engine.dispose()


@pytest.mark.parametrize(
    "days, expected", [(0, {1, 2, 5}), (-1, {1, 5}), (1, {1, 2, 5}), (20, {1, 2, 3, 5})]
)
def test_expiry_filter_handles_zero_and_excludes_inactive(
    context: ApiContext, days: int, expected: Set[int]
) -> None:
    assert get.get__Domain__count(context, days_to_expiry=days) == len(expected)
    result = get.get__Domain__paginated(context, days_to_expiry=days)
    assert {domain.id for domain in result} == expected


def test_active_domain_listing_excludes_inactive_certificate_pointers(
    context: ApiContext,
) -> None:
    assert {
        d.id for d in get.get__Domain__paginated(context, active_certs_only=True)
    } == {1, 2, 3, 5}
    assert {d.id for d in get.get__Domain__paginated(context)} == {1, 2, 3, 4, 5}


def test_expiry_pagination_orders_domains_with_only_one_certificate(
    context: ApiContext,
) -> None:
    result = get.get__Domain__paginated(context, days_to_expiry=0, limit=2)
    assert [domain.id for domain in result] == [5, 1]


@pytest.mark.parametrize("id_only", [False, True])
def test_domain_config_omits_inactive_certificate_pointers(
    monkeypatch: pytest.MonkeyPatch, id_only: bool
) -> None:
    monkeypatch.setattr(
        X509Certificate, "config_payload", property(lambda self: {"id": str(self.id)})
    )
    monkeypatch.setattr(
        X509Certificate,
        "config_payload_idonly",
        property(lambda self: {"id": str(self.id)}),
    )
    domain = Domain(id=1, domain_name="example.com")
    domain.x509_certificate_id__latest_multi = 2
    domain.x509_certificate__latest_multi = X509Certificate(id=2, is_active=False)
    domain.x509_certificate_id__latest_single = 3
    domain.x509_certificate__latest_single = X509Certificate(id=3, is_active=True)
    payload = domain.as_json_config(id_only=id_only)
    assert payload["x509_certificate__latest_multi"] is None
    assert payload["x509_certificate__latest_single"] == {"id": "3"}
