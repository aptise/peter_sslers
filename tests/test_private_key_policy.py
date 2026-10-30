"""Key reuse must follow ownership, algorithm and lifetime policy at service level."""

from __future__ import annotations

import datetime
from typing import Generator
from typing import Optional
from typing import TYPE_CHECKING
from unittest.mock import Mock

import cert_utils
import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from peter_sslers.lib import errors
from peter_sslers.lib.db import actions_acme
from peter_sslers.lib.db import get
from peter_sslers.lib.db import getcreate
from peter_sslers.lib.db.validate import validate_private_key_for_order
from peter_sslers.model import utils as model_utils
from peter_sslers.model.objects import AcmeAccount
from peter_sslers.model.objects import AcmeOrder
from peter_sslers.model.objects import PrivateKey
from peter_sslers.model.objects import RenewalConfiguration
from peter_sslers.model.objects import X509Certificate
from peter_sslers.model.objects import X509CertificateRequest
from .test_routine_recovery import add_order

if TYPE_CHECKING:
    from peter_sslers.lib.context import ApiContext

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 10, 30, 12, tzinfo=UTC)


@pytest.fixture
def key_context() -> Generator[ApiContext, None, None]:
    from peter_sslers.lib.context import ApiContext

    engine = sa.create_engine("sqlite://")
    for model in (PrivateKey, AcmeOrder, X509Certificate):
        model.__table__.create(engine)
    with Session(engine) as session:
        yield ApiContext(dbSession=session, timestamp=NOW)
    engine.dispose()


def key(
    ctx: ApiContext,
    identity: int = 1,
    *,
    kind: str = "standard",
    owner: Optional[int] = 1,
    technology: int = 4,
    created: datetime.datetime = NOW,
    active: bool = True,
    compromised: bool = False,
) -> PrivateKey:
    ctx.dbSession.execute(
        sa.insert(PrivateKey).values(
            id=identity,
            timestamp_created=created,
            key_technology_id=technology,
            key_pem="not-a-real-key",
            key_pem_md5=str(identity),
            spki_sha256=str(identity),
            private_key_type_id=model_utils.PrivateKey_Type.from_string(kind),
            private_key_source_id=1,
            operations_event_id__created=1,
            acme_account_id__owner=owner,
            is_active=active,
            is_compromised=compromised,
        )
    )
    ctx.dbSession.commit()
    result = ctx.dbSession.get(PrivateKey, identity)
    assert result is not None
    return result


@pytest.mark.parametrize("active, compromised", [(False, False), (True, True)])
def test_unusable_keys_are_rejected(
    key_context: ApiContext, active: bool, compromised: bool
) -> None:
    material = key(key_context, active=active, compromised=compromised)
    with pytest.raises(errors.InvalidRequest, match="inactive or compromised"):
        validate_private_key_for_order(key_context, material, 1)


@pytest.mark.parametrize(
    "kind",
    [
        "standard",
        "account_daily",
        "account_weekly",
        "single_use",
        "single_use__reuse_1_year",
    ],
)
def test_account_ownership_is_enforced_for_every_key_kind(
    key_context: ApiContext, kind: str
) -> None:
    material = key(key_context, kind=kind, owner=2)
    with pytest.raises(errors.InvalidRequest, match="different ACME account"):
        validate_private_key_for_order(key_context, material, 1)


@pytest.mark.parametrize("kind", ["account_daily", "account_weekly"])
def test_account_scoped_keys_cannot_have_no_owner(
    key_context: ApiContext, kind: str
) -> None:
    material = key(key_context, kind=kind, owner=None)
    with pytest.raises(errors.InvalidRequest, match="matching owner"):
        validate_private_key_for_order(key_context, material, 1)


def test_single_use_reservation_checks_database_not_cached_counters(
    key_context: ApiContext,
) -> None:
    material = key(key_context, kind="single_use")
    add_order(key_context, 1)
    assert material.count_x509_certificates == 0
    with pytest.raises(errors.InvalidRequest, match="reserved"):
        validate_private_key_for_order(key_context, material, 1)
    order = key_context.dbSession.get(AcmeOrder, 1)
    assert order is not None
    validate_private_key_for_order(key_context, material, 1, order=order)


def test_single_use_keys_can_retry_failed_unissued_work(
    key_context: ApiContext,
) -> None:
    material = key(key_context, kind="single_use")
    add_order(key_context, 1, status="invalid")
    validate_private_key_for_order(key_context, material, 1)


def test_issued_single_use_key_is_rejected_even_when_counters_are_stale(
    key_context: ApiContext,
) -> None:
    material = key(key_context, kind="single_use")
    # Only fields consumed by the policy query are needed for the certificate.
    key_context.dbSession.execute(
        sa.insert(X509Certificate).values(
            id=1,
            timestamp_created=NOW,
            timestamp_not_before=NOW,
            timestamp_not_after=NOW + datetime.timedelta(days=1),
            duration_hours=24,
            key_technology_id=4,
            cert_pem="certificate",
            cert_pem_md5="one",
            spki_sha256="one",
            fingerprint_sha1="one",
            cert_subject="subject",
            cert_issuer="issuer",
            is_active=False,
            unique_fqdn_set_id=1,
            cert_serial="1",
            private_key_id=1,
            certificate_type_id=1,
            operations_event_id__created=1,
        )
    )
    key_context.dbSession.commit()
    with pytest.raises(errors.InvalidRequest, match="already used"):
        validate_private_key_for_order(key_context, material, 1)


@pytest.mark.parametrize("age", [365, 366, -1])
def test_yearly_reuse_has_a_strict_nonfuture_one_year_window(
    key_context: ApiContext, age: int
) -> None:
    material = key(
        key_context,
        kind="single_use__reuse_1_year",
        created=NOW - datetime.timedelta(days=age),
    )
    order = AcmeOrder(id=10, renewal_configuration_id=1)
    with pytest.raises(errors.InvalidRequest, match="reuse period"):
        validate_private_key_for_order(
            key_context, material, 1, order=order, allow_yearly_reuse=True
        )


def test_yearly_reuse_is_confined_to_the_original_configuration(
    key_context: ApiContext,
) -> None:
    material = key(key_context, kind="single_use__reuse_1_year")
    add_order(key_context, 1, status="valid", configuration_id=1)
    validate_private_key_for_order(
        key_context,
        material,
        1,
        order=AcmeOrder(id=2, renewal_configuration_id=1),
        allow_yearly_reuse=True,
    )
    with pytest.raises(errors.InvalidRequest, match="another renewal configuration"):
        validate_private_key_for_order(
            key_context,
            material,
            1,
            order=AcmeOrder(id=2, renewal_configuration_id=2),
            allow_yearly_reuse=True,
        )
    with pytest.raises(errors.InvalidRequest, match="only for renewals"):
        validate_private_key_for_order(key_context, material, 1)


@pytest.mark.parametrize("weekly", [False, True])
def test_calendar_lookup_enforces_algorithm_owner_and_usable_state(
    key_context: ApiContext, weekly: bool
) -> None:
    kind = "account_weekly" if weekly else "account_daily"
    selected = key(key_context, 1, kind=kind)
    key(key_context, 2, kind=kind, technology=1)
    key(key_context, 3, kind=kind, owner=2)
    key(key_context, 4, kind=kind, active=False)
    key(key_context, 5, kind=kind, compromised=True)
    key(key_context, 6, kind=kind, created=NOW + datetime.timedelta(seconds=1))
    query = (
        get.get__PrivateKey_CurrentWeek_AcmeAccount
        if weekly
        else get.get__PrivateKey_CurrentDay_AcmeAccount
    )
    assert query(key_context, 1, key_technology_id=4) is selected


@pytest.mark.parametrize("weekly", [False, True])
def test_global_lookup_excludes_account_owned_keys_and_honors_algorithm(
    key_context: ApiContext, weekly: bool
) -> None:
    kind = "global_weekly" if weekly else "global_daily"
    selected = key(key_context, 1, kind=kind, owner=None, technology=4)
    key(key_context, 2, kind=kind, owner=1, technology=4)
    key(key_context, 3, kind=kind, owner=None, technology=1)
    query = (
        get.get__PrivateKey_CurrentWeek_Global
        if weekly
        else get.get__PrivateKey_CurrentDay_Global
    )
    assert query(key_context, key_technology_id=4) is selected


def test_weekly_selection_crosses_calendar_year_at_iso_week_boundary(
    key_context: ApiContext,
) -> None:
    key_context.timestamp = datetime.datetime(2027, 1, 1, 12, tzinfo=UTC)
    selected = key(
        key_context,
        1,
        kind="account_weekly",
        created=datetime.datetime(2026, 12, 31, 12, tzinfo=UTC),
    )
    key(
        key_context,
        2,
        kind="account_weekly",
        created=datetime.datetime(2026, 12, 27, 12, tzinfo=UTC),
    )
    assert get.get__PrivateKey_CurrentWeek_AcmeAccount(key_context, 1, 4) is selected


def test_daily_selection_uses_utc_calendar_day(key_context: ApiContext) -> None:
    key_context.timestamp = datetime.datetime(
        2026, 10, 30, 1, tzinfo=datetime.timezone(datetime.timedelta(hours=2))
    )
    selected = key(
        key_context,
        1,
        kind="account_daily",
        created=datetime.datetime(2026, 10, 29, 22, tzinfo=UTC),
    )
    assert get.get__PrivateKey_CurrentDay_AcmeAccount(key_context, 1, 4) is selected


@pytest.mark.parametrize(
    "cycle",
    [
        "account_daily",
        "account_weekly",
        "global_daily",
        "global_weekly",
        "single_use",
        "single_use__reuse_1_year",
    ],
)
def test_generation_honors_requested_technology_for_every_cycle(
    key_context: ApiContext,
    monkeypatch: pytest.MonkeyPatch,
    cycle: str,
) -> None:
    account = AcmeAccount(
        id=1,
        order_default_private_key_cycle_id=model_utils.PrivateKey_Cycle.from_string(
            cycle
        ),
        order_default_private_key_technology_id=1,
    )
    generated = PrivateKey(id=99, key_technology_id=5)
    factory = Mock(return_value=generated)
    monkeypatch.setattr(getcreate, "create__PrivateKey", factory)
    result, created = getcreate.getcreate__PrivateKey_for_AcmeAccount(
        key_context, account, key_technology_id=5
    )
    assert result is generated and created
    assert factory.call_args.kwargs["key_technology_id"] == 5
    assert factory.call_args.kwargs.get("acme_account_id__owner") == (
        None if cycle.startswith("global") else 1
    )


@pytest.mark.parametrize("backup", [False, True])
def test_deferred_finalization_uses_the_role_configuration_technology(
    backup: bool,
) -> None:
    configuration = RenewalConfiguration(
        private_key_technology_id__primary=4, private_key_technology_id__backup=5
    )
    order = AcmeOrder(
        private_key_id=0,
        certificate_type_id=(
            model_utils.X509CertificateType.MANAGED_BACKUP
            if backup
            else model_utils.X509CertificateType.MANAGED_PRIMARY
        ),
    )
    order.renewal_configuration = configuration
    assert actions_acme._order_key_technology(order) == (5 if backup else 4)


def test_yearly_lookup_is_scoped_and_not_limited_to_five_recent_orders(
    key_context: ApiContext,
) -> None:
    selected = key(key_context, 1, kind="single_use__reuse_1_year")
    add_order(key_context, 1, status="valid")
    # A newer wrong-algorithm key and many unrelated backup orders must not hide
    # the existing primary key or silently change the requested algorithm.
    key(key_context, 2, kind="single_use__reuse_1_year", technology=1)
    add_order(key_context, 2, status="valid")
    key_context.dbSession.execute(
        sa.update(AcmeOrder).where(AcmeOrder.id == 2).values(private_key_id=2)
    )
    for identity in range(3, 11):
        add_order(key_context, identity, status="valid")
        key_context.dbSession.execute(
            sa.update(AcmeOrder)
            .where(AcmeOrder.id == identity)
            .values(
                acme_account_id=2,
                certificate_type_id=model_utils.X509CertificateType.MANAGED_BACKUP,
            )
        )
    key_context.dbSession.commit()
    order = AcmeOrder(
        id=100,
        renewal_configuration_id=1,
        acme_account_id=1,
        certificate_type_id=model_utils.X509CertificateType.MANAGED_PRIMARY,
    )
    assert actions_acme._find_yearly_reuse_key(key_context, order, 4) is selected
    order.renewal_configuration_id = 2
    assert actions_acme._find_yearly_reuse_key(key_context, order, 4) is None


@pytest.mark.parametrize("change", ["none", "key", "metadata", "corrupt"])
def test_reused_csr_must_match_both_current_key_and_actual_public_key(
    change: str,
) -> None:
    original = cert_utils.new_key_ec()
    replacement = cert_utils.new_key_ec()
    csr_pem = cert_utils.make_csr(["csr-policy.example.com"], key_pem=original)
    original_spki = cert_utils.parse_key__spki_sha256(key_pem=original)
    replacement_spki = cert_utils.parse_key__spki_sha256(key_pem=replacement)
    material = PrivateKey(id=1, key_pem=original, spki_sha256=original_spki)
    csr = X509CertificateRequest(
        id=1, private_key_id=1, spki_sha256=original_spki, csr_pem=csr_pem
    )
    order = AcmeOrder(id=1)
    order.private_key = material
    order.x509_certificate_request = csr
    if change == "key":
        order.private_key = PrivateKey(
            id=2, key_pem=replacement, spki_sha256=replacement_spki
        )
    elif change == "metadata":
        material.spki_sha256 = replacement_spki
        csr.spki_sha256 = (
            replacement_spki  # Matching metadata cannot hide a different CSR key.
        )
    elif change == "corrupt":
        csr.csr_pem = "invalid CSR"
    result = actions_acme._reusable_order_csr(order)
    assert result is csr if change == "none" else result is None


def test_remote_issuance_consumes_single_use_key_before_download(
    key_context: ApiContext,
) -> None:
    material = key(key_context, kind="single_use")
    add_order(key_context, 1, status="valid")
    order = key_context.dbSession.get(AcmeOrder, 1)
    assert order is not None and order.x509_certificate_id is None
    assert key_context.dbSession.query(X509Certificate).count() == 0
    with pytest.raises(errors.InvalidRequest, match="already used"):
        validate_private_key_for_order(key_context, material, 1)
    # Continuing recovery for that same order does not reserve it for another.
    validate_private_key_for_order(key_context, material, 1, order=order)
