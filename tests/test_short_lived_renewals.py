"""Renewal boundaries follow actual certificate validity, including partial hours."""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

import pytest
import sqlalchemy as sa

from peter_sslers.lib.db import get
from peter_sslers.model import utils
from peter_sslers.model.objects import AriCheck
from peter_sslers.model.objects import X509Certificate
from . import test_certificate_expiry

if TYPE_CHECKING:
    from peter_sslers.lib.context import ApiContext

context = test_certificate_expiry.context
NOW = test_certificate_expiry.NOW


@pytest.fixture
def renewal_context(context: ApiContext) -> ApiContext:
    """Use a minimal real SQLite schema for the renewal query's joins."""
    session = context.dbSession
    AriCheck.__table__.create(session.get_bind())
    session.execute(
        sa.text(
            "CREATE TABLE renewal_configuration (id INTEGER PRIMARY KEY, is_active BOOLEAN)"
        )
    )
    session.execute(sa.text("INSERT INTO renewal_configuration VALUES (1,1)"))
    session.execute(
        sa.text(
            "CREATE TABLE acme_order (id INTEGER PRIMARY KEY, x509_certificate_id INTEGER, renewal_configuration_id INTEGER, certificate_type_id INTEGER)"
        )
    )
    session.execute(
        sa.text("INSERT INTO acme_order VALUES (1,1,1,:type)"),
        {"type": utils.X509CertificateType.MANAGED_PRIMARY},
    )
    session.execute(sa.update(X509Certificate).values(is_active=False))
    return context


@pytest.mark.parametrize(
    "seconds", [64 * 86400, 45 * 86400, 160 * 3600, 160 * 3600 + 60]
)
@pytest.mark.parametrize("offset, expected", [(-1, False), (0, True), (1, True)])
def test_actual_validity_boundary_instead_of_cached_whole_hours(
    renewal_context: ApiContext,
    seconds: int,
    offset: int,
    expected: bool,
) -> None:
    end = NOW + datetime.timedelta(seconds=seconds)
    renewal_context.dbSession.execute(
        sa.update(X509Certificate)
        .where(X509Certificate.id == 1)
        .values(
            timestamp_not_before=NOW,
            timestamp_not_after=end,
            duration_hours=1,
            is_active=True,
        )
    )
    threshold = NOW + datetime.timedelta(seconds=seconds * 2 / 3 + offset)
    result = get.get_X509Certificates_renew_now(
        renewal_context, timestamp_max_expiry=threshold
    )
    assert bool(result) is expected


@pytest.mark.parametrize("success", [False, True])
def test_ari_window_remains_authoritative_and_failed_checks_fall_back(
    renewal_context: ApiContext,
    success: bool,
) -> None:
    session = renewal_context.dbSession
    end = NOW + datetime.timedelta(hours=160)
    session.execute(
        sa.update(X509Certificate)
        .where(X509Certificate.id == 1)
        .values(
            timestamp_not_before=NOW,
            timestamp_not_after=end,
            duration_hours=1,
            is_active=True,
        )
    )
    session.add(
        AriCheck(
            x509_certificate_id=1,
            timestamp_created=NOW,
            ari_check_status=success,
            suggested_window_end=end - datetime.timedelta(hours=1),
        )
    )
    session.flush()
    threshold = NOW + datetime.timedelta(hours=110)
    result = get.get_X509Certificates_renew_now(
        renewal_context, timestamp_max_expiry=threshold
    )
    assert bool(result) is (not success)
    assert get.get_X509Certificates_renew_now(renewal_context, timestamp_max_expiry=end)


@pytest.mark.parametrize("offset, expected", [(-1, False), (0, True)])
def test_cutoff_preserves_non_utc_offsets(
    renewal_context: ApiContext, offset: int, expected: bool
) -> None:
    end = NOW + datetime.timedelta(hours=160)
    renewal_context.dbSession.execute(
        sa.update(X509Certificate)
        .where(X509Certificate.id == 1)
        .values(
            timestamp_not_before=NOW,
            timestamp_not_after=end,
            duration_hours=1,
            is_active=True,
        )
    )
    threshold = (
        NOW + datetime.timedelta(seconds=160 * 3600 * 2 / 3 + offset)
    ).astimezone(datetime.timezone(datetime.timedelta(hours=5, minutes=30)))
    assert (
        bool(
            get.get_X509Certificates_renew_now(
                renewal_context, timestamp_max_expiry=threshold
            )
        )
        is expected
    )
