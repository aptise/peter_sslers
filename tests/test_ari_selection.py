import datetime
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import sqlalchemy as sa

from peter_sslers.lib.db import actions, get
from peter_sslers.model.objects import AriCheck, X509Certificate
from peter_sslers.model import utils as model_utils
from .test_certificate_expiry import context, NOW


@pytest.fixture
def ari_context(context):
    session = context.dbSession
    AriCheck.__table__.create(session.get_bind())
    context.application_settings = {"offset.ari_updates":60}
    session.execute(sa.update(X509Certificate).values(
        timestamp_not_after=NOW+datetime.timedelta(days=90), duration_hours=2160,
        is_ari_supported__cert=True,
    ))
    # Multiple checks per certificate; newest ID is authoritative, not oldest hint/window.
    entries = [
        (1,1,-120,-1,-1),(2,1,-60,30,10),
        (3,2,-120,2880,10),(4,2,-120,None,None),
        (5,3,-120,2880,10),(6,3,-120,0,-1),
    ]
    for identity,cert,age,retry,window in entries:
        session.add(AriCheck(
            id=identity,x509_certificate_id=cert,
            timestamp_created=NOW+datetime.timedelta(minutes=age),
            timestamp_retry_after=NOW+datetime.timedelta(minutes=retry) if retry is not None else None,
            suggested_window_start=NOW-datetime.timedelta(days=2) if window is not None else None,
            suggested_window_end=NOW+datetime.timedelta(days=window) if window is not None else None,
            ari_check_status=window is not None,
        ))
    session.commit()
    return context


def test_latest_queries_use_latest_record_before_filtering_due(ari_context):
    assert get.get__AriChecks__count(ari_context,"all") == 6
    assert get.get__AriChecks__count(ari_context,"cert-latest") == 3
    assert [row.id for row in get.get__AriChecks___paginated(ari_context,"cert-latest")] == [6,4,2]
    assert [row.id for row in get.get__AriChecks___paginated(ari_context,"cert-latest",limit=1,offset=1)] == [4]
    assert get.get__AriChecks__count(ari_context,"cert-latest-overdue") == 2
    assert [row.id for row in get.get__AriChecks___paginated(ari_context,"cert-latest-overdue")] == [6,4]


def test_recent_check_without_retry_hint_waits_for_default_interval(ari_context):
    ari_context.dbSession.add(AriCheck(id=7,x509_certificate_id=2,timestamp_created=NOW,ari_check_status=False))
    ari_context.dbSession.flush()
    assert [row.id for row in get.get__AriChecks___paginated(ari_context,"cert-latest-overdue")] == [6]


def test_renewal_uses_latest_window_not_superseded_history(ari_context):
    session = ari_context.dbSession
    session.execute(sa.text("CREATE TABLE renewal_configuration (id INTEGER PRIMARY KEY, is_active BOOLEAN)"))
    session.execute(sa.text("INSERT INTO renewal_configuration VALUES (1,1)"))
    session.execute(sa.text("CREATE TABLE acme_order (id INTEGER PRIMARY KEY, x509_certificate_id INTEGER, renewal_configuration_id INTEGER, certificate_type_id INTEGER)"))
    for identity in range(1,6):
        session.execute(sa.text("INSERT INTO acme_order VALUES (:id,:id,1,:type)"),{"id":identity,"type":model_utils.X509CertificateType.MANAGED_PRIMARY})
    # A legacy failed record may still contain a window; it must not drive renewal.
    session.get(AriCheck,4).suggested_window_end = NOW-datetime.timedelta(days=1)
    result = get.get_X509Certificates_renew_now(ari_context,timestamp_max_expiry=NOW)
    assert [certificate.id for certificate in result] == [3]


def test_routine_honors_latest_retry_hint_and_recovers_after_flush_failure(ari_context, monkeypatch):
    session = ari_context.dbSession
    class Clock(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW
    monkeypatch.setattr(actions,"datetime",SimpleNamespace(datetime=Clock,timezone=datetime.timezone))
    ari_context.pyramid_transaction_commit = Mock(side_effect=session.commit)
    ari_context.pyramid_transaction_rollback = Mock(side_effect=session.rollback)
    visited = []
    def check(context, dbX509Certificate, force_check):
        identity = dbX509Certificate.id
        visited.append(identity)
        if identity == 3:
            session.add(AriCheck())
            session.flush()  # Poison the SQLAlchemy transaction, requiring rollback.
        return SimpleNamespace(ari_check_status=identity == 5), None
    monkeypatch.setattr(actions.actions_acme,"do__AcmeV2_AriCheck",check)
    routine = Mock(return_value=SimpleNamespace(id=1))
    monkeypatch.setattr(actions.lib_db.create,"create__RoutineExecution",routine)
    actions.routine__run_ari_checks(ari_context)
    assert visited == [5,3,2]
    assert routine.call_args.kwargs["count_records_success"] == 1
    assert routine.call_args.kwargs["count_records_fail"] == 2
    ari_context.pyramid_transaction_rollback.assert_called_once()
    assert session.query(X509Certificate).count() == 5


def test_routine_does_not_count_uncommitted_check_as_success(ari_context, monkeypatch):
    class Clock(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW
    monkeypatch.setattr(actions,"datetime",SimpleNamespace(datetime=Clock,timezone=datetime.timezone))
    ari_context.pyramid_transaction_commit = Mock(side_effect=[RuntimeError("commit failed"),None,None,None])
    ari_context.pyramid_transaction_rollback = Mock(side_effect=ari_context.dbSession.rollback)
    monkeypatch.setattr(actions.actions_acme,"do__AcmeV2_AriCheck",Mock(return_value=(SimpleNamespace(ari_check_status=True),None)))
    routine = Mock(return_value=SimpleNamespace(id=1))
    monkeypatch.setattr(actions.lib_db.create,"create__RoutineExecution",routine)
    actions.routine__run_ari_checks(ari_context)
    assert routine.call_args.kwargs["count_records_success"] == 2
    assert routine.call_args.kwargs["count_records_fail"] == 1
    ari_context.pyramid_transaction_rollback.assert_called_once()
