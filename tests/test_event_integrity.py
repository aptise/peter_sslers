"""Audit linkage, rollback, payload freshness and coverage-event consistency."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import cast
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
import sqlalchemy as sa

from peter_sslers.lib import errors
from peter_sslers.lib.db import create
from peter_sslers.lib.db import logger
from peter_sslers.lib.db import update
from peter_sslers.model import utils as model_utils
from peter_sslers.model.objects import CoverageAssuranceEvent
from peter_sslers.model.objects import Domain
from peter_sslers.model.objects import OperationsEvent
from peter_sslers.model.objects import OperationsObjectEvent
from peter_sslers.model.objects import PrivateKey
from peter_sslers.model.objects import X509Certificate
from . import test_certificate_expiry

if TYPE_CHECKING:
    from pyramid.request import Request

    from peter_sslers.lib.context import ApiContext

NOW = test_certificate_expiry.NOW
context = test_certificate_expiry.context
EVENT_TYPE = model_utils.OperationsEventType.from_string("PrivateKey__insert")


@pytest.fixture
def audit_context(context: ApiContext) -> ApiContext:
    for model in (
        OperationsEvent,
        OperationsObjectEvent,
        CoverageAssuranceEvent,
        PrivateKey,
    ):
        model.__table__.create(context.dbSession.get_bind())
    context.dbSession.execute(
        sa.insert(PrivateKey).values(
            id=1,
            timestamp_created=NOW,
            key_technology_id=4,
            key_pem="private",
            key_pem_md5="private",
            spki_sha256="private",
            private_key_type_id=1,
            private_key_source_id=1,
            operations_event_id__created=1,
        )
    )
    context.dbSession.commit()
    return context


def test_event_payload_refresh_and_legacy_read_safety(
    audit_context: ApiContext,
) -> None:
    session = audit_context.dbSession
    event = logger.log__OperationsEvent(audit_context, EVENT_TYPE, {"v": 1, "count": 1})
    session.commit()
    assert event.event_payload_json["count"] == 1
    # Core SQL deliberately bypasses ORM assignment validation, as historical data
    # and external database maintenance can do.
    session.execute(
        sa.update(OperationsEvent)
        .where(OperationsEvent.id == event.id)
        .values(
            event_payload=json.dumps({"v": 1, "count": 2, "password": "legacy-secret"})
        )
    )
    session.commit()
    assert event.event_payload_json["count"] == 2
    assert "legacy-secret" not in json.dumps(event.as_json)


def test_missing_or_multiple_object_subjects_fail_before_database_flush(
    audit_context: ApiContext,
) -> None:
    event = logger.log__OperationsEvent(audit_context, EVENT_TYPE)
    domain = audit_context.dbSession.get(Domain, 1)
    material = audit_context.dbSession.get(PrivateKey, 1)
    assert domain is not None and material is not None
    with pytest.raises(ValueError, match="Exactly one persisted object"):
        logger._log_object_event(audit_context, event, EVENT_TYPE)
    with pytest.raises(ValueError, match="Exactly one persisted object"):
        logger._log_object_event(
            audit_context, event, EVENT_TYPE, dbDomain=domain, dbPrivateKey=material
        )
    with pytest.raises(ValueError, match="Exactly one persisted object"):
        logger._log_object_event(
            audit_context, event, EVENT_TYPE, dbPrivateKey=PrivateKey()
        )
    assert audit_context.dbSession.query(OperationsObjectEvent).count() == 0
    linked = logger._log_object_event(
        audit_context, event, EVENT_TYPE, dbPrivateKey=material
    )
    assert linked.private_key_id == 1


def test_audit_codes_are_validated_before_persistence(
    audit_context: ApiContext,
) -> None:
    with pytest.raises(ValueError, match="Unknown OperationsEvent"):
        logger.log__OperationsEvent(audit_context, -1)
    event = logger.log__OperationsEvent(audit_context, EVENT_TYPE)
    with pytest.raises(ValueError, match="Unknown OperationsObjectEvent"):
        logger._log_object_event(
            audit_context, event, -1, dbDomain=audit_context.dbSession.get(Domain, 1)
        )


def test_detached_rolled_back_parent_is_not_silently_recreated(
    audit_context: ApiContext,
) -> None:
    event = logger.log__OperationsEvent(audit_context, EVENT_TYPE)
    identity = event.id
    audit_context.dbSession.rollback()
    audit_context.dbOperationsEvent = None
    with pytest.raises(ValueError, match="parent"):
        logger.log__OperationsEvent(
            audit_context, EVENT_TYPE, dbOperationsEvent_child_of=event
        )
    assert audit_context.dbSession.get(OperationsEvent, identity) is None


def test_detached_committed_parent_can_link_new_events(
    audit_context: ApiContext,
) -> None:
    event = logger.log__OperationsEvent(audit_context, EVENT_TYPE)
    audit_context.dbSession.commit()
    identity = event.id
    audit_context.dbSession.expunge(event)
    child = logger.log__OperationsEvent(
        audit_context, EVENT_TYPE, dbOperationsEvent_child_of=event
    )
    assert child.operations_event_id__child_of == identity


@pytest.mark.parametrize("committed", [False, True])
def test_context_abort_retains_only_a_parent_that_survives_rollback(
    audit_context: ApiContext, committed: bool
) -> None:
    event = logger.log__OperationsEvent(audit_context, EVENT_TYPE)
    identity = event.id
    if committed:
        audit_context.dbSession.commit()
    manager = SimpleNamespace(
        abort=Mock(side_effect=audit_context.dbSession.rollback), begin=Mock()
    )
    audit_context.request = cast("Request", SimpleNamespace(tm=manager))
    audit_context.pyramid_transaction_rollback()
    assert (audit_context.dbOperationsEvent is not None) is committed
    if committed:
        assert audit_context.dbOperationsEvent is not None
        assert audit_context.dbOperationsEvent.id == identity
    manager.abort.assert_called_once()
    manager.begin.assert_called_once()


def coverage(ctx: ApiContext, *, certificate: bool = False) -> CoverageAssuranceEvent:
    material = ctx.dbSession.get(PrivateKey, 1)
    assert material is not None
    cert = ctx.dbSession.get(X509Certificate, 2) if certificate else None
    return create.create__CoverageAssuranceEvent(
        ctx,
        coverage_assurance_event_type_id=model_utils.CoverageAssuranceEventType.from_string(
            "PrivateKey_compromised_mark"
        ),
        coverage_assurance_event_status_id=model_utils.CoverageAssuranceEventStatus.from_string(
            "reported+deactivated"
        ),
        dbPrivateKey=material,
        dbX509Certificate=cert,
    )


def test_coverage_serialization_uses_certificate_id_not_private_key_id(
    audit_context: ApiContext,
) -> None:
    event = coverage(audit_context, certificate=True)
    assert event.as_json["x509_certificate_id"] == 2
    assert event.as_json["private_key_id"] == 1


def test_coverage_subjects_must_match_the_parent_and_each_other(
    audit_context: ApiContext,
) -> None:
    parent = coverage(audit_context)
    material = PrivateKey(id=99)
    certificate = audit_context.dbSession.get(X509Certificate, 2)
    assert certificate is not None
    with pytest.raises(ValueError):
        create.create__CoverageAssuranceEvent(
            audit_context,
            coverage_assurance_event_type_id=1,
            coverage_assurance_event_status_id=1,
            dbPrivateKey=material,
            dbX509Certificate=certificate,
        )
    with pytest.raises(ValueError):
        create.create__CoverageAssuranceEvent(
            audit_context,
            coverage_assurance_event_type_id=1,
            coverage_assurance_event_status_id=1,
            dbPrivateKey=material,
            dbCoverageAssuranceEvent_parent=parent,
        )
    with pytest.raises(ValueError):
        create.create__CoverageAssuranceEvent(
            audit_context,
            coverage_assurance_event_type_id=1,
            coverage_assurance_event_status_id=1,
            dbPrivateKey=PrivateKey(),
        )


@pytest.mark.parametrize(
    "resolution, status",
    [("abandoned", "resolved-ignored"), ("PrivateKey_replaced", "resolved-replaced")],
)
def test_coverage_resolution_and_status_are_updated_together(
    audit_context: ApiContext, resolution: str, status: str
) -> None:
    event = coverage(audit_context)
    assert update.update_CoverageAssuranceEvent__set_resolution(
        audit_context, event, resolution
    )
    assert event.coverage_assurance_event_status == status
    assert event.coverage_assurance_resolution == resolution
    material = audit_context.dbSession.get(PrivateKey, 1)
    assert material is not None
    material.is_active = False
    assert update.update_CoverageAssuranceEvent__set_resolution(
        audit_context, event, "unresolved"
    )
    assert event.coverage_assurance_event_status == "reported+deactivated"


def test_coverage_rejects_incompatible_and_noop_resolution_changes(
    audit_context: ApiContext,
) -> None:
    event = coverage(audit_context)
    for resolution in ("X509Certificate_replaced", "unresolved"):
        with pytest.raises(errors.InvalidTransition):
            update.update_CoverageAssuranceEvent__set_resolution(
                audit_context, event, resolution
            )
    assert event.coverage_assurance_resolution == "unresolved"


def test_subject_relationship_type_is_checked_even_when_ids_overlap(
    audit_context: ApiContext,
) -> None:
    event = logger.log__OperationsEvent(audit_context, EVENT_TYPE)
    domain = audit_context.dbSession.get(Domain, 1)
    assert domain is not None
    with pytest.raises(ValueError, match="relationship"):
        logger._log_object_event(
            audit_context, event, EVENT_TYPE, dbPrivateKey=cast(PrivateKey, domain)
        )


def test_resolution_transition_has_one_journal_with_before_and_after(
    audit_context: ApiContext,
) -> None:
    incident = coverage(audit_context)
    assert update.update_CoverageAssuranceEvent__set_resolution(
        audit_context, incident, "abandoned"
    )
    operations = audit_context.dbSession.query(OperationsEvent).all()
    assert len(operations) == 1
    payload = operations[0].event_payload_json
    assert payload["previous_resolution"] == "unresolved"
    assert payload["resolution"] == "abandoned"
    assert payload["previous_status"] == "reported+deactivated"
    assert payload["status"] == "resolved-ignored"
    link = audit_context.dbSession.query(OperationsObjectEvent).one()
    assert link.coverage_assurance_event_id == incident.id


def test_coverage_creation_correlates_without_extra_operation(
    audit_context: ApiContext,
) -> None:
    operation = logger.log__OperationsEvent(audit_context, EVENT_TYPE)
    material = audit_context.dbSession.get(PrivateKey, 1)
    assert material is not None
    incident = create.create__CoverageAssuranceEvent(
        audit_context,
        coverage_assurance_event_type_id=1,
        coverage_assurance_event_status_id=1,
        dbPrivateKey=material,
        dbOperationsEvent=operation,
    )
    link = audit_context.dbSession.query(OperationsObjectEvent).one()
    assert link.operations_event_id == operation.id
    assert link.coverage_assurance_event_id == incident.id
    assert audit_context.dbSession.query(OperationsEvent).count() == 1


def test_pending_subject_deletion_cannot_gain_new_audit_or_coverage_links(
    audit_context: ApiContext,
) -> None:
    operation = logger.log__OperationsEvent(audit_context, EVENT_TYPE)
    material = audit_context.dbSession.get(PrivateKey, 1)
    assert material is not None
    audit_context.dbSession.delete(material)
    with pytest.raises(ValueError, match="being deleted"):
        logger._log_object_event(
            audit_context, operation, EVENT_TYPE, dbPrivateKey=material
        )
    with pytest.raises(ValueError, match="being deleted"):
        create.create__CoverageAssuranceEvent(
            audit_context,
            coverage_assurance_event_type_id=1,
            coverage_assurance_event_status_id=1,
            dbPrivateKey=material,
        )


def test_pending_parent_deletion_cannot_gain_new_children(
    audit_context: ApiContext,
) -> None:
    operation = logger.log__OperationsEvent(audit_context, EVENT_TYPE)
    material = audit_context.dbSession.get(PrivateKey, 1)
    assert material is not None
    audit_context.dbSession.delete(operation)
    with pytest.raises(ValueError, match="being deleted"):
        logger.log__OperationsEvent(
            audit_context, EVENT_TYPE, dbOperationsEvent_child_of=operation
        )
    with pytest.raises(ValueError, match="being deleted"):
        logger._log_object_event(
            audit_context, operation, EVENT_TYPE, dbPrivateKey=material
        )
