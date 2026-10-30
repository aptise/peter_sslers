"""Scheduling boundaries and per-item recovery for automated ACME work."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
import sqlalchemy as sa

from peter_sslers.lib import errors
from peter_sslers.lib.config_utils import ApplicationSettings
from peter_sslers.lib.db import actions
from peter_sslers.lib.db import get
from peter_sslers.model import utils as model_utils
from peter_sslers.model.objects import AcmeAuthorization
from peter_sslers.model.objects import AcmeOrder
from peter_sslers.model.objects import AcmeOrder2AcmeAuthorization
from peter_sslers.model.objects import AriCheck
from peter_sslers.model.objects import RenewalConfiguration
from peter_sslers.model.objects import RoutineExecution
from . import test_certificate_expiry

if TYPE_CHECKING:
    from peter_sslers.lib.context import ApiContext


NOW = test_certificate_expiry.NOW
context = test_certificate_expiry.context


@dataclass
class RoutineHarness:
    context: ApiContext
    server: Mock
    factory: Mock
    new_order: Mock
    receipt: Mock

    def counts(self) -> Tuple[int, int]:
        arguments = self.receipt.call_args.kwargs
        return arguments["count_records_success"], arguments["count_records_fail"]


def add_order(
    context: ApiContext,
    identity: int,
    *,
    status: str = "pending",
    configuration_id: int = 1,
    certificate_id: Optional[int] = None,
) -> None:
    context.dbSession.execute(
        sa.insert(AcmeOrder).values(
            id=identity,
            timestamp_created=NOW,
            acme_order_type_id=1,
            acme_order_processing_strategy_id=1,
            acme_order_processing_status_id=1,
            certificate_type_id=model_utils.X509CertificateType.MANAGED_PRIMARY,
            acme_event_log_id=1,
            acme_account_id=1,
            private_key_id=1,
            private_key_cycle_id=1,
            unique_fqdn_set_id=1,
            uniquely_challenged_fqdn_set_id=1,
            private_key_deferred_id=0,
            acme_status_order_id=model_utils.Acme_Status_Order.from_string(status),
            renewal_configuration_id=configuration_id,
            x509_certificate_id=certificate_id,
            is_processing=True if status == "pending" else None,
        )
    )
    context.dbSession.commit()


@pytest.fixture
def harness(context: ApiContext, monkeypatch: pytest.MonkeyPatch) -> RoutineHarness:
    session = context.dbSession
    for model in (
        RenewalConfiguration,
        AcmeOrder,
        AriCheck,
        AcmeAuthorization,
        AcmeOrder2AcmeAuthorization,
    ):
        model.__table__.create(session.get_bind())
    for identity, backup, active in (
        (1, True, True),
        (2, False, True),
        (3, False, False),
    ):
        session.execute(
            sa.insert(RenewalConfiguration).values(
                id=identity,
                timestamp_created=NOW,
                is_active=active,
                is_export_filesystem_id=0,
                uniquely_challenged_fqdn_set_id=1,
                unique_fqdn_set_id=1,
                operations_event_id__created=1,
                acme_account_id__primary=1,
                private_key_cycle_id__primary=1,
                private_key_technology_id__primary=4,
                acme_account_id__backup=2 if backup else None,
                private_key_cycle_id__backup=1 if backup else None,
                private_key_technology_id__backup=4 if backup else None,
            )
        )
    session.commit()
    context.application_settings = ApplicationSettings()
    context.application_settings["offset.ari_updates"] = 60
    setattr(context, "pyramid_transaction_commit", Mock(side_effect=session.commit))
    setattr(context, "pyramid_transaction_rollback", Mock(side_effect=session.rollback))
    receipt = Mock(return_value=RoutineExecution(id=1))
    monkeypatch.setattr(actions.create, "create__RoutineExecution", receipt)
    new_order = Mock(return_value=AcmeOrder(id=100, x509_certificate_id=100))
    monkeypatch.setattr(actions.actions_acme, "do__AcmeV2_AcmeOrder__new", new_order)
    server = Mock()
    return RoutineHarness(
        context, server, Mock(return_value=server), new_order, receipt
    )


@pytest.fixture
def renewals(harness: RoutineHarness) -> RoutineHarness:
    for identity, configuration_id in ((1, 1), (2, 2), (5, 2)):
        add_order(
            harness.context,
            identity + 10,
            status="valid",
            configuration_id=configuration_id,
            certificate_id=identity,
        )
    return harness


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("limit, expected", [(None, 3), (0, 0), (1, 1), (2, 2), (3, 3)])
def test_missing_orders_share_one_limit_and_dry_runs_do_not_start_server(
    harness: RoutineHarness,
    limit: Optional[int],
    expected: int,
    dry_run: bool,
) -> None:
    actions.routine__order_missing(
        harness.context,
        {},
        create_public_server=harness.factory,
        limit=limit,
        dry_run=dry_run,
    )
    assert harness.counts() == (expected, 0)
    assert harness.new_order.call_count == (0 if dry_run else expected)
    assert harness.factory.call_count == (1 if expected and not dry_run else 0)
    assert harness.server.shutdown.call_count == harness.factory.call_count
    if expected and not dry_run:
        roles = [call.kwargs["replaces"] for call in harness.new_order.call_args_list]
        assert roles == ["backup", "primary", "primary"][:expected]


@pytest.mark.parametrize("selected, expected", [((), 0), ((2,), 1), ((1,), 2)])
def test_missing_orders_respect_explicit_configuration_selection(
    harness: RoutineHarness,
    selected: Tuple[int, ...],
    expected: int,
) -> None:
    actions.routine__order_missing(
        harness.context,
        {},
        create_public_server=harness.factory,
        renewal_configuration_ids__only_process=selected,
    )
    assert harness.counts() == (expected, 0)
    assert harness.new_order.call_count == expected


@pytest.mark.parametrize("operation", ["missing", "renew"])
@pytest.mark.parametrize("limit", [-1, True, 1.5, "2"])
def test_invalid_limits_are_rejected_before_work(
    harness: RoutineHarness,
    operation: str,
    limit: object,
) -> None:
    function = (
        actions.routine__order_missing
        if operation == "missing"
        else actions.routine__renew_expiring
    )
    with pytest.raises(ValueError, match="limit"):
        function(
            harness.context,
            {},
            create_public_server=harness.factory,
            limit=cast(Optional[int], limit),
        )
    harness.factory.assert_not_called()
    harness.new_order.assert_not_called()


@pytest.mark.parametrize("operation", ["missing", "renew"])
def test_ordering_recovers_after_failed_database_flush(
    renewals: RoutineHarness,
    operation: str,
) -> None:
    harness = renewals
    # Missing-order selection has one backup left. Add two unused configurations
    # by selecting the existing ones after clearing order history in that case.
    if operation == "missing":
        harness.context.dbSession.execute(sa.delete(AcmeOrder))
        harness.context.dbSession.commit()
    visited = []

    def issue(
        ctx: ApiContext, dbRenewalConfiguration: RenewalConfiguration, **kwargs: object
    ) -> AcmeOrder:
        visited.append(dbRenewalConfiguration.id)
        if len(visited) == 1:
            ctx.dbSession.add(RenewalConfiguration())
            ctx.dbSession.flush()  # Leave the session in PendingRollback state.
        return AcmeOrder(id=100, x509_certificate_id=100)

    harness.new_order.side_effect = issue
    function = (
        actions.routine__order_missing
        if operation == "missing"
        else actions.routine__renew_expiring
    )
    function(harness.context, {}, create_public_server=harness.factory)
    assert harness.counts() == (2, 1)
    assert len(visited) == 3
    cast(Mock, harness.context.pyramid_transaction_rollback).assert_called_once()
    assert harness.context.dbSession.is_active
    harness.server.shutdown.assert_called_once()


@pytest.mark.parametrize("operation", ["missing", "renew"])
def test_ordering_counts_commit_failures_as_failures(
    renewals: RoutineHarness,
    operation: str,
) -> None:
    harness = renewals
    if operation == "missing":
        harness.context.dbSession.execute(sa.delete(AcmeOrder))
        harness.context.dbSession.commit()
    cast(Mock, harness.context.pyramid_transaction_commit).side_effect = [
        RuntimeError("commit failed"),
        None,
        None,
        None,
    ]
    function = (
        actions.routine__order_missing
        if operation == "missing"
        else actions.routine__renew_expiring
    )
    function(harness.context, {}, create_public_server=harness.factory)
    assert harness.counts() == (2, 1)
    cast(Mock, harness.context.pyramid_transaction_rollback).assert_called_once()
    harness.server.shutdown.assert_called_once()


def test_renewal_filter_precedes_limit_and_zero_limit_selects_nothing(
    renewals: RoutineHarness,
) -> None:
    context = renewals.context
    assert [
        certificate.id
        for certificate in get.get_X509Certificates_renew_now(
            context, timestamp_max_expiry=NOW, limit=1, renewal_configuration_ids=(2,)
        )
    ] == [2]
    assert (
        get.get_X509Certificates_renew_now(context, timestamp_max_expiry=NOW, limit=0)
        == []
    )
    assert (
        get.get_X509Certificates_renew_now(
            context, timestamp_max_expiry=NOW, renewal_configuration_ids=()
        )
        == []
    )
    actions.routine__renew_expiring(
        context,
        {},
        create_public_server=renewals.factory,
        limit=1,
        renewal_configuration_ids__only_process=(2,),
    )
    assert renewals.counts() == (1, 0)
    assert renewals.new_order.call_args.kwargs["dbRenewalConfiguration"].id == 2


def test_renewal_dry_run_does_not_issue_or_bind_server(
    renewals: RoutineHarness,
) -> None:
    actions.routine__renew_expiring(
        renewals.context, {}, create_public_server=renewals.factory, dry_run=True
    )
    assert renewals.counts() == (3, 0)
    renewals.new_order.assert_not_called()
    renewals.factory.assert_not_called()


def test_expected_candidate_count_includes_zero_and_is_not_an_assertion(
    renewals: RoutineHarness,
) -> None:
    with pytest.raises(ValueError, match="Expected 0 renewal candidates; selected 3"):
        actions.routine__renew_expiring(
            renewals.context,
            {},
            create_public_server=renewals.factory,
            count_expected_configurations=0,
        )
    renewals.factory.assert_not_called()
    actions.routine__renew_expiring(
        renewals.context,
        {},
        create_public_server=renewals.factory,
        count_expected_configurations=0,
        renewal_configuration_ids__only_process=(),
    )
    assert renewals.counts() == (0, 0)
    renewals.factory.assert_not_called()


@pytest.mark.parametrize("phase", ["sync", "continue"])
def test_reconciliation_commit_failures_are_not_double_counted(
    harness: RoutineHarness,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    add_order(harness.context, 1)
    sync = Mock(side_effect=lambda ctx, dbAcmeOrder, **kwargs: dbAcmeOrder)

    def process(
        ctx: ApiContext, dbAcmeOrder: AcmeOrder, transaction_commit: bool
    ) -> AcmeOrder:
        dbAcmeOrder.acme_status_order_id = model_utils.Acme_Status_Order.from_string(
            "valid"
        )
        return dbAcmeOrder

    monkeypatch.setattr(
        actions.actions_acme, "do__AcmeV2_AcmeOrder__acme_server_sync", sync
    )
    monkeypatch.setattr(actions.actions_acme, "do__AcmeV2_AcmeOrder__process", process)
    cast(Mock, harness.context.pyramid_transaction_commit).side_effect = (
        [RuntimeError("commit failed"), None]
        if phase == "sync"
        else [None, RuntimeError("commit failed"), None]
    )
    actions.routine__reconcile_blocks(
        harness.context,
        {},
        create_public_server=harness.factory,
        transaction_commit=True,
    )
    assert harness.counts() == (0, 1)
    assert harness.factory.call_count == (1 if phase == "continue" else 0)
    cast(Mock, harness.context.pyramid_transaction_rollback).assert_called_once()


def test_reconciliation_isolates_sync_failures_and_bounds_unchanged_orders(
    harness: RoutineHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for identity in (1, 2, 3):
        add_order(harness.context, identity)
    processed = []
    finalized = []

    def sync(
        ctx: ApiContext, dbAcmeOrder: AcmeOrder, transaction_commit: bool
    ) -> AcmeOrder:
        if dbAcmeOrder.id == 2:
            ctx.dbSession.add(RenewalConfiguration())
            ctx.dbSession.flush()
        return dbAcmeOrder

    def process(
        ctx: ApiContext, dbAcmeOrder: AcmeOrder, transaction_commit: bool
    ) -> AcmeOrder:
        processed.append(dbAcmeOrder.id)
        if dbAcmeOrder.id == 1:
            dbAcmeOrder.acme_status_order_id = (
                model_utils.Acme_Status_Order.from_string("ready")
            )
        return dbAcmeOrder

    def finalize(
        ctx: ApiContext, dbAcmeOrder: AcmeOrder, transaction_commit: bool
    ) -> AcmeOrder:
        finalized.append(dbAcmeOrder.id)
        dbAcmeOrder.acme_status_order_id = model_utils.Acme_Status_Order.from_string(
            "valid"
        )
        return dbAcmeOrder

    monkeypatch.setattr(
        actions.actions_acme, "do__AcmeV2_AcmeOrder__acme_server_sync", sync
    )
    monkeypatch.setattr(actions.actions_acme, "do__AcmeV2_AcmeOrder__process", process)
    monkeypatch.setattr(
        actions.actions_acme, "do__AcmeV2_AcmeOrder__finalize", finalize
    )
    actions.routine__reconcile_blocks(
        harness.context,
        {},
        create_public_server=harness.factory,
        transaction_commit=True,
    )
    assert processed == [3, 1]
    assert finalized == [1]
    assert harness.counts() == (1, 2)
    assert cast(Mock, harness.context.pyramid_transaction_rollback).call_count == 2
    harness.server.shutdown.assert_called_once()
    assert harness.context.dbSession.is_active


def test_reconciliation_allows_progress_through_several_authorizations(
    harness: RoutineHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order = AcmeOrder(id=1, acme_status_order_id=1)
    authorizations = [
        AcmeAuthorization(id=identity, acme_status_authorization_id=1)
        for identity in (1, 2)
    ]
    order.to_acme_authorizations = [
        AcmeOrder2AcmeAuthorization(acme_authorization=authorization)
        for authorization in authorizations
    ]

    def process(
        ctx: ApiContext, dbAcmeOrder: AcmeOrder, transaction_commit: bool
    ) -> AcmeOrder:
        if dbAcmeOrder.acme_authorizations_pending:
            dbAcmeOrder.acme_authorizations_pending[0].acme_status_authorization_id = (
                model_utils.Acme_Status_Authorization.from_string("valid")
            )
        else:
            dbAcmeOrder.acme_status_order_id = (
                model_utils.Acme_Status_Order.from_string("ready")
            )
        return dbAcmeOrder

    def finalize(
        ctx: ApiContext, dbAcmeOrder: AcmeOrder, transaction_commit: bool
    ) -> AcmeOrder:
        dbAcmeOrder.acme_status_order_id = model_utils.Acme_Status_Order.from_string(
            "valid"
        )
        return dbAcmeOrder

    processor = Mock(side_effect=process)
    finalizer = Mock(side_effect=finalize)
    monkeypatch.setattr(
        actions.actions_acme, "do__AcmeV2_AcmeOrder__process", processor
    )
    monkeypatch.setattr(
        actions.actions_acme, "do__AcmeV2_AcmeOrder__finalize", finalizer
    )
    assert actions._continue_reconciled_order(harness.context, order) is order
    assert processor.call_count == 3
    finalizer.assert_called_once()


def test_reconciliation_dry_run_never_contacts_acme_or_starts_server(
    harness: RoutineHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    add_order(harness.context, 1)
    sync = Mock()
    monkeypatch.setattr(
        actions.actions_acme, "do__AcmeV2_AcmeOrder__acme_server_sync", sync
    )
    actions.routine__reconcile_blocks(
        harness.context, {}, create_public_server=harness.factory, dry_run=True
    )
    assert harness.counts() == (1, 0)
    sync.assert_not_called()
    harness.factory.assert_not_called()


def test_reconciliation_requires_commit_acknowledgment_before_work(
    harness: RoutineHarness,
) -> None:
    with pytest.raises(errors.AcknowledgeTransactionCommitRequired):
        actions.routine__reconcile_blocks(
            harness.context, {}, create_public_server=harness.factory
        )
    harness.factory.assert_not_called()
    harness.receipt.assert_not_called()


def test_public_server_does_not_mutate_caller_settings_and_disables_debug(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from peter_sslers import web

    settings: Dict[str, str] = {
        "enable_views_admin": "true",
        "enable_views_public": "false",
        "pyramid.debug_authorization": "true",
        "pyramid.debug_notfound": "true",
        "pyramid.debug_routematch": "true",
        "http_port.renewals": "9876",
        "pyramid.includes": "pyramid_tm pyramid_debugtoolbar",
    }
    original = settings.copy()
    main = Mock()
    server = Mock()
    factory = Mock(return_value=server)
    monkeypatch.setattr(web, "main", main)
    monkeypatch.setattr(actions.StopableWSGIServer, "create", factory)
    assert actions._create_public_server(settings) is server
    assert settings == original
    configured = main.call_args.kwargs
    assert configured["enable_views_admin"] == "false"
    assert configured["enable_views_public"] == "true"
    for field in (
        "pyramid.debug_authorization",
        "pyramid.debug_notfound",
        "pyramid.debug_routematch",
    ):
        assert configured[field] == "false"
    assert "pyramid_debugtoolbar" not in configured["pyramid.includes"]
    assert factory.call_args.kwargs["port"] == 9876


def test_missing_orders_do_not_duplicate_in_progress_attempts(
    harness: RoutineHarness,
) -> None:
    add_order(harness.context, 1, configuration_id=2)
    add_order(harness.context, 2, configuration_id=1)
    harness.context.dbSession.execute(
        sa.update(AcmeOrder)
        .where(AcmeOrder.id == 2)
        .values(certificate_type_id=model_utils.X509CertificateType.MANAGED_BACKUP)
    )
    harness.context.dbSession.commit()
    actions.routine__order_missing(
        harness.context, {}, create_public_server=harness.factory
    )
    assert harness.counts() == (1, 0)
    assert harness.new_order.call_args.kwargs["dbRenewalConfiguration"].id == 1
    assert harness.new_order.call_args.kwargs["replaces"] == "primary"


def test_reconciliation_does_not_start_server_for_processing_only_orders(
    harness: RoutineHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    add_order(harness.context, 1, status="processing")
    monkeypatch.setattr(
        actions.actions_acme, "do__AcmeV2_AcmeOrder__acme_server_sync", Mock()
    )
    actions.routine__reconcile_blocks(
        harness.context,
        {},
        create_public_server=harness.factory,
        transaction_commit=True,
    )
    assert harness.counts() == (1, 0)
    harness.factory.assert_not_called()


def test_reconciliation_has_a_hard_step_budget(
    harness: RoutineHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorization = AcmeAuthorization(id=1, acme_status_authorization_id=1)
    order = AcmeOrder(id=1, acme_status_order_id=1)
    order.to_acme_authorizations = [
        AcmeOrder2AcmeAuthorization(acme_authorization=authorization)
    ]

    def process(
        ctx: ApiContext, dbAcmeOrder: AcmeOrder, transaction_commit: bool
    ) -> AcmeOrder:
        # Even continuously changing remote identifiers cannot keep a run alive forever.
        authorization.id += 1
        return dbAcmeOrder

    processor = Mock(side_effect=process)
    monkeypatch.setattr(
        actions.actions_acme, "do__AcmeV2_AcmeOrder__process", processor
    )
    with pytest.raises(errors.AcmeCommunicationError, match="step limit"):
        actions._continue_reconciled_order(harness.context, order)
    assert processor.call_count == 5


def test_unissued_orders_are_recorded_as_failures(harness: RoutineHarness) -> None:
    harness.new_order.return_value = AcmeOrder(id=100, x509_certificate_id=None)
    actions.routine__order_missing(
        harness.context, {}, create_public_server=harness.factory
    )
    assert harness.counts() == (0, 3)
    cast(Mock, harness.context.pyramid_transaction_rollback).assert_not_called()
    harness.server.shutdown.assert_called_once()


@pytest.mark.parametrize("already_valid", [False, True])
def test_reconciliation_recovers_unsaved_certificate_without_challenge_server(
    harness: RoutineHarness,
    monkeypatch: pytest.MonkeyPatch,
    already_valid: bool,
) -> None:
    add_order(harness.context, 1, status="valid" if already_valid else "processing")
    harness.context.dbSession.execute(
        sa.update(AcmeOrder)
        .where(AcmeOrder.id == 1)
        .values(certificate_url="https://ca.example/certificate/1")
    )
    harness.context.dbSession.commit()

    def sync(
        ctx: ApiContext, dbAcmeOrder: AcmeOrder, transaction_commit: bool
    ) -> AcmeOrder:
        dbAcmeOrder.acme_status_order_id = model_utils.Acme_Status_Order.from_string(
            "valid"
        )
        return dbAcmeOrder

    def download(
        ctx: ApiContext, dbAcmeOrder: AcmeOrder, transaction_commit: bool
    ) -> AcmeOrder:
        dbAcmeOrder.x509_certificate_id = 1
        return dbAcmeOrder

    downloader = Mock(side_effect=download)
    syncer = Mock(side_effect=sync)
    monkeypatch.setattr(
        actions.actions_acme, "do__AcmeV2_AcmeOrder__acme_server_sync", syncer
    )
    monkeypatch.setattr(
        actions.actions_acme, "do__AcmeV2_AcmeOrder__download_certificate", downloader
    )
    actions.routine__reconcile_blocks(
        harness.context,
        {},
        create_public_server=harness.factory,
        transaction_commit=True,
    )
    assert harness.counts() == (1, 0)
    downloader.assert_called_once()
    harness.factory.assert_not_called()
    actions.routine__reconcile_blocks(
        harness.context,
        {},
        create_public_server=harness.factory,
        transaction_commit=True,
    )
    assert harness.counts() == (0, 0)
    assert syncer.call_count == 1
    assert downloader.call_count == 1


def test_failed_certificate_download_is_retried_on_the_next_run(
    harness: RoutineHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    add_order(harness.context, 1, status="valid")
    harness.context.dbSession.execute(
        sa.update(AcmeOrder).values(certificate_url="https://ca.example/certificate/1")
    )
    harness.context.dbSession.commit()
    monkeypatch.setattr(
        actions.actions_acme, "do__AcmeV2_AcmeOrder__acme_server_sync", Mock()
    )
    downloader = Mock(side_effect=errors.AcmeCommunicationError("download interrupted"))
    monkeypatch.setattr(
        actions.actions_acme, "do__AcmeV2_AcmeOrder__download_certificate", downloader
    )
    for _ in range(2):
        actions.routine__reconcile_blocks(
            harness.context,
            {},
            create_public_server=harness.factory,
            transaction_commit=True,
        )
        assert harness.counts() == (0, 1)
    assert downloader.call_count == 2
    assert cast(Mock, harness.context.pyramid_transaction_rollback).call_count == 2
    harness.factory.assert_not_called()


def test_reconciliation_pages_do_not_skip_rows_as_sync_changes_the_query(
    harness: RoutineHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for identity in range(1, 7):
        add_order(harness.context, identity)
    visited: List[int] = []

    def sync(
        ctx: ApiContext, dbAcmeOrder: AcmeOrder, transaction_commit: bool
    ) -> AcmeOrder:
        visited.append(dbAcmeOrder.id)
        dbAcmeOrder.acme_status_order_id = model_utils.Acme_Status_Order.from_string(
            "valid"
        )
        dbAcmeOrder.x509_certificate_id = 1
        if len(visited) == 1:
            add_order(ctx, 99)  # A new concurrent order is outside this run's fence.
        return dbAcmeOrder

    monkeypatch.setattr(
        actions.actions_acme, "do__AcmeV2_AcmeOrder__acme_server_sync", sync
    )
    actions.routine__reconcile_blocks(
        harness.context,
        {},
        create_public_server=harness.factory,
        transaction_commit=True,
        batch_size=2,
    )
    assert visited == [6, 5, 4, 3, 2, 1]
    assert harness.counts() == (6, 0)
    harness.factory.assert_not_called()


def test_missing_order_limit_is_shared_across_small_batches(
    harness: RoutineHarness,
) -> None:
    actions.routine__order_missing(
        harness.context, {}, create_public_server=harness.factory, batch_size=1, limit=2
    )
    assert harness.counts() == (2, 0)
    assert [call.kwargs["replaces"] for call in harness.new_order.call_args_list] == [
        "backup",
        "primary",
    ]
    harness.server.shutdown.assert_called_once()
