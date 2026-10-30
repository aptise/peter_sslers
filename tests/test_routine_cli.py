"""CLI limits are shared across stages and overlapping invocations are harmless."""

from contextlib import nullcontext
from types import ModuleType
from types import SimpleNamespace
from typing import Optional
from unittest.mock import Mock

import pytest

from peter_sslers.lib.errors import RoutineAlreadyRunning
from peter_sslers.web.scripts import routine__automatic_orders as automatic
from peter_sslers.web.scripts import routine__reconcile_blocks as reconcile


@pytest.mark.parametrize(
    "limit, completed, remaining",
    [(0, 0, None), (1, 1, None), (3, 1, 2), (None, 5, None)],
)
def test_automatic_cli_preserves_zero_and_shares_limit(
    monkeypatch: pytest.MonkeyPatch,
    limit: Optional[int],
    completed: int,
    remaining: Optional[int],
) -> None:
    context = Mock()
    receipt = SimpleNamespace(count_records_processed=completed, as_json={})
    missing = Mock(return_value=receipt)
    renewing = Mock(return_value=receipt)
    monkeypatch.setattr(automatic, "validate_config_uri", lambda value: value)
    monkeypatch.setattr(automatic, "get_appsettings", Mock(return_value={}))
    monkeypatch.setattr(automatic, "new_scripts_setup", Mock(return_value=context))
    monkeypatch.setattr(automatic, "execution_lock", lambda *args: nullcontext())
    monkeypatch.setattr(automatic.lib_db.actions, "routine__order_missing", missing)
    monkeypatch.setattr(automatic.lib_db.actions, "routine__renew_expiring", renewing)
    arguments = ["routine", "config.ini", "batch-size=7", "dry-run=true"]
    if limit is not None:
        arguments.append("limit=%s" % limit)
    automatic.main(arguments)
    assert missing.call_args.kwargs["limit"] == limit
    assert missing.call_args.kwargs["batch_size"] == 7
    if limit is not None and completed >= limit:
        renewing.assert_not_called()
    else:
        assert renewing.call_args.kwargs["limit"] == remaining
        assert renewing.call_args.kwargs["batch_size"] == 7
    context.pyramid_transaction_commit.assert_called_once()
    context.dbSession.close.assert_called_once()


@pytest.mark.parametrize("module", [automatic, reconcile])
def test_busy_cli_does_not_start_work_and_releases_session(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    module: ModuleType,
) -> None:
    context = Mock()
    monkeypatch.setattr(module, "validate_config_uri", lambda value: value)
    monkeypatch.setattr(module, "get_appsettings", Mock(return_value={}))
    monkeypatch.setattr(module, "new_scripts_setup", Mock(return_value=context))
    monkeypatch.setattr(
        module, "execution_lock", Mock(side_effect=RoutineAlreadyRunning("busy"))
    )
    module.main(["routine", "config.ini"])
    assert "Skipped:" in capsys.readouterr().out
    context.pyramid_transaction_rollback.assert_called_once()
    context.pyramid_transaction_commit.assert_not_called()
    context.dbSession.close.assert_called_once()
