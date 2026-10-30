"""CLI preview must roll back; explicit apply must persist censored rows."""

from contextlib import nullcontext
import json
from types import SimpleNamespace
from typing import cast
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from peter_sslers.web.scripts import audit_events
from . import test_audit_maintenance

if TYPE_CHECKING:
    from peter_sslers.lib.context import ApiContext

session = test_audit_maintenance.session


@pytest.mark.parametrize("apply", [False, True])
def test_cli_preview_and_apply_use_real_transactions(
    session: Session,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    apply: bool,
) -> None:
    context = cast(
        "ApiContext",
        SimpleNamespace(
            dbSession=session,
            pyramid_transaction_commit=session.commit,
            pyramid_transaction_rollback=session.rollback,
        ),
    )
    setup = Mock(return_value=context)
    monkeypatch.setattr(audit_events, "new_scripts_setup", setup)
    monkeypatch.setattr(audit_events, "validate_config_uri", lambda value: value)
    monkeypatch.setattr(audit_events, "execution_lock", lambda *args: nullcontext())
    arguments = ["audit_events", "config.ini", "mode=sanitize", "limit=1"]
    if apply:
        arguments.append("apply=true")
    audit_events.main(arguments)
    setup.assert_called_once_with(
        "config.ini",
        options={
            "mode": "sanitize",
            "limit": "1",
            **({"apply": "true"} if apply else {}),
        },
        create_schema=False,
    )
    report = json.loads(capsys.readouterr().out)
    assert report["apply"] is apply
    assert report["changed"] == int(apply)
    raw = session.execute(
        sa.text("SELECT event_payload FROM operations_event WHERE id=1")
    ).scalar_one()
    assert ("old-secret" in raw) is (not apply)
