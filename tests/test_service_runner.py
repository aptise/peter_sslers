"""Local service failures must not hang the suite or leave background processes."""

from pathlib import Path
import subprocess
import sys
from typing import Any
from typing import List
from unittest.mock import Mock

import pytest

from . import _services


def test_verbose_service_does_not_deadlock_on_full_pipes(tmp_path: Path) -> None:
    ready = tmp_path / "ready"
    command = [
        sys.executable,
        "-c",
        "import pathlib,sys,time; sys.stdout.write('x'*1000000); sys.stderr.write('y'*1000000); pathlib.Path(%r).touch(); time.sleep(30)"
        % str(ready),
    ]
    with _services.managed_service(
        command, ready=ready.exists, startup_timeout=5
    ) as process:
        assert process.poll() is None
    assert process.poll() is not None


def test_service_cleanup_on_caller_error(tmp_path: Path) -> None:
    ready = tmp_path / "ready"
    command = [
        sys.executable,
        "-c",
        "import pathlib,time; pathlib.Path(%r).touch(); time.sleep(30)" % str(ready),
    ]
    with pytest.raises(RuntimeError, match="caller failed"):
        with _services.managed_service(
            command, ready=ready.exists, startup_timeout=5
        ) as process:
            raise RuntimeError("caller failed")
    assert process.poll() is not None


def test_early_exit_reports_status_without_dumping_service_output() -> None:
    command = [
        sys.executable,
        "-c",
        "print('secret-from-service-output'); raise SystemExit(7)",
    ]
    with pytest.raises(RuntimeError, match="code 7") as error:
        with _services.managed_service(command, ready=lambda: False, startup_timeout=5):
            pytest.fail("Exited service cannot become ready")
    assert "secret-from-service-output" not in str(error.value)


def test_timeout_and_ready_callback_failure_always_stop_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = subprocess.Popen
    children: List[subprocess.Popen[bytes]] = []

    def start(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        # Capture the real child without altering the service behavior.
        child = original(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(_services.subprocess, "Popen", start)
    with pytest.raises(TimeoutError):
        with _services.managed_service(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            ready=lambda: False,
            startup_timeout=0.15,
        ):
            pytest.fail("Never-ready service cannot start")
    assert children[0].poll() is not None
    with pytest.raises(ValueError, match="readiness failed"):
        with _services.managed_service(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            ready=Mock(side_effect=ValueError("readiness failed")),
            startup_timeout=1,
        ):
            pytest.fail("Readiness callback should fail")
    assert children[1].poll() is not None


@pytest.mark.parametrize("deadline", [-1, 0, float("nan"), float("inf")])
def test_invalid_startup_deadline_is_rejected(deadline: float) -> None:
    with pytest.raises(ValueError, match="startup_timeout"):
        with _services.managed_service(
            ["not-a-binary"], ready=lambda: False, startup_timeout=deadline
        ):
            pytest.fail("Invalid service configuration cannot start")
