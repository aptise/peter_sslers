"""Local integration services with bounded readiness and unconditional cleanup."""

from contextlib import contextmanager
import math
import os
from pathlib import Path
import subprocess
import tempfile
import time
from typing import Callable
from typing import Iterator
from typing import Mapping
from typing import Optional
from typing import Sequence


@contextmanager
def managed_service(
    command: Sequence[str],
    *,
    ready: Callable[[], bool],
    env: Optional[Mapping[str, str]] = None,
    log_path: Optional[Path] = None,
    startup_timeout: float = 30,
    shutdown_timeout: float = 5,
    ready_log_marker: Optional[bytes] = None,
) -> Iterator[subprocess.Popen[bytes]]:
    """No pipe reads, unbounded startup loops, leaked services, or raw log dumps."""
    if not math.isfinite(startup_timeout) or startup_timeout <= 0:
        raise ValueError("startup_timeout must be positive and finite")
    with tempfile.TemporaryDirectory(prefix="sslers-service-") as directory:
        destination = log_path or Path(directory) / "service.log"
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                env=env,
            )
            try:
                deadline = time.monotonic() + startup_timeout
                while True:
                    status = process.poll()
                    if status is not None:
                        raise RuntimeError(
                            "Test service exited before readiness (code %s)" % status
                        )
                    with destination.open("rb") as captured:
                        announced = (
                            ready_log_marker is None
                            or ready_log_marker in captured.read(256 * 1024)
                        )
                    if announced and ready():
                        if process.poll() is not None:
                            raise RuntimeError(
                                "Test service exited during readiness check"
                            )
                        break
                    if time.monotonic() >= deadline:
                        raise TimeoutError(
                            "Test service did not become ready within its startup deadline"
                        )
                    time.sleep(0.05)
                yield process
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=shutdown_timeout)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=shutdown_timeout)
