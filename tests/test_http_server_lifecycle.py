from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from peter_sslers.lib import http


@pytest.mark.parametrize("failed_attempts", [0, 1, 2])
def test_readiness_closes_connections_on_success_and_failure(monkeypatch, failed_attempts):
    connections = [Mock() for _ in range(2)]
    for index, connection in enumerate(connections):
        if index < failed_attempts:
            connection.request.side_effect = OSError("not ready")
        connection.getresponse.return_value.status = 200
    factory = Mock(side_effect=connections)
    monkeypatch.setattr(http.client, "HTTPConnection", factory)
    monkeypatch.setattr(http.time, "sleep", Mock())
    result = http.check_server("localhost", 1234, retries=2)
    assert result == (0 if failed_attempts == 2 else 200)
    for connection in connections[:factory.call_count]:
        connection.close.assert_called_once_with()


@pytest.mark.parametrize("ready", [0, 200])
def test_server_wait_shuts_down_only_when_not_ready(monkeypatch, ready):
    monkeypatch.setattr(http, "check_server", Mock(return_value=ready))
    server = SimpleNamespace(adj=SimpleNamespace(host="localhost", port=1234), shutdown=Mock())
    assert http.StopableWSGIServer.wait(server) is bool(ready)
    assert server.shutdown.call_count == (0 if ready else 1)


def test_server_wait_propagates_shutdown_failure(monkeypatch):
    monkeypatch.setattr(http, "check_server", Mock(return_value=0))
    server = SimpleNamespace(
        adj=SimpleNamespace(host="localhost", port=1234),
        shutdown=Mock(side_effect=RuntimeError("shutdown failed")),
    )
    with pytest.raises(RuntimeError, match="shutdown failed"):
        http.StopableWSGIServer.wait(server)
