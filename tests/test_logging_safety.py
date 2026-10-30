"""Sensitive wire data must not reach either log handlers or audit payloads."""

from __future__ import annotations

import ast
from configparser import ConfigParser
from http.client import HTTPMessage
from io import BytesIO
import json
import logging
import os
from pathlib import Path
import stat
from types import SimpleNamespace
from typing import cast
from typing import TYPE_CHECKING
from unittest.mock import Mock
from urllib.error import HTTPError

import pytest

from peter_sslers import logging_utils
from peter_sslers.lib import acme_v2
from peter_sslers.lib import errors
from peter_sslers.model.objects import OperationsEvent
from peter_sslers.web import db_log_cleanup__tween_factory

if TYPE_CHECKING:
    from pyramid.request import Request

    from peter_sslers.lib.context import ApiContext


CANARY = "never-log-this-secret-52d41c"


@pytest.mark.parametrize(
    "field",
    [
        "password",
        "old.api_key",
        "Authorization",
        "key_pem",
        "keyauthorization",
        "Replay-Nonce",
        "externalAccountBinding",
        "jws",
        "server_response_body",
        "details.token",
    ],
)
def test_nested_secret_fields_are_censored_without_mutating_input(field: str) -> None:
    payload = {
        "v": 1,
        "edit": {
            field: CANARY,
            "private_key.id": 42,
            "private_key_cycle": "single_use",
        },
    }
    original = json.dumps(payload)
    rendered = logging_utils.censor(payload)
    assert CANARY not in json.dumps(rendered)
    assert json.dumps(payload) == original
    assert isinstance(rendered, dict)
    edit = rendered["edit"]
    assert isinstance(edit, dict)
    assert edit["private_key.id"] == 42
    assert edit["private_key_cycle"] == "single_use"


@pytest.mark.parametrize(
    "text",
    [
        "password=" + CANARY,
        "api_key: '" + CANARY + "'",
        "-----BEGIN PRIVATE KEY-----\n" + CANARY + "\n-----END PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----\n" + CANARY,
        "https://user:" + CANARY + "@ca.example/authz/" + CANARY + "?token=" + CANARY,
    ],
)
def test_text_credentials_pem_and_urls_are_censored(text: str) -> None:
    assert CANARY not in logging_utils.censored_text(text)


def test_transport_logs_metadata_only_even_at_debug(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    headers = HTTPMessage()
    headers["Replay-Nonce"] = CANARY
    response = Mock()
    response.headers = headers
    response.getcode.return_value = 200
    response.read.return_value = json.dumps(
        {"unlabeled": CANARY, "status": "valid"}
    ).encode()
    monkeypatch.setattr(acme_v2, "urlopen", Mock(return_value=response))
    with caplog.at_level(logging.DEBUG, logger="peter_sslers.lib.acme_api"):
        _, payload, _ = acme_v2.url_request(
            cast("ApiContext", SimpleNamespace()),
            "https://ca.example/order/" + CANARY,
            post_data=json.dumps(
                {"payload": CANARY, "protected": CANARY, "signature": CANARY}
            ).encode(),
        )
    assert isinstance(payload, dict)
    assert payload["unlabeled"] == CANARY  # Functional protocol data remains intact.
    assert CANARY not in caplog.text
    assert any("status=200" in record.getMessage() for record in caplog.records)
    assert "POST" in caplog.text


def test_server_exception_strings_do_not_reveal_protocol_data() -> None:
    error = errors.AcmeServerError(
        400,
        "https://ca.example/" + CANARY,
        {"detail": CANARY},
        {"Replay-Nonce": CANARY},
    )
    assert CANARY not in str(error)
    assert "400" in str(error)
    assert error.args[2] == {"detail": CANARY}


def test_non_json_errors_do_not_embed_signed_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = HTTPError(
        "https://ca.example/order",
        503,
        "unavailable",
        HTTPMessage(),
        BytesIO(CANARY.encode()),
    )
    monkeypatch.setattr(acme_v2, "urlopen", Mock(side_effect=error))
    with pytest.raises(errors.AcmeServerError) as caught:
        acme_v2.url_request(
            cast("ApiContext", SimpleNamespace()),
            "https://ca.example/order",
            post_data=CANARY.encode(),
        )
    assert CANARY not in str(caught.value)
    assert CANARY not in str(caught.value.args[2])


def test_exception_arguments_and_extra_fields_do_not_leak_to_handlers(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger = logging.getLogger("peter_sslers.lib")
    with caplog.at_level(logging.ERROR, logger=logger.name):
        try:
            raise ValueError(CANARY)
        except ValueError:
            logger.exception("Operation failed", extra={"api_key": CANARY})
    record = caplog.records[-1]
    assert record.exc_info is None
    assert CANARY not in repr(record.__dict__)
    assert "ValueError" in caplog.text
    assert "Operation failed" in caplog.text


def test_unformattable_records_fail_closed(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("peter_sslers.lib")
    with caplog.at_level(logging.ERROR, logger=logger.name):
        logger.error("numeric=%d", object(), extra={"api_key": CANARY})
    assert CANARY not in repr(caplog.records[-1].__dict__)
    assert "OMITTED" in caplog.text


def test_cycles_depth_and_control_characters_are_bounded() -> None:
    cyclic: list[object] = []
    cyclic.append(cyclic)
    assert logging_utils.censor(cyclic) == ["[CYCLE]"]
    assert "\n" not in logging_utils.censored_text("untrusted\nlog entry")
    assert len(cast(str, logging_utils.censor("x" * 10000))) < 4200


def test_operations_payloads_are_censored_and_never_stale() -> None:
    event = OperationsEvent(event_payload='{"v":1,"counter":1}')
    old = event.event_payload_json
    old["counter"] = 200
    assert event.event_payload_json["counter"] == 1
    event.set_event_payload({"v": 1, "counter": 2, "nested": {"api_key": CANARY}})
    assert event.event_payload_json["counter"] == 2
    assert CANARY not in event.event_payload
    event.event_payload = json.dumps({"v": 1, "counter": 3, "password": CANARY})
    assert event.event_payload_json["counter"] == 3
    assert CANARY not in event.event_payload


@pytest.mark.parametrize("raw", ["[]", "null", '"value"', "broken"])
def test_operations_payloads_require_json_objects(raw: str) -> None:
    with pytest.raises(ValueError):
        OperationsEvent(event_payload=raw)


def test_command_request_does_not_change_global_logging() -> None:
    names = ("", "peter_sslers", "requests", "sqlalchemy")
    before = [
        (logging.getLogger(name).level, logging.getLogger(name).propagate)
        for name in names
    ]
    response = Mock()
    handler = Mock(return_value=response)
    request = cast("Request", SimpleNamespace(environ={"paste.command_request": True}))
    assert db_log_cleanup__tween_factory(handler, None)(request) is response
    assert before == [
        (logging.getLogger(name).level, logging.getLogger(name).propagate)
        for name in names
    ]


def test_log_files_are_private_bounded_and_do_not_follow_symlinks(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "audit.log"
    handler = logging_utils.SecureRotatingFileHandler(
        destination, maxBytes=80, backupCount=2, encoding="utf-8"
    )
    try:
        for _ in range(8):
            handler.emit(
                logging.LogRecord("test", logging.INFO, __file__, 1, "x" * 40, (), None)
            )
    finally:
        handler.close()
    files = list(tmp_path.glob("audit.log*"))
    assert len(files) == 3
    for path in files:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    if hasattr(os, "O_NOFOLLOW"):
        link = tmp_path / "linked.log"
        link.symlink_to(destination)
        with pytest.raises(OSError):
            logging_utils.SecureRotatingFileHandler(link)


@pytest.mark.parametrize(
    "path",
    [
        "tests/test_configuration/config.ini",
        "example_configs/development.ini",
        "example_configs/staging.ini",
        "example_configs/production.ini",
    ],
)
def test_shipped_logging_config_avoids_duplicates_and_uses_private_rotating_files(
    path: str,
) -> None:
    config = ConfigParser(interpolation=None)
    config.read(path)
    assert config.getboolean("logger_peter_sslers", "propagate") is False
    assert config.getboolean("logger_acme_api", "propagate") is False
    assert config.get("logger_peter_sslers", "handlers").strip()
    names = [name for name in config.sections() if name.startswith("handler_file")]
    assert len(names) >= 2
    for name in names:
        assert (
            config.get(name, "class")
            == "peter_sslers.logging_utils.SecureRotatingFileHandler"
        )
        args = ast.literal_eval(config.get(name, "args"))
        assert args[2:4] == (10485760, 5)


def test_audit_payload_preserves_all_subject_ids_while_text_logs_are_bounded() -> None:
    identities = list(range(500))
    event = OperationsEvent(event_payload='{"v":1}')
    event.set_event_payload({"v": 1, "domain.ids": identities})
    assert event.event_payload_json["domain.ids"] == identities
    assert (
        len(cast(list[object], logging_utils.censor(identities)))
        == logging_utils.MAX_ITEMS
    )


@pytest.mark.parametrize(
    "message",
    [
        "Authorization: Bearer " + CANARY,
        "Authorization: Basic " + CANARY,
        "Cookie: one=" + CANARY + "; two=" + CANARY,
        "raw body: {'unlabeled': '" + CANARY + "'}",
    ],
)
def test_formatted_headers_and_body_reprs_are_censored(message: str) -> None:
    assert CANARY not in logging_utils.censored_text(message)


def test_unknown_protocol_fields_are_never_dumped_as_python_logging_arguments(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger = logging.getLogger("peter_sslers.lib")
    with caplog.at_level(logging.WARNING, logger=logger.name):
        logger.warning("Diagnostic body: %s", {"unknown-field": CANARY})
        logger.warning((400, {"unknown-field": CANARY}))
    assert CANARY not in repr([record.__dict__ for record in caplog.records])


@pytest.mark.parametrize(
    "name",
    [
        "urllib3.connectionpool",
        "requests",
        "pyacmedns",
        "sqlalchemy.engine.Engine",
        "cert_utils",
    ],
)
def test_dependency_debug_records_and_warning_details_cannot_leak(
    name: str, caplog: pytest.LogCaptureFixture
) -> None:
    logging_utils.install_logging_safety(handlers=True)
    logger = logging.getLogger(name)
    with caplog.at_level(logging.DEBUG, logger=name):
        logger.debug("GET /private/" + CANARY + " HTTP/1.1")
        logger.warning("unlabeled " + CANARY)
    assert CANARY not in repr([record.__dict__ for record in caplog.records])
    assert not any(
        record.levelno < logging.WARNING
        for record in caplog.records
        if record.name == name
    )


def test_cached_formatter_message_cannot_bypass_censoring() -> None:
    record = logging.LogRecord(
        "peter_sslers", logging.INFO, __file__, 1, "password=never-print", (), None
    )
    record.message = record.getMessage()
    assert logging_utils.CensoringFilter().filter(record)
    assert "never-print" not in record.getMessage()
    assert "never-print" not in str(record.__dict__.get("message", ""))
