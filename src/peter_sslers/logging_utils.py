"""Censored logging primitives; this module must not import application models."""

from __future__ import annotations

from io import BufferedWriter
from io import FileIO
from io import TextIOWrapper
from itertools import islice
import json
import logging
from logging.handlers import RotatingFileHandler
import math
import os
import re
import traceback
from typing import Dict
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple
from typing import Union
from urllib.parse import urlsplit

from typing_extensions import TypeAlias

LogValue: TypeAlias = Union[
    None, bool, int, float, str, List["LogValue"], Dict[str, "LogValue"]
]
REDACTED = "[REDACTED]"
MAX_TEXT = 4096
MAX_ITEMS = 100
MAX_DEPTH = 12
_SENSITIVE = frozenset(
    (
        "password",
        "passwd",
        "passphrase",
        "authorization",
        "proxyauthorization",
        "cookie",
        "setcookie",
        "apikey",
        "xapikey",
        "keypem",
        "privatekeypem",
        "privatekey",
        "accountkey",
        "secret",
        "clientsecret",
        "hmac",
        "hmackey",
        "externalaccountbinding",
        "token",
        "keyauthorization",
        "dnskeyauthorization",
        "signature",
        "replaynonce",
        "nonce",
        "jws",
        "protected",
        "payload",
        "postdata",
        "respdata",
        "rawresponse",
        "serverresponsebody",
        "detail",
        "message",
        "error",
        "reason",
        "username",
        "credentials",
        "key",
        "txt",
        "keyauth",
    )
)
_PEM = re.compile(
    r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----.*?(?:-----END \1-----|\Z)", re.S
)
_URL = re.compile(r"https?://[^\s<>\"']+", re.I)
_LABELED = re.compile(
    r"(?i)(\b(?:password|passwd|passphrase|api[_-]?key|x-api-key|secret|token|"
    r"key[_-]?authorization|replay-nonce|authorization|cookie)\b\s*[:=]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;}]+)"
)
_HEADER = re.compile(
    r"(?im)(\b(?:authorization|proxy-authorization|cookie|set-cookie)\b[\"']?\s*:\s*)[^\r\n]+"
)
_STRUCTURED_TEXT = re.compile(r"\{.*\}")
_PATH_WORDS = frozenset(
    (
        "acme",
        "v1",
        "v2",
        "dir",
        "directory",
        "new-nonce",
        "new-account",
        "new-order",
        "revoke-cert",
        "key-change",
        "renewal-info",
        "newNonce",
        "newAccount",
        "newOrder",
        "revokeCert",
        "keyChange",
        "renewalInfo",
        "order",
        "orders",
        "authz",
        "auth",
        "acct",
        "account",
        "accounts",
        "cert",
        "certificate",
        "challenge",
        "chall",
        "finalize",
        "api",
    )
)
_PACKAGE_LOGGERS = (
    "peter_sslers",
    "peter_sslers.lib",
    "peter_sslers.lib.db",
    "peter_sslers.lib.acme_api",
    "peter_sslers.model",
    "peter_sslers.web",
    "cert_utils",
)
_MANAGED_PREFIXES = (
    "peter_sslers",
    "cert_utils",
    "pyacmedns",
    "urllib3",
    "requests",
    "sqlalchemy",
)
_STANDARD_RECORD_KEYS = frozenset(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__
)


def censored_url(url: str) -> str:
    """Keep the service and known operation names, never credentials or IDs."""
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return REDACTED
        host = parsed.hostname
        if ":" in host:
            host = "[%s]" % host
        port = ":%s" % parsed.port if parsed.port is not None else ""
        path = "/".join(
            segment if segment in _PATH_WORDS else REDACTED
            for segment in parsed.path.split("/")
            if segment
        )
        return "%s://%s%s%s" % (parsed.scheme, host, port, "/" + path if path else "")
    except (TypeError, ValueError):
        return REDACTED


def sensitive_field(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    if any(
        part in normalized
        for part in ("password", "passwd", "passphrase", "apikey", "secret", "token")
    ):
        return True
    if normalized.endswith(("keyauthorization", "replaynonce", "signature")):
        return True
    # ID/strategy metadata is intentionally retained; it is not private key data.
    if normalized.endswith(("id", "ids", "cycle", "technology", "strategy")):
        return False
    return normalized in _SENSITIVE or any(
        normalized.endswith(part)
        for part in (
            "password",
            "passwd",
            "passphrase",
            "apikey",
            "keypem",
            "secret",
            "token",
        )
    )


def censored_text(value: str) -> str:
    value = _PEM.sub(REDACTED, value)
    value = _URL.sub(lambda match: censored_url(match.group()), value)
    value = _HEADER.sub(lambda match: match.group(1) + REDACTED, value)
    value = _STRUCTURED_TEXT.sub("[STRUCTURED DATA OMITTED]", value)
    value = _LABELED.sub(lambda match: match.group(1) + REDACTED, value)
    value = re.sub(
        r"[\x00-\x1f\x7f]", lambda match: "\\x%02x" % ord(match.group()), value
    )
    if len(value) > MAX_TEXT:
        value = value[:MAX_TEXT] + "[TRUNCATED]"
    return value


def censor(
    value: object,
    *,
    field: str = "",
    max_items: Optional[int] = MAX_ITEMS,
    _depth: int = 0,
    _seen: Optional[Set[int]] = None,
) -> LogValue:
    """Copy logging data without mutating its functional caller-owned value."""
    if sensitive_field(field):
        return REDACTED
    if _depth >= MAX_DEPTH:
        return "[DEPTH LIMIT]"
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else "[NON-FINITE NUMBER]"
    if isinstance(value, str):
        if value.lstrip().startswith(("{", "[")) and len(value) <= MAX_TEXT:
            try:
                decoded = json.loads(value)
            except (ValueError, RecursionError):
                pass
            else:
                return json.dumps(
                    censor(decoded, max_items=max_items, _depth=_depth + 1),
                    sort_keys=True,
                )
        return censored_text(value)
    if isinstance(value, BaseException):
        return type(value).__name__
    if isinstance(value, bytes):
        return "[BINARY DATA OMITTED]"
    if not isinstance(value, (dict, list, tuple, set)):
        return "[OBJECT OMITTED]"
    seen = set() if _seen is None else _seen
    if id(value) in seen:
        return "[CYCLE]"
    seen.add(id(value))
    try:
        if isinstance(value, dict):
            result: Dict[str, LogValue] = {}
            for index, (key, item) in enumerate(value.items()):
                if max_items is not None and index >= max_items:
                    result["[TRUNCATED]"] = True
                    break
                safe_key = (
                    censored_text(key) if isinstance(key, str) else "[NON-TEXT KEY]"
                )
                result[safe_key] = censor(
                    item,
                    field=key if isinstance(key, str) else "",
                    max_items=max_items,
                    _depth=_depth + 1,
                    _seen=seen,
                )
            return result
        values = list(value) if max_items is None else list(islice(value, max_items))
        return [
            censor(item, max_items=max_items, _depth=_depth + 1, _seen=seen)
            for item in values
        ]
    finally:
        seen.remove(id(value))


class CensoringFilter(logging.Filter):
    """Sanitize owned records before any handler can retain or format them."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not any(
            record.name == prefix or record.name.startswith(prefix + ".")
            for prefix in _MANAGED_PREFIXES
        ):
            return True
        try:
            if record.name.startswith(
                ("sqlalchemy", "urllib3", "requests", "pyacmedns", "cert_utils")
            ):
                if record.levelno < logging.WARNING:
                    return False
                record.msg = "Client diagnostic omitted (may contain credentials)"
            elif isinstance(record.msg, BaseException):
                record.msg = type(record.msg).__name__
            elif isinstance(record.msg, str):
                if record.args:
                    arguments: Union[Dict[str, LogValue], Tuple[LogValue, ...]]
                    if isinstance(record.args, dict):
                        arguments = {
                            key: (
                                "[STRUCTURED DATA OMITTED]"
                                if isinstance(value, (dict, list, tuple, set, bytes))
                                else censor(value, field=key)
                            )
                            for key, value in record.args.items()
                        }
                    else:
                        arguments = tuple(
                            (
                                "[STRUCTURED DATA OMITTED]"
                                if isinstance(item, (dict, list, tuple, set, bytes))
                                else censor(item)
                            )
                            for item in record.args
                        )
                    record.msg = censored_text(record.msg % arguments)
                else:
                    record.msg = censored_text(record.msg)
            else:
                record.msg = "[NON-TEXT LOG MESSAGE OMITTED]"
            record.args = ()
            record.__dict__.pop("message", None)
            if record.exc_info:
                exception_type, _, tb = record.exc_info
                frames = traceback.extract_tb(tb)
                record.exc_text = (
                    "Traceback (exception values omitted):\n"
                    + "\n".join(
                        '  File "%s", line %s, in %s'
                        % (frame.filename, frame.lineno, frame.name)
                        for frame in frames
                    )
                    + "\n"
                    + (exception_type.__name__ if exception_type else "Exception")
                )
                record.exc_info = None
            elif record.exc_text:
                record.exc_text = censored_text(record.exc_text)
            if record.stack_info:
                record.stack_info = "[STACK SOURCE OMITTED]"
            for key in (
                set(record.__dict__) - _STANDARD_RECORD_KEYS - {"message", "asctime"}
            ):
                record.__dict__[key] = censor(record.__dict__[key], field=key)
        except Exception:
            # A logging failure must never fall back to printing an unsafe repr.
            record.msg = "[UNFORMATTABLE LOG RECORD OMITTED]"
            record.__dict__.pop("message", None)
            record.args = ()
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
            for key in (
                set(record.__dict__) - _STANDARD_RECORD_KEYS - {"message", "asctime"}
            ):
                record.__dict__[key] = REDACTED
        return True


_FILTER = CensoringFilter()


def install_logging_safety(*, handlers: bool = False) -> None:
    """Keep host logging configuration; install censoring at record boundaries."""
    for name in _PACKAGE_LOGGERS:
        logger = logging.getLogger(name)
        if _FILTER not in logger.filters:
            logger.addFilter(_FILTER)
    if handlers:
        targets = [logging.getLogger()] + [
            value
            for value in logging.Logger.manager.loggerDict.values()
            if isinstance(value, logging.Logger)
        ]
        for logger in targets:
            for handler in logger.handlers:
                if _FILTER not in handler.filters:
                    handler.addFilter(_FILTER)


class SecureRotatingFileHandler(RotatingFileHandler):
    """Bounded log files created privately and never opened through symlinks."""

    def _open(self) -> TextIOWrapper[BufferedWriter]:
        if self.mode not in ("a", "w"):
            raise ValueError("Private log files support append/write text modes only")
        mode = "a" if self.mode == "a" else "w"
        flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        flags |= os.O_APPEND if mode == "a" else os.O_TRUNC
        descriptor = os.open(self.baseFilename, flags, 0o600)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            return TextIOWrapper(
                BufferedWriter(FileIO(descriptor, "wb")),
                encoding=self.encoding,
                errors=self.errors,
            )
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
