# stdlib
import base64
import datetime
import json
import logging
from typing import Any
from typing import Dict
from typing import Optional
from typing import TYPE_CHECKING

# pypi
from pyramid.decorator import reify
import pyramid_tm
import requests
import transaction
import zope.sqlalchemy
from zope.sqlalchemy import mark_changed

# local
from . import config_utils
from .. import USER_AGENT

if TYPE_CHECKING:
    from pyramid.request import Request
    from sqlalchemy.orm.session import Session
    from .config_utils import ApplicationSettings

# ==============================================================================


PLACEHOLDER_TEXT__KEY = "*placeholder-key*"
PLACEHOLDER_TEXT__SHA1 = "*placeholder-sha1*"


log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


# ------------------------------------------------------------------------------


def url_to_server(url: str) -> str:
    url = url.lower()
    if url[:8] == "https://":
        url = url[8:]
    elif url[:7] == "http://":
        url = url[7:]
    url = url.split("/")[0]
    return url


def urlify(as_dict: Dict) -> str:
    _json_data = json.dumps(as_dict)
    _encoded_bytes = _json_data.encode("utf-8")
    _encoded = base64.b64encode(_encoded_bytes).decode("utf-8")
    return _encoded


def unurlify(_encoded: str) -> Dict:
    try:
        _decoded = base64.b64decode(_encoded)
        _json_data = json.loads(_decoded)
    except Exception as exc:
        log.debug(exc)
        _json_data = {}
    return _json_data


def ari_timestamp_to_python(timestamp: str) -> datetime.datetime:
    if "." in timestamp:
        # are these nanoseconds?
        _components = timestamp.split(".")
        _precision = []
        for char in _components[1]:
            if char.isdigit():
                _precision.append(char)
            else:
                break
        if len(_precision) > 6:
            _tz = _components[1][len(_precision) :]
            timestamp = _components[0] + "." + "".join(_precision[:6]) + _tz
        if timestamp[-1].isdigit() or (
            timestamp[-1] == "Z" and timestamp[-2].isdigit()
        ):
            return datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
        return datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%Z")
    if timestamp[-1].isdigit() or (timestamp[-1] == "Z" and timestamp[-2].isdigit()):
        return datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S%z")
    return datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S%Z")


def new_BrowserSession() -> requests.Session:
    sess = requests.Session()
    sess.headers.update({"User-Agent": USER_AGENT})
    return sess


timedelta_ARI_CHECKS_TIMELY = datetime.timedelta(days=3000)

# ------------------------------------------------------------------------------


def new_event_payload_dict() -> Dict:
    return {"v": 1}


# ------------------------------------------------------------------------------


def issuer_to_endpoint(
    cert_data: Optional[Dict] = None,  # via parse_cert
    sock_data: Optional[Dict] = None,  # via socket analysis
) -> Optional[str]:
    if not any((cert_data, sock_data)) or all((cert_data, sock_data)):
        raise ValueError("submit `cert_data` OR `sock_data`")
    if cert_data:
        _issuer = cert_data["issuer"].split("\n")
        if len(_issuer) > 1:
            if _issuer[1] == "O=Let's Encrypt":
                return "https://acme-v02.api.letsencrypt.org/directory"
        return None
    if TYPE_CHECKING:
        assert sock_data is not None
    if len(sock_data["issuer"]) > 1:
        if sock_data["issuer"][1][0][1] == "Let's Encrypt":
            return "https://acme-v02.api.letsencrypt.org/directory"
    return None


# ------------------------------------------------------------------------------


class ApiContext(object):
    """
    A context object
    API Calls can rely on this object to assist in logging.

    This implements an interface that guarantees several properties.  Substitutes may be used-

    :param request: - Pyramid `request` object
    :param timestamp: `datetime.datetime.now(datetime.timezone.utc)`
    :param dbSession: - SqlAlchemy `Session` object
    :param dbOperationsEvent: - the top OperationsEvent object for the active `request`, if any
    """

    dbOperationsEvent: Optional[Any] = None
    dbSession: "Session"
    timestamp: datetime.datetime
    request: Optional["Request"] = None
    config_uri: Optional[str] = None
    application_settings: Optional["ApplicationSettings"] = None

    def __init__(
        self,
        request: Optional["Request"] = None,
        dbOperationsEvent=None,
        dbSession: Optional["Session"] = None,
        timestamp: Optional[datetime.datetime] = None,
        config_uri: Optional[str] = None,
        application_settings: Optional["ApplicationSettings"] = None,
    ):
        self.request = request
        self.dbOperationsEvent = dbOperationsEvent
        if dbSession:
            self.dbSession = dbSession
        if timestamp is None:
            timestamp = datetime.datetime.now(datetime.timezone.utc)
        self.timestamp = timestamp
        self.config_uri = config_uri
        self.application_settings = application_settings

    @property
    def transaction_manager(self) -> "transaction.manager":
        # this is the pyramid_tm interface
        if self.request is None:
            raise ValueError("`self.request` not set")
        return self.request.tm

    def pyramid_transaction_commit(self) -> None:
        """this method does some ugly stuff to commit the pyramid transaction"""
        # mark_changed is oblivious to the `keep_session` we created the session with
        mark_changed(self.dbSession, keep_session=True)
        self.transaction_manager.commit()
        self.transaction_manager.begin()

    def pyramid_transaction_rollback(self) -> None:
        """this method does some ugly stuff to rollback the pyramid transaction"""
        self.transaction_manager.abort()
        self.transaction_manager.begin()


# ------------------------------------------------------------------------------


class MockedRegistry(object):

    settings: Dict

    def __init__(self, settings: Dict):
        self.settings = settings


class RequestCommandline(object):

    dbSession: "Session"
    api_context: "ApiContext"
    environ: Dict
    registry: MockedRegistry

    def __init__(
        self,
        dbSession: "Session",
        transaction_manager: "transaction.manager" = transaction.manager,
        application_settings: Optional[config_utils.ApplicationSettings] = None,
        settings: Optional[Dict] = None,
    ):
        # the normal app constructs the request with this; we must inject it
        dbSession.info["request"] = self

        zope.sqlalchemy.register(
            dbSession, transaction_manager=transaction_manager, keep_session=True
        )

        self.dbSession = dbSession

        if settings is None:
            settings = {}
        self.registry = MockedRegistry(settings)

        # do we need a cleanup registered here?

        self.environ = {
            "scheme": "http",
            "HTTP_HOST": "127.0.0.1",
        }

    def _cleanup(self):
        self.dbSession.close()

    @reify
    def tm(self):
        # request.environ.get('tm.manager')
        # request.registry.settings.get('tm.manager_hook')
        return pyramid_tm.create_tm(self)

    @property
    def api_host(self) -> str:
        from ..web.lib.handler import api_host

        return api_host(self)

    @property
    def admin_url(self) -> str:
        from ..web.lib.handler import admin_url

        return admin_url(self)
