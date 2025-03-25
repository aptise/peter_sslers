# stdlib
import base64
import datetime
import functools
import json
import logging
import re
from typing import Dict
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING

# pypi
import cert_utils
from pyramid.decorator import reify
import pyramid_tm
import requests
import tldextract
import transaction
import zope.sqlalchemy

# local
from . import config_utils
from .. import USER_AGENT

if TYPE_CHECKING:
    from sqlalchemy.orm.session import Session
    from .context import ApiContext
    from ..model.objects import CertificateCAPreferencePolicy

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


"""
#  https://github.com/psf/requests/issues/2011
class MyHTTPAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, timeout=None, *args, **kwargs):
        self.timeout = timeout
        super(MyHTTPAdapter, self).__init__(*args, **kwargs)

    def send(self, *args, **kwargs):
        kwargs['timeout'] = self.timeout
        return super(MyHTTPAdapter, self).send(*args, **kwargs)


sess = requests.Session()
# sess.mount("http://", MyHTTPAdapter(timeout=10))
# sess.mount("https://", MyHTTPAdapter(timeout=10))
"""


def new_BrowserSession() -> requests.Session:
    sess = requests.Session()
    _connect_timeout_s: float = 1.0
    _read_timeout_s: float = 6.0
    _timeout = (_connect_timeout_s, _read_timeout_s)
    for method in ("get", "options", "head", "post", "put", "patch", "delete"):
        setattr(
            sess, method, functools.partial(getattr(sess, method), timeout=_timeout)
        )
    sess.headers.update({"User-Agent": USER_AGENT})
    return sess


# ------------------------------------------------------------------------------


def new_event_payload_dict() -> Dict:
    return {"v": 1}


# 64chars, first must be a letter
RE_websafe = re.compile(r"^([a-zA-Z][a-zA-Z0-9\-]{1,63})$")


def validate_websafe_slug(slug: str) -> bool:
    if RE_websafe.match(slug):
        return True
    return False


def normalize_unique_text(text: str) -> str:
    if text:
        return text.strip().lower()
    return text


# 64chars
RE_label = re.compile(r"^([a-zA-Z0-9\-\.\_]{1,64})$")


def validate_label(label: str) -> bool:
    if RE_label.match(label):
        return True
    return False


def apply_domain_template(
    template: str,
    domain_name: str,
    reverse_domain_name: str,
) -> str:
    template = template.replace("{DOMAIN}", domain_name).replace(
        "{NIAMOD}", reverse_domain_name
    )
    return template


def validate_label_template(template: str) -> Tuple[bool, Optional[str]]:
    if ("{DOMAIN}" not in template) and ("{NIAMOD}" not in template):
        return False, "Missing {DOMAIN} or {NIAMOD} marker"
    _expanded = apply_domain_template(template, "example.com", "com.example")
    _normalized = normalize_unique_text(_expanded)
    if not validate_label(_normalized):
        return False, "the `label_template` is not compliant"
    return True, None


def validate_domains_template(
    template: str,
    require_markers: bool = False,
) -> Tuple[Optional[str], Optional[str]]:
    """
    validates and normalizes the template
    return value is a tuple:
        Optional[NormalizedTemplate], Optional[ErrorMessage]
    Success will return:
        [String, None]
    Failure will yield:
        [None, String]
    """
    if not template:
        return None, "Nothing submitted"
    # remove any spaces
    template = template.replace(" ", "")

    if require_markers:
        if ("{DOMAIN}" not in template) and ("{NIAMOD}" not in template):
            return None, "Missing {DOMAIN} or {NIAMOD} marker"

    templated = apply_domain_template(template, "example.com", "com.example")

    ds = [i.strip() for i in templated.split(",")]
    try:
        cert_utils.validate_domains(ds)
    except Exception:
        return None, "Invalid Domain(s) Detected"
    normalized = templated
    return normalized, None


# ------------------------------------------------------------------------------


def parse_domain_name(domain: str) -> Tuple[str, str]:
    # parses a domain into the result.domain and result.suffix
    result = tldextract.extract(domain)
    return result.domain, result.suffix


def reverse_domain_name(domain: str) -> str:
    result = tldextract.extract(domain)
    stack = [result.suffix, result.domain]
    if result.subdomain:
        stack.extend(reversed(result.subdomain.split(".")))
    return ".".join(stack)


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


class MockedRegistry(object):

    settings: Dict

    def __init__(self, settings: Dict):
        self.settings = settings


class RequestCommandline(object):

    dbSession: "Session"
    api_context: "ApiContext"
    environ: Dict
    registry: MockedRegistry
    application_settings: config_utils.ApplicationSettings

    def __init__(
        self,
        dbSession: "Session",
        application_settings: config_utils.ApplicationSettings,
        transaction_manager: "transaction.manager" = transaction.manager,
        settings: Optional[Dict] = None,
    ):
        # the normal app constructs the request with this; we must inject it
        dbSession.info["request"] = self

        self.dbSession = dbSession
        self.application_settings = application_settings

        zope.sqlalchemy.register(
            dbSession, transaction_manager=transaction_manager, keep_session=True
        )

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

    @reify
    def dbCertificateCAPreferencePolicy(self) -> "CertificateCAPreferencePolicy":
        from ..web.lib.handler import load_CertificateCAPreferencePolicy_global

        return load_CertificateCAPreferencePolicy_global(self)


def new_scripts_setup(config_uri: str, options: Optional[dict] = None) -> "ApiContext":
    from .context import ApiContext
    from pyramid.paster import get_appsettings
    from pyramid.paster import setup_logging

    from .config_utils import ApplicationSettings
    from ..model.meta import Base
    from ..web.models import get_engine
    from ..web.models import get_session_factory

    """
    Alt Pattern:

        with transaction.manager:
            dbSession = get_tm_session(None, session_factory, transaction.manager)
            ctx = ApiContext()
            ...
            tasks
            ...
        transaction.commit()
    """

    setup_logging(config_uri)
    settings = get_appsettings(config_uri, options=options)

    engine = get_engine(settings)

    Base.metadata.create_all(engine)

    session_factory = get_session_factory(engine)

    application_settings = ApplicationSettings(config_uri)
    application_settings.from_settings_dict(settings)

    dbSession = session_factory()
    # dbSession = get_tm_session(None, session_factory, transaction.manager)

    ctx = ApiContext(
        dbSession=dbSession,
        request=RequestCommandline(
            dbSession,
            application_settings=application_settings,
        ),
        config_uri=config_uri,
        application_settings=application_settings,
    )
    assert ctx.request
    ctx.request.api_context = ctx

    return ctx
