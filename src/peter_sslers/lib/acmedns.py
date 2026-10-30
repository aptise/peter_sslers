"""Bounded acme-dns adapter that never embeds credentials in exceptions."""

import json
import logging
import math
import time
from typing import Dict
from typing import List
from typing import Mapping
from typing import Optional
from typing import Sequence
from typing import Tuple
from urllib.parse import urlsplit

from pyacmedns.exceptions import AcmeDnsClientException
import requests
from typing_extensions import TypedDict

from ..logging_utils import censored_url

log = logging.getLogger("peter_sslers.lib.acme_api")


class AcmeDnsCredentials(TypedDict):
    username: str
    password: str
    subdomain: str
    fulldomain: str
    allowfrom: List[str]


class AcmeDnsClient:
    def __init__(
        self, api_url: str, *, timeout: Tuple[float, float] = (3.05, 10)
    ) -> None:
        parsed = urlsplit(api_url)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "acme-dns requires an HTTP(S) API URL without embedded credentials, query or fragment"
            )
        if any(not math.isfinite(value) or value <= 0 for value in timeout):
            raise ValueError("acme-dns timeouts must be positive and finite")
        self.acmedns_url = api_url.rstrip("/")
        self.timeout = timeout

    def _post(
        self,
        operation: str,
        payload: Mapping[str, object],
        *,
        expected_status: int,
        headers: Optional[Mapping[str, str]] = None,
        decode: bool = False,
    ) -> Optional[Dict[str, object]]:
        url = self.acmedns_url + "/" + operation
        started = time.monotonic()
        try:
            # Custom X-Api-Key headers must never follow an HTTP redirect.
            with requests.post(
                url,
                json=dict(payload),
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False,
                stream=True,
            ) as response:
                log.info(
                    "acme-dns response endpoint=%s status=%s",
                    censored_url(url),
                    response.status_code,
                )
                if response.status_code != expected_status:
                    raise AcmeDnsClientException(
                        "acme-dns %s failed (HTTP %s; response omitted)"
                        % (operation, response.status_code)
                    )
                if not decode:
                    return None
                content = bytearray()
                for chunk in response.iter_content(chunk_size=1):
                    if time.monotonic() - started > sum(self.timeout):
                        raise AcmeDnsClientException(
                            "acme-dns response exceeded its time budget"
                        )
                    content.extend(chunk)
                    if len(content) > 65536:
                        raise AcmeDnsClientException(
                            "acme-dns response exceeded its size limit"
                        )
                try:
                    document: object = json.loads(content)
                except (ValueError, UnicodeError):
                    raise AcmeDnsClientException(
                        "acme-dns returned malformed registration data"
                    ) from None
                if not isinstance(document, dict) or not all(
                    isinstance(key, str) for key in document
                ):
                    raise AcmeDnsClientException(
                        "acme-dns returned malformed registration data"
                    )
                return {
                    key: value
                    for key, value in document.items()
                    if isinstance(key, str)
                }
        except (requests.RequestException, UnicodeError, ValueError) as exc:
            raise AcmeDnsClientException(
                "acme-dns request failed (%s)" % type(exc).__name__
            ) from None

    def register_account(
        self, allowfrom: Optional[Sequence[str]]
    ) -> AcmeDnsCredentials:
        if isinstance(allowfrom, str):
            raise ValueError("allowfrom must be a sequence of CIDR strings")
        document = self._post(
            "register",
            {"allowfrom": list(allowfrom or ())},
            expected_status=201,
            decode=True,
        )
        if document is None:
            raise AcmeDnsClientException("acme-dns returned no registration data")
        fields: Dict[str, str] = {}
        for field in ("username", "password", "subdomain", "fulldomain"):
            value = document.get(field)
            if (
                not isinstance(value, str)
                or not value
                or any(character in value for character in "\r\n")
            ):
                raise AcmeDnsClientException(
                    "acme-dns registration omitted required credential fields"
                )
            fields[field] = value
        allowed = document.get("allowfrom", [])
        if allowed is None:
            allowed = []
        if not isinstance(allowed, list) or not all(
            isinstance(item, str) for item in allowed
        ):
            raise AcmeDnsClientException(
                "acme-dns registration returned malformed allowfrom data"
            )
        return AcmeDnsCredentials(
            username=fields["username"],
            password=fields["password"],
            subdomain=fields["subdomain"],
            fulldomain=fields["fulldomain"],
            allowfrom=[item for item in allowed if isinstance(item, str)],
        )

    def update_txt_record(self, account: Mapping[str, object], txt: str) -> None:
        fields: Dict[str, str] = {}
        for field in ("username", "password", "subdomain"):
            value = account.get(field)
            if (
                not isinstance(value, str)
                or not value
                or any(character in value for character in "\r\n")
            ):
                raise AcmeDnsClientException("Invalid acme-dns account credentials")
            fields[field] = value
        self._post(
            "update",
            {"subdomain": fields["subdomain"], "txt": txt},
            expected_status=200,
            headers={"X-Api-User": fields["username"], "X-Api-Key": fields["password"]},
        )


def new_client(api_url: str) -> AcmeDnsClient:
    return AcmeDnsClient(api_url)
