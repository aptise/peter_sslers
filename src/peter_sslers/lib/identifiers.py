"""Canonical identities shared by local certificate, order and renewal models."""

import ipaddress
from typing import Iterable
from typing import List
from typing import Optional
from urllib.parse import urlsplit

from cert_utils.identifiers import Identifier
from cert_utils.utils import identify_san_type

from . import errors


def canonical_name(value: str) -> str:
    """Normalize a bare DNS name or IP address; reject ambiguous address syntax."""
    name = value.strip().lower()
    if not name or any(character in name for character in "[]/%"):
        raise ValueError("Expected a bare DNS name or IP address")
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        if ":" in name or all(character in "0123456789." for character in name):
            raise ValueError("Invalid IP address") from None
        if identify_san_type(name) != "hostname":
            raise ValueError("Invalid DNS name")
        return name
    return address.compressed


def identifier(value: str, address_type: Optional[int] = None) -> Identifier:
    """Classify a canonical identity, optionally checking a persisted address type."""
    name = canonical_name(value)
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        kind = 1
        result: Identifier = {"type": "dns", "value": name}
    else:
        kind = 2 if address.version == 4 else 3
        result = {"type": "ip", "value": name}
    if address_type is not None and address_type != kind:
        raise ValueError("Stored address type does not match its identity")
    return result


def canonical_names(values: Iterable[str]) -> List[str]:
    """Deduplicate names before lookup and identity-set fingerprinting."""
    return sorted({canonical_name(value) for value in values})


def names_from_identifiers(values: Iterable[Identifier]) -> List[str]:
    """Reject SAN-kind confusion instead of reinterpreting numeric DNS SANs."""
    result: List[str] = []
    for value in values:
        if value["value"] != value["value"].strip():
            raise ValueError("Whitespace is not valid in a certificate identity")
        parsed = identifier(value["value"])
        if parsed["type"] != value["type"]:
            raise ValueError("SAN type does not match the stored identity model")
        result.append(parsed["value"])
    return canonical_names(result)


def validate_ip_policy(values: Iterable[str], require_public_ip: bool = True) -> None:
    """Apply issuer policy without limiting which identities can be stored locally."""
    for value in values:
        item = identifier(value)
        if item["type"] == "ip" and require_public_ip:
            address = ipaddress.ip_address(item["value"])
            if not address.is_global or address.is_reserved or address.is_multicast:
                raise errors.InvalidRequest(
                    "ACME server requires publicly routable IP addresses"
                )


def http_host(value: str) -> str:
    """Bracket an IPv6 literal when constructing an HTTP challenge URL."""
    name = canonical_name(value)
    return f"[{name}]" if ":" in name else name


def name_from_http_host(value: str) -> str:
    """Extract a canonical challenge identity from a DNS or bracketed IP Host."""
    parsed = urlsplit("http://" + value)
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Invalid HTTP Host")
    parsed.port  # Validate the port rather than silently ignoring malformed authorities.
    return canonical_name(parsed.hostname or "")
