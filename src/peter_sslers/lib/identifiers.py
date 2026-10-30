"""Canonical identities shared by local certificate, order and renewal models."""

import ipaddress
from typing import Iterable
from typing import List
from typing import Optional

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


def require_dns_issuance(values: Iterable[str]) -> None:
    """Keep IP ordering disabled until ACME IP identifier support is implemented."""
    if any(identifier(value)["type"] == "ip" for value in values):
        raise errors.InvalidRequest("IP ACME issuance is not implemented yet")
