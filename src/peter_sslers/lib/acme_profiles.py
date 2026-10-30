"""Normalize advertised ACME profiles without treating local metadata as policy."""

from typing import Dict
from typing import Mapping
from urllib.parse import urlsplit

from .errors import FieldError


def directory_profiles(directory: Mapping[str, object]) -> Dict[str, str]:
    """Return advertised names and descriptions/URLs, rejecting malformed maps."""
    meta = directory.get("meta")
    if meta is None:
        return {}
    if not isinstance(meta, dict):
        raise ValueError("ACME directory meta must be an object")
    advertised = meta.get("profiles")
    if advertised is None:
        return {}
    if not isinstance(advertised, dict):
        raise ValueError("ACME profiles must be an object")
    profiles: Dict[str, str] = {}
    for name, value in advertised.items():
        if (
            not isinstance(name, str)
            or not name
            or "," in name
            or name != name.strip()
            or any(ord(character) < 32 for character in name)
            or not isinstance(value, str)
        ):
            raise ValueError("ACME profiles require valid names and string values")
        profiles[name] = value
    return dict(sorted(profiles.items()))


def profile_link(value: str) -> bool:
    """Only render ordinary credential-free HTTP(S) references as hyperlinks."""
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme in ("http", "https")
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and not any(ord(character) < 32 for character in value)
        )
    except ValueError:
        return False


def require_profile(directory: Mapping[str, object], name: str) -> None:
    """Reject a missing selection without switching to a default or local catalogue."""
    if name not in directory_profiles(directory):
        raise FieldError(
            "profile", "The AcmeServer no longer offers the selected profile"
        )
