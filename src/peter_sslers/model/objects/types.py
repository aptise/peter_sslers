"""Payload contracts shared by certificate configuration consumers."""

from typing import Optional

from typing_extensions import NotRequired
from typing_extensions import TypedDict


class PemPayload(TypedDict):
    id: str
    pem: NotRequired[str]


class CertificateConfigPayload(TypedDict):
    id: str
    private_key: PemPayload
    certificate: PemPayload
    chain: PemPayload
    fullchain: PemPayload


class DomainMetadata(TypedDict):
    id: str
    domain_name: str


class DomainConfigPayload(TypedDict):
    Domain: DomainMetadata
    x509_certificate__latest_single: Optional[CertificateConfigPayload]
    x509_certificate__latest_multi: Optional[CertificateConfigPayload]
