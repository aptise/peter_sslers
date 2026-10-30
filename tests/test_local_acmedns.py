"""Opt-in checks against the locally built acme-dns server; no external DNS."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
from typing import Iterator

import dns.message
import dns.query
import dns.rdatatype
from pyacmedns.exceptions import AcmeDnsClientException
import pytest
import requests

from peter_sslers.lib.acmedns import AcmeDnsClient
from ._local_dns import local_http_dns
from ._services import managed_service

pytestmark = pytest.mark.skipif(
    os.environ.get("SSL_RUN_LOCAL_ACME_INTEGRATION") != "1",
    reason="local ACME integration is opt-in",
)


@contextmanager
def local_acmedns(tmp_path: Path) -> Iterator[AcmeDnsClient]:
    binary = os.environ.get("SSL_ACME_DNS_BINARY")
    if not binary:
        raise ValueError("SSL_ACME_DNS_BINARY must identify the local executable")
    api_port = int(os.environ.get("SSL_LOCAL_ACME_DNS_API_PORT", "18511"))
    dns_port = int(os.environ.get("SSL_LOCAL_ACME_DNS_PORT", "18553"))
    config = tmp_path / "acme-dns.cfg"
    config.write_text(
        '[general]\nlisten = "127.0.0.1:%s"\nprotocol = "both4"\n'
        'domain = "audit.example.com"\nnsname = "audit.example.com"\n'
        'nsadmin = "admin.example.com"\n'
        'records = ["audit.example.com. A 127.0.0.1"]\n'
        '[database]\nengine = "sqlite"\nconnection = %s\n'
        '[api]\nip = "127.0.0.1"\nport = "%s"\ntls = "none"\n'
        '[logconfig]\nloglevel = "error"\nlogtype = "stdout"\nlogformat = "json"\n'
        % (dns_port, json.dumps(str(tmp_path / "dns.sqlite")), api_port)
    )
    api = "http://127.0.0.1:%s" % api_port

    def ready() -> bool:
        try:
            with requests.get(api + "/health", timeout=0.5) as response:
                return response.status_code == 200
        except requests.RequestException:
            return False

    with managed_service([binary, "-c", str(config)], ready=ready):
        yield AcmeDnsClient(api)


@pytest.fixture
def live_dns(tmp_path: Path) -> Iterator[AcmeDnsClient]:
    with local_acmedns(tmp_path) as client:
        yield client


def test_live_registration_update_and_authoritative_dns(
    live_dns: AcmeDnsClient,
) -> None:
    credentials = live_dns.register_account(["127.0.0.1/32"])
    value = "A" * 43
    live_dns.update_txt_record(credentials, value)
    question = dns.message.make_query(credentials["fulldomain"], dns.rdatatype.TXT)
    port = int(os.environ.get("SSL_LOCAL_ACME_DNS_PORT", "18553"))
    for query in (dns.query.udp, dns.query.tcp):
        answer = query(question, "127.0.0.1", port=port, timeout=2)
        values = [
            record.to_text().strip('"') for rrset in answer.answer for record in rrset
        ]
        assert value in values


def test_live_invalid_credentials_are_rejected_without_disclosure(
    live_dns: AcmeDnsClient,
) -> None:
    credentials = live_dns.register_account(None)
    bad = dict(credentials, password="invalid-secret-never-log")
    with pytest.raises(AcmeDnsClientException) as caught:
        live_dns.update_txt_record(bad, "B" * 43)
    assert "invalid-secret-never-log" not in str(caught.value)
    assert credentials["password"] not in str(caught.value)
    # A failed update must not destroy the legitimate account.
    live_dns.update_txt_record(credentials, "C" * 43)


def test_live_forwarder_resolves_registered_alias(live_dns: AcmeDnsClient) -> None:
    credentials = live_dns.register_account(None)
    value = "D" * 43
    live_dns.update_txt_record(credentials, value)
    name = "_acme-challenge.forward.audit.example.com."
    port = int(os.environ.get("SSL_LOCAL_ACME_DNS_PORT", "18553"))
    with local_http_dns(
        aliases={name: credentials["fulldomain"]}, authoritative_port=port
    ):
        answer = dns.query.tcp(
            dns.message.make_query(name, dns.rdatatype.TXT),
            "127.0.0.1",
            port=18554,
            timeout=2,
        )
    assert any(rrset.rdtype == dns.rdatatype.CNAME for rrset in answer.answer)
    values = [
        record.to_text().strip('"')
        for rrset in answer.answer
        if rrset.rdtype == dns.rdatatype.TXT
        for record in rrset
    ]
    assert value in values
