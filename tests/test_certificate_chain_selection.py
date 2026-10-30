from __future__ import annotations

from types import SimpleNamespace
from typing import Tuple
from unittest.mock import Mock

import pytest

from peter_sslers.model.objects import PrivateKey
from peter_sslers.model.objects import X509Certificate
from peter_sslers.model.objects import X509CertificateChain
from peter_sslers.model.objects import X509CertificateTrustChain
from peter_sslers.model.objects import X509CertificateTrusted
from peter_sslers.model.objects import objects


@pytest.fixture
def certificate(
    monkeypatch: pytest.MonkeyPatch,
) -> Tuple[X509Certificate, SimpleNamespace]:
    first = X509CertificateTrustChain(id=1, chain_pem="first chain")
    second = X509CertificateTrustChain(id=2, chain_pem="second chain")
    first.x509_certificate_trusted_0_id = 11
    first.x509_certificate_trusted_0 = X509CertificateTrusted(id=11)
    second.x509_certificate_trusted_0_id = 22
    second.x509_certificate_trusted_0 = X509CertificateTrusted(id=22)
    first.x509_certificate_trusted_ids = [11]
    second.x509_certificate_trusted_ids = [22]
    cert = X509Certificate(
        id=1, cert_pem="leaf\n", private_key=PrivateKey(id=7, key_pem="key")
    )
    cert.x509_certificate_chains = [
        X509CertificateChain(
            x509_certificate_trust_chain_id=1, x509_certificate_trust_chain=first
        ),
        X509CertificateChain(
            x509_certificate_trust_chain_id=2, x509_certificate_trust_chain=second
        ),
    ]
    policy = SimpleNamespace(
        x509_certificate_trust_preference_policy_items=[
            SimpleNamespace(x509_certificate_trusted_id=11)
        ]
    )
    request = SimpleNamespace(dbX509CertificateTrustPreferencePolicy=policy)
    monkeypatch.setattr(
        objects.sa_Session,
        "object_session",
        Mock(return_value=SimpleNamespace(info={"request": request})),
    )
    return cert, policy


def test_preferred_chain_and_pem_follow_changed_policy(
    certificate: Tuple[X509Certificate, SimpleNamespace],
) -> None:
    cert, policy = certificate
    assert cert.x509_certificate_trust_chain_id__preferred == 1
    assert cert.cert_chain_pem == "first chain"
    policy.x509_certificate_trust_preference_policy_items = [
        SimpleNamespace(x509_certificate_trusted_id=22)
    ]
    assert cert.x509_certificate_trust_chain_id__preferred == 2
    assert cert.cert_fullchain_pem == "leaf\nsecond chain"
    assert cert.valid_cert_chain_pem() == "second chain"
    assert cert.valid_cert_fullchain_pem() == "leaf\nsecond chain"


def test_explicit_chain_must_belong_to_certificate(
    certificate: Tuple[X509Certificate, SimpleNamespace],
) -> None:
    cert, _ = certificate
    assert cert.valid_cert_chain_pem(2) == "second chain"
    with pytest.raises(ValueError, match="No X509CertificateTrustChain"):
        cert.valid_cert_chain_pem(999)


def test_chain_membership_changes_are_not_cached(
    certificate: Tuple[X509Certificate, SimpleNamespace],
) -> None:
    cert, _ = certificate
    assert cert.x509_certificate_trust_chain_ids == [1, 2]
    cert.x509_certificate_chains.pop(0)
    assert cert.x509_certificate_trust_chain_ids == [2]
    assert cert.x509_certificate_trust_chain_id__preferred == 2


def test_detached_certificate_uses_first_available_chain(
    certificate: Tuple[X509Certificate, SimpleNamespace],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cert, _ = certificate
    monkeypatch.setattr(objects.sa_Session, "object_session", Mock(return_value=None))
    assert cert.x509_certificate_trust_chain_id__preferred == 1


@pytest.mark.parametrize("id_only", [False, True])
def test_config_payload_tracks_current_preferred_chain(
    certificate: Tuple[X509Certificate, SimpleNamespace], id_only: bool
) -> None:
    cert, policy = certificate
    assert cert.custom_config_payload(id_only=id_only)["chain"]["id"] == "1"
    policy.x509_certificate_trust_preference_policy_items = [
        SimpleNamespace(x509_certificate_trusted_id=22)
    ]
    payload = cert.custom_config_payload(id_only=id_only)
    assert payload["chain"]["id"] == "2"
    assert payload["fullchain"]["id"] == "1,2"
    if not id_only:
        assert payload["chain"]["pem"] == "second chain"
        assert payload["fullchain"]["pem"] == "leaf\nsecond chain"


def test_upchain_membership_tracks_removed_chains(
    certificate: Tuple[X509Certificate, SimpleNamespace],
) -> None:
    cert, _ = certificate
    assert set(cert.x509_certificate_trusted_ids__upchain) == {11, 22}
    assert {ca.id for ca in cert.x509_certificate_trusteds__upchain} == {11, 22}
    cert.x509_certificate_chains.pop(0)
    assert cert.x509_certificate_trusted_ids__upchain == [22]
    assert [ca.id for ca in cert.x509_certificate_trusteds__upchain] == [22]
