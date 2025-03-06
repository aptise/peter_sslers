# stdlib
import os
from typing import Dict
from typing import Optional
from typing import TYPE_CHECKING

# pypi
from typing_extensions import TypedDict

if TYPE_CHECKING:
    from ..model.objects import CertificateSigned
    from ..model.objects import RenewalConfiguration

# ==============================================================================


A_CertPayload = TypedDict(
    "A_CertPayload",
    {
        "cert.pem": str,
        "chain.pem": str,
        "fullchain.pem": str,
        "pkey.pem": str,
    },
)

A_DirectoryPayload = TypedDict(
    "A_DirectoryPayload",
    {
        "primary": Optional[A_CertPayload],
        "backup": Optional[A_CertPayload],
    },
)

A_ConfigPayload = TypedDict(
    "A_ConfigPayload",
    {
        "directories": Dict[str, A_DirectoryPayload],
        "labels": Dict[str, str],
    },
)


def encode_CertificateSigned_a(
    dbCertificateSigned: "CertificateSigned",
) -> A_CertPayload:
    payload: A_CertPayload = {
        "cert.pem": dbCertificateSigned.cert_pem,
        "chain.pem": dbCertificateSigned.cert_chain_pem,
        "fullchain.pem": dbCertificateSigned.cert_fullchain_pem,
        "pkey.pem": dbCertificateSigned.private_key.key_pem,
    }
    return payload


def encode_RenewalConfiguration_a(
    dbRenewalConfiguration: "RenewalConfiguration",
) -> A_DirectoryPayload:
    directory_payload: A_DirectoryPayload = {"primary": None, "backup": None}
    pCert: Optional["CertificateSigned"] = None
    bCert: Optional["CertificateSigned"] = None
    if dbRenewalConfiguration.certificate_signeds__primary__5:
        pCert = dbRenewalConfiguration.certificate_signeds__primary__5[0]
    if dbRenewalConfiguration.certificate_signeds__backup__5:
        bCert = dbRenewalConfiguration.certificate_signeds__backup__5[0]
    for dbCert, dest in ((pCert, "primary"), (bCert, "backup")):
        if not dbCert:
            continue
        if TYPE_CHECKING:
            assert dbCert.cert_chain_pem
            assert dbCert.fullchain_pem
        payload = encode_CertificateSigned_a(dbCert)
        directory_payload[dest] = payload
    return directory_payload


def write_pem(directory: str, filename: str, filecontents: str) -> bool:
    fpath = os.path.join(directory, filename)
    with open(fpath, "w") as fh:
        fh.write(filecontents)
    return True
