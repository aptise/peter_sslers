# stdlib
import os
import os.path
from typing import Dict
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING

# pypi
from typing_extensions import TypedDict

if TYPE_CHECKING:
    from .context import ApiContext
    from ..model.objects import RenewalConfiguration
    from ..model.objects import X509Certificate

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


def encode_X509Certificate_a(
    dbX509Certificate: "X509Certificate",
) -> A_CertPayload:
    payload: A_CertPayload = {
        "cert.pem": dbX509Certificate.cert_pem,
        "chain.pem": dbX509Certificate.cert_chain_pem or "",
        "fullchain.pem": dbX509Certificate.cert_fullchain_pem or "",
        "pkey.pem": dbX509Certificate.private_key.key_pem,
    }
    return payload


def encode_RenewalConfiguration_a(
    dbRenewalConfiguration: "RenewalConfiguration",
) -> A_DirectoryPayload:
    directory_payload: A_DirectoryPayload = {"primary": None, "backup": None}
    pCert: Optional["X509Certificate"] = None
    bCert: Optional["X509Certificate"] = None
    if dbRenewalConfiguration.x509_certificates__primary__5:
        pCert = dbRenewalConfiguration.x509_certificates__primary__5[0]
    if dbRenewalConfiguration.x509_certificates__backup__5:
        bCert = dbRenewalConfiguration.x509_certificates__backup__5[0]
    for dbCert, dest in ((pCert, "primary"), (bCert, "backup")):
        if not dbCert:
            continue
        if TYPE_CHECKING:
            assert dbCert.cert_chain_pem
            assert dbCert.fullchain_pem
        payload = encode_X509Certificate_a(dbCert)
        directory_payload[dest] = payload  # type: ignore[literal-required]
    return directory_payload


def relative_symlink(src, dst):
    dir = os.path.dirname(dst)
    src = os.path.relpath(src, dir)
    return os.symlink(src, dst)


def write_pem(directory: str, filename: str, filecontents: str) -> bool:
    fpath = os.path.join(directory, filename)
    with open(fpath, "w") as fh:
        fh.write(filecontents)
    return True


def get_exports_dirs(ctx: "ApiContext") -> Tuple[str, str]:
    if TYPE_CHECKING:
        assert ctx.application_settings
    EXPORTS_DIR = os.path.join(ctx.application_settings["data_dir"], "certificates")
    EXPORTS_DIR_WORKING = os.path.join(
        ctx.application_settings["data_dir"], "certificates.working"
    )
    return (EXPORTS_DIR, EXPORTS_DIR_WORKING)
