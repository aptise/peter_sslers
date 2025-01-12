# stdlib
import logging
from typing import Optional
from typing import TYPE_CHECKING

# pypi
import cert_utils

# local
from .. import utils

if TYPE_CHECKING:
    from ...model.objects import CertificateSigned


# ==============================================================================

log = logging.getLogger(__name__)

# ------------------------------------------------------------------------------


def _certificate_parse_to_record(
    cert_pem: str,
    cert_pem_filepath: Optional[str],
    dbCertificateSigned: "CertificateSigned",
) -> "CertificateSigned":
    """
    helper utility

    :param cert_pem: (required) the PEM encoded certificate
    :param cert_pem_filepath: (optional) the tempfile to a PEM encoded certificate
    :param dbCertificateSigned: (required) The :class:`model.objects.CertificateSigned`

    :returns: the inbound `CertificateSigned`, updated.

    sets the following object attributes:
        :attr:`model.utils.CertificateSigned.timestamp_not_before`
        :attr:`model.utils.CertificateSigned.timestamp_not_after`
        :attr:`model.utils.CertificateSigned.cert_subject`
        :attr:`model.utils.CertificateSigned.cert_issuer`
        :attr:`model.utils.CertificateSigned.fingerprint_sha1`
        :attr:`model.utils.CertificateSigned.spki_sha256`
        :attr:`model.utils.CertificateSigned.cert_serial`
        :attr:`model.utils.CertificateSigned.is_ari_supported__cert`

    # --------------------------------------------------------------------------
    cert_dates = cert_utils.parse_cert__dates(pem_filepath=_tmpfileCert.name)

    datetime_signed = cert_dates["startdate"]
    if not datetime_signed.startswith("notBefore="):
        raise ValueError("unexpected notBefore: %s" % datetime_signed)
    datetime_signed = datetime_signed[10:]
    datetime_signed = dateutil_parser.parse(datetime_signed)
    datetime_signed = datetime_signed.replace(tzinfo=None)
    dbCertificateSigned.timestamp_not_before = datetime_signed

    datetime_expires = cert_dates["enddate"]
    if not datetime_expires.startswith("notAfter="):
        raise ValueError("unexpected notAfter: %s" % datetime_expires)
    datetime_expires = datetime_expires[9:]
    datetime_expires = dateutil_parser.parse(datetime_expires)
    datetime_expires = datetime_expires.replace(tzinfo=None)
    dbCertificateSigned.timestamp_not_after = datetime_expires
    """
    # everything is in here
    _cert_data = cert_utils.parse_cert(
        cert_pem=cert_pem,
        cert_pem_filepath=cert_pem_filepath,
    )
    dbCertificateSigned.timestamp_not_before = _cert_data["startdate"]
    dbCertificateSigned.timestamp_not_after = _cert_data["enddate"]
    dbCertificateSigned.cert_subject = _cert_data["subject"]
    dbCertificateSigned.cert_issuer = _cert_data["issuer"]
    dbCertificateSigned.fingerprint_sha1 = _cert_data["fingerprint_sha1"]
    dbCertificateSigned.spki_sha256 = _cert_data["spki_sha256"]
    dbCertificateSigned.cert_serial = str(
        _cert_data["serial"]
    )  # cast to str, because int may be TOO large
    _ari_endpoint = utils.issuer_to_endpoint(cert_data=_cert_data)
    if _ari_endpoint:
        dbCertificateSigned.is_ari_supported__cert = True

    return dbCertificateSigned


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = ("_certificate_parse_to_record",)
