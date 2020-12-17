# logging
import logging

log = logging.getLogger(__name__)

# localapp
from .. import cert_utils


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _certificate_parse_to_record(_tmpfileCert, dbCertificateSigned):
    """
    helper utility

    :param _tmpfileCert: (required) the tempfile to a PEM encoded certificate
    :param dbCertificateSigned: (required) The :class:`model.objects.CertificateSigned`

    sets the following object attributes:
        :attr:`model.utils.CertificateSigned.cert_pem_modulus_md5`
        :attr:`model.utils.CertificateSigned.timestamp_not_before`
        :attr:`model.utils.CertificateSigned.timestamp_not_after`
        :attr:`model.utils.CertificateSigned.cert_subject`
        :attr:`model.utils.CertificateSigned.cert_issuer`

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
    # grab the modulus
    dbCertificateSigned.cert_pem_modulus_md5 = cert_utils.modulus_md5_cert(
        cert_pem=dbCertificateSigned.cert_pem,
        cert_pem_filepath=_tmpfileCert.name,
    )
    # the rest...
    _cert_data = cert_utils.parse_cert(
        cert_pem=dbCertificateSigned.cert_pem,
        cert_pem_filepath=_tmpfileCert.name,
    )
    dbCertificateSigned.timestamp_not_before = _cert_data["startdate"]
    dbCertificateSigned.timestamp_not_after = _cert_data["enddate"]
    dbCertificateSigned.cert_subject = _cert_data["subject"]
    dbCertificateSigned.cert_issuer = _cert_data["issuer"]
    return dbCertificateSigned


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = ("_certificate_parse_to_record",)
