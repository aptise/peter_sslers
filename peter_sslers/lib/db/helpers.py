# logging
import logging

log = logging.getLogger(__name__)

# localapp
from .. import cert_utils


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _certificate_parse_to_record(_tmpfileCert, dbServerCertificate):
    """
    helper utility

    :param _tmpfileCert: (required) the tempfile to a PEM encoded certificate
    :param dbServerCertificate: (required) The :class:`model.objects.ServerCertificate`

    sets the following object attributes:
        :attr:`model.utils.ServerCertificate.cert_pem_modulus_md5`
        :attr:`model.utils.ServerCertificate.timestamp_signed`
        :attr:`model.utils.ServerCertificate.timestamp_expires`
        :attr:`model.utils.ServerCertificate.cert_subject`
        :attr:`model.utils.ServerCertificate.cert_subject_hash`
        :attr:`model.utils.ServerCertificate.cert_issuer`
        :attr:`model.utils.ServerCertificate.cert_issuer_hash`

    # --------------------------------------------------------------------------
    cert_dates = cert_utils.parse_cert__dates(pem_filepath=_tmpfileCert.name)

    datetime_signed = cert_dates["startdate"]
    if not datetime_signed.startswith("notBefore="):
        raise ValueError("unexpected notBefore: %s" % datetime_signed)
    datetime_signed = datetime_signed[10:]
    datetime_signed = dateutil_parser.parse(datetime_signed)
    datetime_signed = datetime_signed.replace(tzinfo=None)
    dbServerCertificate.timestamp_signed = datetime_signed

    datetime_expires = cert_dates["enddate"]
    if not datetime_expires.startswith("notAfter="):
        raise ValueError("unexpected notAfter: %s" % datetime_expires)
    datetime_expires = datetime_expires[9:]
    datetime_expires = dateutil_parser.parse(datetime_expires)
    datetime_expires = datetime_expires.replace(tzinfo=None)
    dbServerCertificate.timestamp_expires = datetime_expires
    """
    # TODO: this should be one parsing
    # TODO: leverage crypto

    # grab the modulus
    cert_pem_modulus_md5 = cert_utils.modulus_md5_cert(
        cert_pem=dbServerCertificate.cert_pem, cert_pem_filepath=_tmpfileCert.name,
    )
    dbServerCertificate.cert_pem_modulus_md5 = cert_pem_modulus_md5
    # the rest...
    dbServerCertificate.timestamp_signed = cert_utils.parse_cert_startdate(
        cert_pem=dbServerCertificate.cert_pem, cert_pem_filepath=_tmpfileCert.name,
    )
    dbServerCertificate.timestamp_expires = cert_utils.parse_cert_enddate(
        cert_pem=dbServerCertificate.cert_pem, cert_pem_filepath=_tmpfileCert.name,
    )
    dbServerCertificate.cert_subject = cert_utils.cert_single_op__pem_filepath(
        _tmpfileCert.name, "-subject"
    )
    dbServerCertificate.cert_subject_hash = cert_utils.cert_single_op__pem_filepath(
        _tmpfileCert.name, "-subject_hash"
    )
    dbServerCertificate.cert_issuer = cert_utils.cert_single_op__pem_filepath(
        _tmpfileCert.name, "-issuer"
    )
    dbServerCertificate.cert_issuer_hash = cert_utils.cert_single_op__pem_filepath(
        _tmpfileCert.name, "-issuer_hash"
    )

    return dbServerCertificate


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = ("_certificate_parse_to_record",)
