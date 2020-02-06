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
    """
    # grab the modulus
    cert_pem_modulus_md5 = cert_utils.modulus_md5_cert__pem_filepath(_tmpfileCert.name)
    dbServerCertificate.cert_pem_modulus_md5 = cert_pem_modulus_md5

    dbServerCertificate.timestamp_signed = cert_utils.parse_startdate_cert__pem_filepath(
        _tmpfileCert.name
    )
    dbServerCertificate.timestamp_expires = cert_utils.parse_enddate_cert__pem_filepath(
        _tmpfileCert.name
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
