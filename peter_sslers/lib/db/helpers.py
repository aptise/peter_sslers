# logging
import logging

log = logging.getLogger(__name__)

# localapp
from .. import cert_utils


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _certificate_parse_to_record(_tmpfileCert, dbCertificate):
    """
    helper utility
    """
    # grab the modulus
    cert_pem_modulus_md5 = cert_utils.modulus_md5_cert__pem_filepath(_tmpfileCert.name)
    dbCertificate.cert_pem_modulus_md5 = cert_pem_modulus_md5

    dbCertificate.timestamp_signed = cert_utils.parse_startdate_cert__pem_filepath(
        _tmpfileCert.name
    )
    dbCertificate.timestamp_expires = cert_utils.parse_enddate_cert__pem_filepath(
        _tmpfileCert.name
    )
    dbCertificate.cert_subject = cert_utils.cert_single_op__pem_filepath(
        _tmpfileCert.name, "-subject"
    )
    dbCertificate.cert_subject_hash = cert_utils.cert_single_op__pem_filepath(
        _tmpfileCert.name, "-subject_hash"
    )
    dbCertificate.cert_issuer = cert_utils.cert_single_op__pem_filepath(
        _tmpfileCert.name, "-issuer"
    )
    dbCertificate.cert_issuer_hash = cert_utils.cert_single_op__pem_filepath(
        _tmpfileCert.name, "-issuer_hash"
    )

    return dbCertificate


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = ("_certificate_parse_to_record",)
