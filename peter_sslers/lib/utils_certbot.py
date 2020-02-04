# pypi
from OpenSSL import crypto


# ==============================================================================

# from certbot/certbot/crypto_util
# https://github.com/certbot/certbot/blob/e048da1e389ede7a52bd518ab4ebf9a0b18bfafc/certbot/certbot/crypto_util.py


def cert_and_chain_from_fullchain(fullchain_pem):
    """Split fullchain_pem into cert_pem and chain_pem
    :param str fullchain_pem: concatenated cert + chain
    :returns: tuple of string cert_pem and chain_pem
    :rtype: tuple
    """
    cert = crypto.dump_certificate(
        crypto.FILETYPE_PEM, crypto.load_certificate(crypto.FILETYPE_PEM, fullchain_pem)
    ).decode("utf8")
    chain = fullchain_pem[len(cert) :].lstrip()
    return (cert, chain)
