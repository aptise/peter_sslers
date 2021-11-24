# stdlib
import re

# pypi
from OpenSSL import crypto as openssl_crypto

# ==============================================================================

# see `peter_sslers.lib.cert_utils.CERT_PEM_REGEX`, via certbot
CERT_PEM_REGEX = re.compile(
    b"""-----BEGIN CERTIFICATE-----\r?.+?\r?-----END CERTIFICATE-----\r?""", re.DOTALL
)

# ------------------------------------------------------------------------------

# read all the certs

_end_entity = open("cert.pem").read()

_chain_0 = open("chain_0.pem").read()
_chain_1 = open("chain_1.pem").read()
_chain_2 = open("chain_2.pem").read()

_root_0 = open("root_0.pem").read()
_root_1 = open("root_1.pem").read()
_root_2 = open("root_2.pem").read()

# ------------------------------------------------------------------------------


def validate_chain(root, chain, endentity=None):
    """
    validates from a root down to a chain
    if chain is a fullchain (with endentity), endentity can be None

    This test script matured into `cert_utils.ensure_chain`
    """
    root_parsed = openssl_crypto.load_certificate(openssl_crypto.FILETYPE_PEM, root)
    store = openssl_crypto.X509Store()
    store.add_cert(root_parsed)

    intermediates = CERT_PEM_REGEX.findall(chain.encode())
    if endentity is None:
        endentity = intermediates.pop()
    else:
        endentity = endentity.strip()  # needed to match regex results
        if intermediates[-1] == endentity:
            intermediates = intermediates[:-1]

    for _cert in reversed(intermediates):
        _cert_parsed = openssl_crypto.load_certificate(
            openssl_crypto.FILETYPE_PEM, _cert
        )
        # Check the chain certificate before adding it to the store.
        _store_ctx = openssl_crypto.X509StoreContext(store, _cert_parsed)
        _store_ctx.verify_certificate()
        store.add_cert(_cert_parsed)

    end_parsed = openssl_crypto.load_certificate(openssl_crypto.FILETYPE_PEM, endentity)
    _store_ctx = openssl_crypto.X509StoreContext(store, end_parsed)
    _store_ctx.verify_certificate()
    return True


# start with root 0
validate_chain(_root_0, _chain_0, _end_entity)
validate_chain(_root_1, _chain_1, _end_entity)
validate_chain(_root_2, _chain_2, _end_entity)

# now try passing in a fullchain
_fullchain_0 = "%s\n%s\n" % (_chain_0, _end_entity)
_fullchain_1 = "%s\n%s\n" % (_chain_1, _end_entity)
_fullchain_2 = "%s\n%s\n" % (_chain_2, _end_entity)
validate_chain(_root_0, _fullchain_0, _end_entity)
validate_chain(_root_0, _fullchain_0)
validate_chain(_root_1, _fullchain_1, _end_entity)
validate_chain(_root_1, _fullchain_1)
validate_chain(_root_2, _fullchain_2, _end_entity)
validate_chain(_root_2, _fullchain_2)
