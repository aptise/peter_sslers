# stdlib
import datetime
import sys

# pypi
import cert_utils
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

# ==============================================================================

DOMAIN_CERTS = [
    "a.test-replaces.example.com",
    "b.test-replaces.example.com",
    "c.test-replaces.example.com",
]


def _gen_csr(
    domain: str,
    key_pem: str,
) -> str:
    print("\tgenerating CSR for %s" % domain)
    csr = cert_utils.make_csr(
        domain_names=[domain],
        key_pem=key_pem,
    )
    return csr


def generate_csrs() -> bool:
    print("Generating CSRs:")
    key_pem = open("../privkey1.pem").read().strip()
    for domain in DOMAIN_CERTS:
        csr = _gen_csr(domain, key_pem=key_pem)
        with open("%s/csr.pem" % domain, "w") as fh:
            fh.write(csr)
    return True


def _sign_csr(
    csr_path: str,
    pkey_path: str,
    cert_path: str,
) -> None:
    """
    csr_path (str): Path to the CSR file.
    pkey_path (str): Path to the private key file.
    cert_path (str): Path to save the signed certificate.
    """
    # Load the CSR
    with open(csr_path, "rb") as f:
        csr = x509.load_pem_x509_csr(f.read())

    # Load the private key
    with open(pkey_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )
        assert isinstance(private_key, RSAPrivateKey)

    # Create a builder for the signed certificate
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(csr.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )
    )

    # Copy extensions from CSR to the certificate
    for extension in csr.extensions:
        builder = builder.add_extension(extension.value, extension.critical)

    # set the authority key, so we can do ARI
    authority_key = x509.AuthorityKeyIdentifier.from_issuer_public_key(
        private_key.public_key()
    )
    builder = builder.add_extension(authority_key, False)

    # Sign the certificate
    certificate = builder.sign(private_key, hashes.SHA256())

    # Save the signed certificate
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(encoding=serialization.Encoding.PEM))


def generate_certs() -> bool:
    print("Generating Certs:")
    pkey_path = "../../../test_configuration/pebble/test/certs/pebble.minica.key.pem"
    for domain in DOMAIN_CERTS:
        csr_path = "%s/csr.pem" % domain
        cert_path = "%s/cert.pem" % domain
        _sign_csr(csr_path=csr_path, pkey_path=pkey_path, cert_path=cert_path)
    return True


def check_aris() -> bool:
    print("Checking ARI:")
    for domain in DOMAIN_CERTS:
        cert_path = "%s/cert.pem" % domain
        cert_data = open(cert_path, "r").read()
        ari = cert_utils.ari_construct_identifier(cert_data)
        print(ari)

    return True


if __name__ == "__main__":

    def _usage():
        print("usage:")
        print("python regenerate.py check_aris")
        print("python regenerate.py generate_csrs")
        print("python regenerate.py generate_certs")
        print("python regenerate.py generate_csrs generate_certs check_aris")
        exit()

    _valid_commands = (
        "check_aris",
        "generate_csrs",
        "generate_certs",
    )
    executes = {}
    for c in sys.argv[1:]:
        executes[c] = True

    if not executes.keys():
        _usage()

    if executes.get("generate_csrs"):
        generate_csrs()
    if executes.get("generate_certs"):
        generate_certs()
    if executes.get("check_aris"):
        check_aris()
