"""
fake_boulder

purpose:
    this spins up a server with some simple routes for testing ACME V1 client development
    this crafts endpoints for success

    for ACME V2 support, please use pebble (https://github.com/letsencrypt/pebble)

usage:
    1. edit environment.ini and set the following:
        certificate_authority = http://127.0.0.1:7202
    2. export OPENSSL_CA_DIR= /path/to/../../../fake_boulder_config
    3. python fake_boulder.py
        note this uses an openssl system running in `./fake_boulder_config` and will create/edit files in there
        you can safely trash the generated certs
"""

# stdlib
import base64
import datetime
import json
import os
import subprocess
from wsgiref.simple_server import make_server

# pypi
import cert_utils
from pyramid.config import Configurator
from pyramid.response import Response


# ==============================================================================


OPENSSL_BIN = "openssl"

# originally this figured out the path to the ca... but that's actually needed by openssl as an environment variable
# so let's just use that...
OPENSSL_CA_DIR = os.getenv("OPENSSL_CA_DIR", None)
if not OPENSSL_CA_DIR:
    raise ValueError("You MUST set the environment variable `OPENSSL_CA_DIR`")
CAPATH = OPENSSL_CA_DIR


# ==============================================================================


def _unb64(b):
    # http://letsencrypt.readthedocs.io/projects/acme/en/latest/_modules/acme/jose/b64.html#b64encode
    data = b.encode("ascii")
    return base64.urlsafe_b64decode(data + b"=" * (4 - (len(data) % 4)))


def decrypt_acme_newcert(post_data):
    as_json = json.loads(post_data)
    payload = as_json["payload"]
    payload_unb64 = _unb64(payload)
    payload_unb64_json = json.loads(payload_unb64)
    csr_der_b64 = payload_unb64_json["csr"]
    csr_der = _unb64(csr_der_b64)

    csr_pem = cert_utils.convert_der_to_pem__csr(csr_der)

    domain_names = cert_utils.parse_csr_domains(csr_pem)
    return (csr_pem, domain_names)


def sign_csr(csr_pem):
    _tempfiles = []
    try:
        # store some data in a tempfile
        _tmpfile_cert = cert_utils.new_pem_tempfile("")
        _tempfiles.append(_tmpfile_cert)

        _tmpfile_csr = cert_utils.new_pem_tempfile(csr_pem)
        _tempfiles.append(_tmpfile_csr)

        # openssl ca -batch -config ./openssl-ca-2.cnf -policy signing_policy -extensions signing_req -out mygenerated.pem -infiles a.csr
        # openssl ca -batch -config ./openssl-ca-2.cnf -policy signing_policy -extensions signing_req -out mygenerated.pem -in a.csr
        proc = subprocess.Popen(
            [
                OPENSSL_BIN,
                "ca",
                "-batch",
                "-config",
                "%s/%s" % (CAPATH, "openssl-ca-2.cnf"),
                "-policy",
                "signing_policy",
                "-extensions",
                "signing_req",
                "-notext",
                "-out",
                _tmpfile_cert.name,
                "-in",
                _tmpfile_csr.name,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        foo, err = proc.communicate()
        _tmpfile_cert.seek(0)
        data = _tmpfile_cert.read()
        return data
    finally:
        for t in _tempfiles:
            t.close()


def directory(request):
    return Response(
        body="""{"123123123": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417","key-change": "http://127.0.0.1:7202/acme/key-change","meta": {"caaIdentities": ["letsencrypt.org"],"terms-of-service": "https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf","website": "https://letsencrypt.org/docs/staging-environment/"},"new-authz": "http://127.0.0.1:7202/acme/new-authz","new-cert": "http://127.0.0.1:7202/acme/new-cert","new-reg": "http://127.0.0.1:7202/acme/new-reg","revoke-cert": "http://127.0.0.1:7202/acme/revoke-cert"}""",
        status_code=200,
        headers={"Replay-Nonce": "123123_123123_", "Content-Type": "application/json"},
    )


def acme_newauthz(request):
    """
    https://tools.ietf.org/html/draft-ietf-acme-acme-03#section-6.4
        6.4.  Identifier Authorization

           GET /acme/authz/1234 HTTP/1.1
             Host: example.com

             HTTP/1.1 200 OK
             Content-Type: application/json
             Link: <https://example.com/acme/some-directory>;rel="directory"

             {
               "status": "pending",

               "identifier": {
                 "type": "dns",
                 "value": "example.org"
               },

               "challenges": [
                 {
                   "type": "http-01",
                   "uri": "https://example.com/authz/asdf/0",
                   "token": "IlirfxKKXAsHtmzK29Pj8A"
                 },
                 {
                   "type": "dns-01",
                   "uri": "https://example.com/authz/asdf/1",
                   "token": "DGyRejmCefe7v4NfDGDKfA"
                 }
               ],

               "combinations": [[0], [1]]
             }
    """
    return Response(
        body="""{"challenges": [{"type": "http-01", "token": "123123123-12312", "uri": "http://127.0.0.1:7202/acme/CHALLENGE"}]}""",
        status_code=201,
    )


def acme_CHALLENGE(request):
    """
    https://tools.ietf.org/html/draft-ietf-acme-acme-03#section-6.4.1
        6.4.1.  Responding to Challenges

           GET /acme/authz/asdf HTTP/1.1
           Host: example.com

           HTTP/1.1 200 OK

           {
             "status": "valid",
             "expires": "2015-03-01T14:09:00Z",

             "identifier": {
               "type": "dns",
               "value": "example.org"
             },

             "challenges": [
               {
                 "type": "http-01"
                 "status": "valid",
                 "validated": "2014-12-01T12:05:00Z",
                 "token": "IlirfxKKXAsHtmzK29Pj8A",
                 "keyAuthorization": "IlirfxKKXA...vb29HhjjLPSggwiE"
               }
             ]
           }

    """
    return Response(body="""{"status": "valid"}""", status_code=202)


def acme_newcert(request):
    """
    https://tools.ietf.org/html/draft-ietf-acme-acme-03#section-6.3.1
        6.3.1.  Downloading the Certificate

       GET /acme/cert/asdf HTTP/1.1
       Host: example.com
       Accept: application/pkix-cert

       HTTP/1.1 200 OK
       Content-Type: application/pkix-cert
       Link: <https://example.com/acme/ca-cert>;rel="up";title="issuer"
       Link: <https://example.com/acme/revoke-cert>;rel="revoke"
       Link: <https://example.com/acme/app/asdf>;rel="author"
       Link: <https://example.com/acme/sct/asdf>;rel="ct-sct"
       Link: <https://example.com/acme/some-directory>;rel="directory"

       [DER-encoded certificate]
    """
    inbound = request.body
    if not inbound:
        return Response(body="", status_code=500)
    (csr_pem, domain_names) = decrypt_acme_newcert(inbound)
    signedcert_pem = sign_csr(csr_pem)
    if not signedcert_pem:
        raise ValueError("could not generate a cert")
    signedcert_der = cert_utils.convert_pem_to_der(signedcert_pem)
    return Response(
        body=signedcert_der,
        status_code=201,
        headers={
            "Link": '<https://acme-v01.api.letsencrypt.org/acme/issuer-cert>;rel="up";title="issuer"',
            "Date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "Expires": (
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=90)
            ).isoformat(),
            "Content-Type": "application/pkix-cert",
        },
    )


def acme_newreg(request):
    """
    https://tools.ietf.org/html/draft-ietf-acme-acme-03#section-6.2
    IN
    {"header": {"alg": "RS256", "jwk": {"e": "AQAB", "kty": "RSA", "n": ""}}, "protected": "", "payload": "", "signature": ""}

    OUT
    HTTP/1.1 201 Created
    Content-Type: application/json
    Location: https://example.com/acme/reg/asdf
    Link: <https://example.com/acme/terms>;rel="terms-of-service"
    Link: <https://example.com/acme/some-directory>;rel="directory"

    {
      "key": { /* JWK from JWS header */ },
      "status": "good",

      "contact": [
        "mailto:cert-admin@example.com",
        "tel:+12025551212"
      ]
    }
    """
    try:
        inbound = request.body
        inbound_json = json.loads(inbound)
        key = inbound_json["header"]["jwk"]
        body = json.dumps(
            {
                "key": key,
                "status": "good",
                "contact": ["mailto:cert-admin@example.com", "tel:+12025551212"],
            },
            sort_keys=True,
        )
    except Exception as exc:  # noqa: F841
        raise ValueError("invalid input")
    return Response(
        body=body,
        status_code=201,
        headers={
            "Link": '<https://127.0.0.1/acme/terms>;rel="terms-of-service"',
            "Date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
    )


if __name__ == "__main__":
    print("running test server...")
    config = Configurator()
    config.include("pyramid_debugtoolbar")

    config.add_route("/directory", "/directory")
    config.add_view(directory, route_name="/directory")

    config.add_route("/acme/new-authz", "/acme/new-authz")
    config.add_view(acme_newauthz, route_name="/acme/new-authz")

    config.add_route("/acme/CHALLENGE", "/acme/CHALLENGE")
    config.add_view(acme_CHALLENGE, route_name="/acme/CHALLENGE")

    config.add_route("/acme/new-cert", "/acme/new-cert")
    config.add_view(acme_newcert, route_name="/acme/new-cert")

    config.add_route("/acme/new-reg", "/acme/new-reg")
    config.add_view(acme_newreg, route_name="/acme/new-reg")

    config.add_request_method(
        lambda request: request.environ["HTTP_HOST"].split(":")[0],
        "active_domain_name",
        reify=True,
    )

    app = config.make_wsgi_app()
    server = make_server("127.0.0.1", 7202, app)
    server.serve_forever()
