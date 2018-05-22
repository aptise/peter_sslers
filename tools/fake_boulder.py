"""
fake_boulder

purpose:
    this spins up a server with some simple routes for testing client development
    this crafts endpoints for success


usage:
    0. edit environment.ini and set the following:
        certificate_authority = http://127.0.0.1:7202
        certificate_authority_testing = True
    2. python fake_boulder.py
"""


from wsgiref.simple_server import make_server
from pyramid.config import Configurator
from pyramid.response import Response

import datetime
import base64
import binascii
import textwrap
import pdb
import json
import tempfile
import subprocess

from peter_sslers.lib import cert_utils



OPENSSL_BIN = 'openssl'

'''
$ openssl genrsa -des3 -out key_unprivate.pem.original 1024
passphrase: 1234
$ openssl rsa -in key_unprivate.pem.original -out key_unprivate.pem
$ openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
'''

SIGNING_KEY = '''-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDINcYvy0Ukfu/q+Z9huH6K3gxtD1Dif8YrkdDfci8/P3F2muie
+3QCJAfNIRiT2QUlbMeiM1ZdNmxAZG7LeMNZdc2Kmoryfq29EVtFkuT/+9lszHsk
kxVGLXbAEkiBIgNHhi0OkK3We+JmvGUfrH6TZhN3Lxwm50jcLejLUwvYrwIDAQAB
AoGAGW6jR0z18oXhaiLdeSdbg75jK7NnXe5HOR+jvc6ea9VeT2esJw3gFamICCmt
GpLV0YQ488S7ssmIBMH9RQGJJul53byJNyifYs6SM+sFpF5teI7wTONoJonuqcpd
R0skfXJ2kiQLsftm+a7UbfmyAxs9SUsZRY9KvZO2gVaOkxECQQDsv617oExX96Af
+o0arIXIXzuD1kJgSkASDWYhcNVKoYf6h1/pAhNC+IVoMP3U+HQ7kOLHPSRuN1YI
3OcbwKJnAkEA2H17gWmotWDMGbj1z3lZcwtGZZ2Z2dR3TEyL4RCxlCrXCl7YPeS2
TdNOeCXWzmQt05DNCWsPH/lrYKtsv1Z6eQJAMkrdrZ912FIQP/rXsszndpNUb0M6
wn3DcpJKGdyAUuRRoJTVeQgp01Y78NBHe9Bz0JuMsUp5zLgQnL1gkvKvDQJBAISw
JEqlX+oLcg0x+Dc5wUFp37PYbLu+JYB2SiWf/bc6qqKIjzEgRTxeDvJE/utxK0VI
suLa42JNlSqi5vw/HMECQQCg3DwzZz654K/j0ISX/sE10bVLUQbHQlhsQWRnuu1U
Lw25TZFkNo2zXaq8FLYnD7E5GVKRF5CQP8s918u97H22
-----END RSA PRIVATE KEY-----
'''


# ==============================================================================


def _unb64(b):
	# http://letsencrypt.readthedocs.io/projects/acme/en/latest/_modules/acme/jose/b64.html#b64encode
    data = b.encode('ascii')
    return base64.urlsafe_b64decode(data + b'=' * (4 - (len(data) % 4)))


def decrypt_acme_newcert(post_data):
    as_json = json.loads(post_data)
    payload = as_json['payload']
    payload_unb64 = _unb64(payload)
    payload_unb64_json = json.loads(payload_unb64)
    csr_der_b64 = payload_unb64_json['csr']
    csr_der = _unb64(csr_der_b64)

    _tmpfile_der = None
    csr_decoded = None
    try:
        # store some data in a tempfile
        _tmpfile_der = tempfile.NamedTemporaryFile()
        _tmpfile_der.write(csr_der)
        _tmpfile_der.seek(0)
        
        csr_pem = cert_utils.convert_der_to_pem__csr(csr_der)
        
        #if False:
        #    proc = subprocess.Popen([OPENSSL_BIN, "req", "-in", _tmpfile_der.name, '-inform', 'DER', "-noout", "-text"],
        #                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #    csr_decoded, err = proc.communicate()
        #else:
        domain_names = cert_utils.parse_csr_domains(_tmpfile_der.name, is_der=True)
        return (csr_pem, domain_names)
    finally:
        _tmpfile_der.close()


def sign_csr(csr_pem):
    _tempfiles = []
    try:
        # store some data in a tempfile
        _tmpfile_cert = cert_utils.new_pem_tempfile('')
        _tempfiles.append(_tmpfile_cert)

        _tmpfile_csr = cert_utils.new_pem_tempfile(csr_pem)
        _tempfiles.append(_tmpfile_csr)
        
        _tmpfile_key = cert_utils.new_pem_tempfile(SIGNING_KEY)
        _tempfiles.append(_tmpfile_key)

        proc = subprocess.Popen([OPENSSL_BIN, "x509", "-req", "-days", "365",
                                 "-in", _tmpfile_csr.name,
                                 '-signkey', _tmpfile_key.name,
                                 '-out', _tmpfile_cert.name
                                 ],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        foo, err = proc.communicate()
        _tmpfile_cert.seek(0)
        data = _tmpfile_cert.read()
        print "Signed", data
        return data
    finally:
        for t in _tempfiles:
            t.close()


def directory(request):
    return Response(body='''{"123123123": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417","key-change": "http://127.0.0.1:7202/acme/key-change","meta": {"caaIdentities": ["letsencrypt.org"],"terms-of-service": "https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf","website": "https://letsencrypt.org/docs/staging-environment/"},"new-authz": "http://127.0.0.1:7202/acme/new-authz","new-cert": "http://127.0.0.1:7202/acme/new-cert","new-reg": "http://127.0.0.1:7202/acme/new-reg","revoke-cert": "http://127.0.0.1:7202/acme/revoke-cert"}''',
        status_code=200,
        headers = {'Replay-Nonce': '123123_123123_',
                   'Content-Type': 'application/json',
                   },
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
    return Response(body='''{"challenges": [{"type": "http-01", "token": "123123123-12312", "uri": "http://127.0.0.1:7202/acme/CHALLENGE"}]}''', 
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
    return Response(body='''{"status": "valid"}''',
                    status_code=202,
                    )


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
    inbound = request.POST.items()[0][0]
    (csr_pem,
     domain_names
     ) = decrypt_acme_newcert(inbound)
    signedcert = sign_csr(csr_pem)
    signedcert_der = cert_utils.convert_pem_to_der(signedcert)

    return Response(body=signedcert_der,
                    status_code=201,
                    headers = {'Link': '<https://acme-v01.api.letsencrypt.org/acme/issuer-cert>;rel="up";title="issuer"',
                               'Date': datetime.datetime.utcnow().isoformat(),
                               'Expires': (datetime.datetime.utcnow() + datetime.timedelta(days=90)).isoformat(),
                               'Content-Type': 'application/pkix-cert',
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
    inbound = request.POST.items()[0][0]
    inbound_json = json.loads(inbound)
    key = inbound_json["header"]["jwk"]
    body = json.dumps({"key": key,
                       "status": "good",
                       "contact": [
                         "mailto:cert-admin@example.com",
                         "tel:+12025551212"
                       ],
                       })
    return Response(body=body,
                    status_code=201,
                    headers = {'Link': '<https://127.0.0.1/acme/terms>;rel="terms-of-service"',
                               'Date': datetime.datetime.utcnow().isoformat(),
                               },
                    )


if __name__ == '__main__':
    print "running test server..."
    config = Configurator()
    config.include('pyramid_debugtoolbar')

    config.add_route('/directory', '/directory')
    config.add_view(directory, route_name='/directory')

    config.add_route('/acme/new-authz', '/acme/new-authz')
    config.add_view(acme_newauthz, route_name='/acme/new-authz')

    config.add_route('/acme/CHALLENGE', '/acme/CHALLENGE')
    config.add_view(acme_CHALLENGE, route_name='/acme/CHALLENGE')

    config.add_route('/acme/new-cert', '/acme/new-cert')
    config.add_view(acme_newcert, route_name='/acme/new-cert')

    config.add_route('/acme/new-reg', '/acme/new-reg')
    config.add_view(acme_newreg, route_name='/acme/new-reg')

    config.add_request_method(lambda request: request.environ['HTTP_HOST'].split(':')[0], 'active_domain_name', reify=True)

    app = config.make_wsgi_app()
    server = make_server('0.0.0.0', 7202, app)
    server.serve_forever()
