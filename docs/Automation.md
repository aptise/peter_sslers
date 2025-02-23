* [Previous - Implementation_Details](https://github.com/aptise/peter_sslers/blob/main/docs/Implementation_Details.md)
* [Next - Frequently_Asked_Questions](https://github.com/aptise/peter_sslers/blob/main/docs/Frequently_Asked_Questions.md)

# Automation

## Routines

Several routines are designed for integration with cron scheduling:

* routine__run_ari_checks 

This is low-overhead and can run hourly, if not multiple times per day.

This routine iterates all the enrolled certificates and polls them for ARI information.

The ARI information is used to hint at renewal time.

This routine does not require inbound traffic or firewall adjustment.


* routine__automatic_orders 

This has moderate overhead and should run at least once a day.

This routine may require inbound traffic and firewall adjustment.

This routine does two tasks:

1- Orders missing certificates.  When a RenewalConfiguration supporting a backup
certificate is created, only the primary is ordered.  The backup order is deferred
to manual ordering or being picked up by this routine.

2- Renews expiring certificates.







## Routes Designed for JSON Automation

### `/.well-known/peter_sslers/api/deactivate-expired.json`

Deactivate expired Certificates.

### `/.well-known/peter_sslers/api/redis/prime.json`

Prime a `Redis` cache with Domain data.

### `/.well-known/peter_sslers/api/update-recents.json`

Updates Domain records to list the most recent Certificates for the Domain.


## Routes with JSON support

Most routes have support for JSON requests via a `.json` suffix.

These are usually documented on the html version, and via "GET" requests to the
json version.

### `/.well-known/peter_sslers/certificate-signed/upload.json`

This can be used used to directly import Certificates already issued by LetsEncrypt

    curl --form "private_key_file=@privkey1.pem" \
         --form "certificate_file=@cert1.pem" \
         --form "chain_file=@chain1.pem" \
         http://127.0.0.1:7201/.well-known/peter_sslers/certificate-signed/upload.json

    curl --form "private_key_file=@privkey2.pem" \
         --form "certificate_file=@cert2.pem" \
         --form "chain_file=@chain2.pem" \
         http://127.0.0.1:7201/.well-known/peter_sslers/certificate-signed/upload.json

Note the url is not `/upload` like the html form but `/upload.json`.

Both URLS accept the same form data, but `/upload.json` returns json data which
is probably more readable from the commandline.

Errors will appear in JSON if encountered.

If data is not POSTed to the form, instructions are returned in the json.

There is an `invoke` script to automate these imports:

    invoke import-certbot-certs-archive \
           --archive-path='/path/to/archive' \
           --server-url-root='http://127.0.0.1:7201/.well-known/peter_sslers'

    invoke import-certbot-cert-version \
           --domain-certs-path="/path/to/ssl/archive/example.com" \
           --certificate-version=3 \
           --server-url-root="http://127.0.0.1:7201/.well-known/peter_sslers"

    invoke import-certbot-certs-live \
           --live-path='/etc/letsencrypt/live' \
           --server-url-root='http://127.0.0.1:7201/.well-known/peter_sslers'

    invoke import-certbot-cert-plain \
           --cert-path='/etc/letsencrypt/live/example.com' \
           --server-url-root='http://127.0.0.1:7201/.well-known/peter_sslers'

If peter_sslers is installed on the same machine: the commandline script
`import_certbot`, which is installed into the shell path via entrypoints, will
yield superior performance as it does not require HTTP.

### `/.well-known/peter_sslers/certificate-ca/upload-cert.json`

Upload a new CertificateAuthority (LetsEncrypt) Certificate.

### `/.well-known/peter_sslers/certificate-ca-chain/upload-chain.json`

Upload a new CertificateAuthority (LetsEncrypt) Chain.  A chain are the
intermediate certificates.

### `/.well-known/peter_sslers/domain/{DOMAIN|ID}/config.json` Domain Data

`{DOMAIN|ID}` can be the internal numeric id or the Domain name.

Will return a JSON document:

    {"domain": {"id": "1",
                "domain_name": "a",
                },
     "certificate_signed__latest_single": null,
     "certificate_signed__latest_multi": {"id": "1",
                                  "private_key": {"id": "1",
                                                  "pem": "a",
                                                  },
                                  "certificate": {"id": "1",
                                                  "pem": "a",
                                                  },
                                  "chain": {"id": "1",
                                            "pem": "a",
                                            },
                                  "fullchain": {"id": "1",
                                                "pem": "a",
                                                },
                                  }
     }

If you pass in the querystring '?idonly=1', the PEMs will not be returned.

Notice that the numeric ids are returned as strings. This is by design.

If you pass in the querystring '?openresty=1' to identify the request as coming
from `OpenResty` (as an API request), this will function as a write-through cache
for `Redis` and load the Domain's info into `Redis` (if `Redis` is configured).

This is the route use by the `OpenResty` Lua script to query Domain data.

### `/.well-known/peter_sslers/certificate/{ID}/config.json` Certificate Data

The certificate JSON payload is what is nested in the Domain payload

    {"id": "1",
     "private_key": {"id": "1",
                     "pem": "a",
                     },
     "certificate": {"id": "1",
                     "pem": "a",
                     },
     "chain": {"id": "1",
               "pem": "a",
               },
     "fullchain": {"id": "1",
                   "pem": "a",
                   },
     }

Notice that the numeric ids are returned as strings. This is by design.

Need to get the Certificate data directly? NO SWEAT. Peter transforms this for you
on the server, and sends it to you with the appropriate headers.

* /.well-known/peter_sslers/certificate-signed/{ID}/cert.crt
* /.well-known/peter_sslers/certificate-signed/{ID}/cert.pem
* /.well-known/peter_sslers/certificate-signed/{ID}/cert.pem.txt
* /.well-known/peter_sslers/certificate-signed/{ID}/chain.cer
* /.well-known/peter_sslers/certificate-signed/{ID}/chain.crt
* /.well-known/peter_sslers/certificate-signed/{ID}/chain.der
* /.well-known/peter_sslers/certificate-signed/{ID}/chain.pem
* /.well-known/peter_sslers/certificate-signed/{ID}/chain.pem.txt
* /.well-known/peter_sslers/certificate-signed/{ID}/fullchain.pem
* /.well-known/peter_sslers/certificate-signed/{ID}/fullchain.pem.txt
* /.well-known/peter_sslers/certificate-signed/{ID}/privkey.key
* /.well-known/peter_sslers/certificate-signed/{ID}/privkey.pem
* /.well-known/peter_sslers/certificate-signed/{ID}/privkey.pem.txt

