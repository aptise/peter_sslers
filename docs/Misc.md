* [Previous - Frequently_Asked_Questions](https://github.com/aptise/peter_sslers/docs/Frequently_Asked_Questions.md)
* [Next - Tools](https://github.com/aptise/peter_sslers/docs/Tools.md)

# Misc

## Tips

This library was designed to be deployed behind a couple of load balancers that
use round-robin DNS. They were both in the same physical network.

* `Nginx` is on port 80. everything in the `/.well-known directory` is proxied to
  an internal machine *which is not guaranteed to be up*
* this service is only spun up when certificate management is needed
* `/.well-known/admin` is not on the public internet

For testing Certificates, these 2 commands can be useful:

reprime `Redis` cache

    $ prequest -m POST example_development.ini /.well-known/admin/api/redis/prime.json

clear out `Nginx` cache

    curl -k -f https://127.0.0.1/.peter_sslers/nginx/shared_cache/expire/all

the `-k` will keep the Certificate from verifying, the `-f` wont blow up from errors.

# `Redis` support

There are several `.ini` config options for `Redis` support, they are listed above.

## `Redis` priming style

currently only `redis.prime_style = 1` and `redis.prime_style = 2` are supported.

### prime_style = 1

This prime style will store data into `Redis` in the following format:

* `d:{DOMAIN_NAME}` a 3 element hash for
  * CertificateSigned (c)
  * PrivateKey (p)
  * CertificateCAChain (i)
  * Note: the leading colon is required
* `c{ID}` the CertificateSigned in PEM format; (c)ert
* `p{ID}` the PrivateKey in PEM format; (p)rivate
* `i{ID}` the CertificateCAChain in PEM format; (i)ntermediate certs

The `Redis` datastore might look something like this:

    r['d:foo.example.com'] = {'c': '1', 'p': '1', 'i' :'99'}  # certid, pkeyid, chainid
    r['d:foo2.example.com'] = {'c': '2', 'p': '1', 'i' :'99'}  # certid, pkeyid, chainid
    r['c1'] = CERT.PEM  # (c)ert
    r['c2'] = CERT.PEM
    r['p2'] = PKEY.PEM  # (p)rivate
    r['i99'] = CHAIN.PEM  # (i)ntermediate certs

to assemble the data for `foo.example.com`:

* (c, p, i) = r.hmget('d:foo.example.com', 'c', 'p', 'i')
** returns {'c': '1', 'p': '1', 'i': '99'}
* cert = r.get('c1')
* pkey = r.get('p1')
* chain = r.get('i99')
* fullchain = cert + "\n" + chain

### prime_style = 2

This prime style will store data into `Redis` in the following format:

* `{DOMAIN_NAME}` a 2 element hash for:
  * FullChain [CertificateSigned+CertificateCAChain] (f)
  * PrivateKey (p)

The `Redis` datastore might look something like this:

    r['foo.example.com'] = {'f': 'FullChain', 'p': 'PrivateKey'}
    r['foo2.example.com'] = {'f': 'FullChain', 'p': 'PrivateKey'}


