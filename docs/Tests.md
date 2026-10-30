* [Previous - Tools](https://github.com/aptise/peter_sslers/blob/main/docs/Tools.md)
* [Next - Versioning](https://github.com/aptise/peter_sslers/blob/main/docs/Versioning.md)

# Tests

The following is an overview of the testing systems.

If you plan on contributing code or need to write your own tests, please read the
[Full Development README](https://github.com/aptise/peter_sslers/blob/main/docs/README_DEVELOPMENT.md),
which goes into greater detail about the test suite.

To keep things simple, tests are run using unittest, which can be invoked as
simply as:

    python setup.py test

There are a few environment variables you can set, some of which include:

    # run tests that hit `Nginx` for cache clearing
    export SSL_RUN_NGINX_TESTS=True

    # run tests that hit `Redis` for cache priming
    export SSL_RUN_REDIS_TESTS=True

    # run tests that hit the LetsEncryptAPI
    export SSL_RUN_LETSENCRYPT_API_TESTS=True

    # Set TRUE if you expect the LE API verificaiton to fail
    # this is desired right now, because it's rather complicated to set up a -
    # - test suite that responds to public requests
    export SSL_LETSENCRYPT_API_VALIDATES=True

Tests are done on a SQLite database as specified in `/data_testing/config.ini` .

`/tests/test_data/` contains the keys and Certificates used for testing

You can overwrite the testdb; beware that it CAN NOT run as a memory db. It must
be a disk file due to how the tests are structured.

If running tests against the LetsEncrypt test API, there are some extra
configurations to note:

* `SSL_TEST_DOMAINS` should reflect one or more Domains which point to the IP
  address the server runs on. This will be used for verification of AcmeChallenges.
  LetsEncrypt must be able to communicate with this Domain on port 80.
* `SSL_TEST_PORT` lets you specify which port the test server should bind to
* `/tools/nginx_conf/testing.conf` is an `Nginx` configuration file that can be
  used for testing. it includes a flag check so you can just touch/remove a file
  to alter how `Nginx` proxies.


## Isolated local ACME hardening tests

The opt-in tests in tests/test_local_acme.py use strict Pebble validation
(PEBBLE_VA_ALWAYS_VALID=0). They cover HTTP-01 issuance, a deliberately invalid
HTTP challenge, recovery after an interrupted certificate download, and DNS-01
issuance through a real acme-dns registration and update. A test-only DNS resolver
answers example.com names on loopback and follows the configured challenge alias
to the local authoritative server. No public DNS or hosts-file changes are needed.
Project-side optional prechecks remain disabled by the fixture; the CA performs
the actual challenge verification.

Set SSL_RUN_LOCAL_ACME_INTEGRATION=1, SSL_PEBBLE_BINARY to the local Pebble binary,
and SSL_ACME_DNS_BINARY to the built acme-dns binary. Use an isolated SSL_TEST_INI
and run these tests serially. The standard fixture ports are HTTP 5002, Pebble
14000/15000, test DNS 18554, authoritative DNS 18553, and acme-dns API 18511.
SSL_LOCAL_ACME_DNS_PORT and SSL_LOCAL_ACME_DNS_API_PORT override the latter two
(the forwarding resolver uses the authoritative port selected by the fixture).

    SSL_RUN_LOCAL_ACME_INTEGRATION=1     SSL_PEBBLE_BINARY=/path/to/pebble     SSL_ACME_DNS_BINARY=/path/to/acme-dns     SSL_TEST_INI=/path/to/private/config.ini     DEBUG_DBFREEZE=1 DEBUG_DBFREEZE_ARCHIVE=1     python -m pytest tests/test_local_acme.py tests/test_local_acmedns.py

The standalone acme-dns tests verify UDP/TCP TXT reads and rejection of incorrect
credentials. Child services have bounded startup/readiness and unconditional
cleanup. Service logs use private files rather than unread subprocess pipes.

Frozen database caches are useful for this expensive suite. On a failed testing
reset, both the active database and every reusable frozen/backup database must be
invalidated. Failure archives remain diagnostic artifacts and must never be
reused as successful snapshots. Do not run two suites against the same config
or cache directory.
