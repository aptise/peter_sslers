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

