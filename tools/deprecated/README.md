## Acme v1 Test Environment

`./fake_boulder.py` was written to spin up a fake acme-v1 server.
The script has documentation in it, regarding how to set things up.
At this time this README was written, `./fake_boulder.py` handles uses openssl's "ca" mode to sign certificates.
This requires environment variabels to be set, and will write copies of the generated certificates.

Support for Acme V1 was removed from this project in `v0.4.0`;  therefore `fake_boulder` is no longer supported.

This tool only remains in the source code to function as a reference implementation for future efforts.

