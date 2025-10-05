"""
quick utility script
leverages the test framework to start/manage a few background subprocess:

* pebble
* pebble_alt
* acme_dns


"""

# stdlib
import os
import time

# locals
import tests._utils
from tests._utils import under_acme_dns
from tests._utils import under_pebble
from tests._utils import under_pebble_alt

# ==============================================================================

RUN_API_TESTS__PEBBLE = bool(int(os.environ.get("SSL_RUN_API_TESTS__PEBBLE", 0)))

if not RUN_API_TESTS__PEBBLE:
    print("env var `SSL_RUN_API_TESTS__PEBBLE=1` must be set")
    exit(1)


def run():
    print("Spinning up services...")

    @under_acme_dns
    def _acme_dns():
        print("Running: acme_dns")

        @under_pebble
        def _pebble():
            print("Running: pebble")

            @under_pebble_alt
            def _pebble_alt():
                print("Running: pebble_alt")

                while True:
                    print("running...")
                    time.sleep(60)

            print("Starting: pebble_alt")
            _pebble_alt()

        print("Starting: pebble")
        _pebble()

    print("Starting: acme_dns")
    _acme_dns()


tests._utils.TEST_INI = "data_development/config.ini"
tests._utils.intialize_appsettings()

run()
