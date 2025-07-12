"""
This file should be included at the top of all commandline script invocations.

The env vars below SHOULD NEVER BE SET OUTSIDE OF WARNINGS

The purpose of this file is to disable all warnings and loggings of the Python
processes launched within a subprocess during commandline tests.

Python emits warnings and loggings to STDERR, which makes it difficult to
differentiate if an Exception has occurred within a script launched by within a
subprocess.

The `tests/test_commandline.py` test harness will test the commandline scripts
in a subprocess with these env vars set.  That is the only context in which these
vars should be set.
"""

import logging
import os
import warnings

COMMANDLINE_TESTS_DISABLE_WARNINGS = bool(
    int(os.getenv("COMMANDLINE_TESTS_DISABLE_WARNINGS", "0"))
)
COMMANDLINE_TESTS_DISABLE_LOGGINGS = bool(
    int(os.getenv("COMMANDLINE_TESTS_DISABLE_LOGGINGS", "0"))
)

if COMMANDLINE_TESTS_DISABLE_WARNINGS:
    warnings.filterwarnings("ignore")
    warnings.simplefilter("ignore")
    logging.getLogger().addHandler(logging.NullHandler())

# this doesn't really work, because the entrypoint scripts placed in {ENV}/bin
# will import `peter_sslers.web`, which imports `pyramid`, which imports pkg_resources.
# if we move the imports under `main()` in that file, at some point we still import
# `zope.sqlalchemy`, which will trigger the same warning.  If we try to gurad against
# that, this is just becoming a massive amount of work!
warnings.filterwarnings("ignore", message="pkg_resources is deprecated as an API.")


if COMMANDLINE_TESTS_DISABLE_LOGGINGS:
    logging.disable(logging.CRITICAL)
