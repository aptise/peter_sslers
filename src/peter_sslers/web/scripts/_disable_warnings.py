"""
This file should be included on all commandline script invocations.

The purpose is to disable warnings and logging, as Python sends that to STDERR--
which is largely incompatible with using subprocess.
"""

import logging
import os
import warnings

DISABLE_WARNINGS_COMMANDLINE = bool(int(os.getenv("DISABLE_WARNINGS_COMMANDLINE", "0")))

if DISABLE_WARNINGS_COMMANDLINE:
    warnings.filterwarnings("ignore")
    warnings.simplefilter("ignore")
    logging.getLogger().addHandler(logging.NullHandler())
