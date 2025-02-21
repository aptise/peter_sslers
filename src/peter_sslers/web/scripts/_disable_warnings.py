import logging
import os
import warnings

DISABLE_WARNINGS_COMMANDLINE = bool(int(os.getenv("DISABLE_WARNINGS_COMMANDLINE", "0")))

if DISABLE_WARNINGS_COMMANDLINE:
    warnings.filterwarnings("ignore")
    logging.getLogger().addHandler(logging.NullHandler())
