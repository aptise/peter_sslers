"""
This script is primarily used for project development and testing.

This will run `alembic upgrade` against all local installs matching:

   data_*/config.ini

This is likely not needed for normal usage, unless there are multiple environments.
"""

# stdlib
import os
import subprocess
from typing import List

# pypi
import psutil

# ==============================================================================

data_dirs: List[str] = [
    i
    for i in os.listdir(".")
    if (os.path.isdir(i) and (i[:5] == "data_") and ("config.ini" in os.listdir(i)))
]

for d in data_dirs:
    config_file = os.path.join(d, "config.ini")
    print("upgrading: %s" % config_file)
    with psutil.Popen(
        ["alembic", "-c", config_file, "upgrade", "head"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        _data, _err = proc.communicate()
        if _err:
            print("error", _err)
        print("response", _data)
