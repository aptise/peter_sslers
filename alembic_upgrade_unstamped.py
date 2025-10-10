"""
A deployment hotfix introduced alembic to several nodes WITHOUT correctly stamping them.

This was not detected until several revisions had been introduced.

This script was used to update the nodes.  It does the following:

* archives the database
* attempts to upgrade from a revision stamp
* on failure, the database is restored from a backup and the next revision is tried

This might be adaptable to your needs.

This assumes an upgrade from no stamp has failed; this does not detect an existing stamp.

"""

# stdlib
import os
import shutil
import subprocess
import sys
from typing import Optional

# pypi
from alembic.config import Config
from alembic.script import ScriptDirectory
import psutil

# ==============================================================================

# sanity checking...
if len(sys.argv) != 2:
    raise ValueError("invoke as `python alembic_upgrade_unstamped.py {CONFIG_FILE}`")
CONFIG_file = sys.argv[1]
if not os.path.exists(CONFIG_file):
    raise ValueError("%s is not on disk" % CONFIG_file)

CONFIG = Config(CONFIG_file)
if not CONFIG.get_section_option("alembic", "script_location"):
    CONFIG.set_section_option("alembic", "script_location", "alembic")


sqlalchemy_url = CONFIG.get_section_option("alembic", "sqlalchemy.url")
if not sqlalchemy_url:
    raise ValueError("no sqlalchemy.url found")
if not sqlalchemy_url[:11] == "sqlite:////":
    raise ValueError("%s is not a compatible sqlite url" % sqlalchemy_url)

db_file = sqlalchemy_url[10:]
db_file_backup = "%s-ORIGINAL" % db_file

# initial backup
if not os.path.exists(db_file):
    raise ValueError("DB File not found on disk:", db_file)
shutil.copy(db_file, db_file_backup)


def reset_db():
    if not os.path.exists(db_file_backup):
        raise ValueError("BACKUP does not exist; will not delete main until backed up")
    os.remove(db_file)
    shutil.copy(db_file_backup, db_file)


# # history prints, we don't want that
# history = alembic.command.history(config=CONFIG)

revisions = []
script = ScriptDirectory.from_config(CONFIG)
for sc in script.walk_revisions(base="base", head="heads"):
    # print(sc.down_revision, sc.revision, sc.nextrev)
    revisions.append(sc.revision)
revisions.reverse()

PASSED: Optional[str] = None
for rev in revisions:
    reset_db()

    print("STAMPING", rev)
    with psutil.Popen(
        ["alembic", "-c", CONFIG_file, "stamp", rev],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        _data, _err = proc.communicate()
        if _err:
            if b"Traceback" in _err:
                print("\tERROR; Fatal")
                exit(1)

    print("ATTEMPT UPGRADE")

    with psutil.Popen(
        ["alembic", "-c", CONFIG_file, "upgrade", "head"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        _data, _err = proc.communicate()
        if _err:
            if b"Traceback" in _err:
                print("\tERROR; try next")
                continue
        PASSED = rev
        break

print("\n")
if PASSED:
    print("revision `%s` upgraded successfully" % PASSED)
else:
    print("no revisions upgraded")
