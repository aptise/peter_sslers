from . import _disable_warnings  # noqa: F401

# stdlib
import json  # noqa: I100
import os
import sys
from typing import List

# pypi

# local
from ...lib import db as lib_db
from ...lib.utils import new_scripts_setup
from ...lib.utils import validate_config_uri
from ...model.utils import AcmeServerInput

# ==============================================================================


INSTRUCTIONS = """\

for "register" action:

<file> should be the path to a JSON encoded file that lists the servers to add
in the following format:

[
    {"name": "letsencrypt",
     "directory_url": "https://127.0.0.1:14000/dir",
     "protocol": "acme-v2",
     "is_supports_ari__version": "draft-ietf-acme-ari-03",
     "filepath_ca_cert_bundle": "/path/to/pem"
     "ca_cert_bundle": "PEM_ENCODED"
     }
]

Note JSON encoding does not have a trailing , in lists. Utilizing a trailing
comma will break the json loading.

These fields are required:
    name
    directory
    protocol

`filepath_ca_cert_bundle` is a filepath to CA Trust Bundle for this server.
This is NOT the Trusted Root used by the AcmeServer to sign your certificates;
instead it is the Trusted Root root used by the AcmeServer to encrypt HTTPS.
This is usually only needed for Private CAs and Test systems.  The filepath
will be read and contents associated with the ACME Server; it only needs to
be accessible during this import.

Alternately, `ca_cert_bundle` can be provided.  Only one can be provided per
input.

If an AcmeServer already exists on this server, the request will be considered
an "Edit" and not an "Addition".

Currently, the only fields supported by "Edit" are:
    filepath_ca_cert_bundle
    ca_cert_bundle


for "export" action:

<file> should be the path to a target file that does not exist.

the routine will dump all servers into a json encoding, in a format compatible
with the `register` action


for "reset" action:

nothing required.


"""


def usage(argv):
    cmd = os.path.basename(argv[0])
    print("usage: %s <config_uri> <action> <file>\n" % cmd)
    print('(example: "%s data_development/config.ini register imports.json")\n' % cmd)
    print('(example: "%s data_development/config.ini export exports.json")\n' % cmd)
    print('(example: "%s data_development/config.ini reset")\n' % cmd)
    print(INSTRUCTIONS)
    sys.exit(1)


def main(argv=sys.argv):
    if len(argv) not in (3, 4):
        usage(argv)
        if len(argv) == 3 and argv[2] != "reset":
            usage(argv)
    config_uri = argv[1]
    config_uri = validate_config_uri(config_uri)
    action = argv[2]
    if action not in ("register", "export", "reset"):
        raise ValueError("action must be `register`, `export` or `reset`")
    fpath = argv[3] if action in ("register", "export") else None

    if action == "register":
        assert isinstance(fpath, str)  # typing
        if not os.path.exists(fpath):
            raise ValueError("%s is not a file" % fpath)
        with open(fpath, "r") as fh:
            _data = fh.read()
        _acme_servers = json.loads(_data)
        servers: List[AcmeServerInput] = []
        for _server in _acme_servers:
            assert _server["name"] is not None
            assert _server["directory_url"] is not None
            assert _server["protocol"] is not None
            if _server.get("filepath_ca_cert_bundle") and _server.get("ca_cert_bundle"):
                raise ValueError(
                    "you may only supply `filepath_ca_cert_bundle` or ``ca_cert_bundle"
                )
            server = AcmeServerInput(
                name=_server["name"],
                directory_url=_server["directory_url"],
                protocol=_server["protocol"],
                is_supports_ari__version=_server.get("is_supports_ari__version"),
                is_retry_challenges=_server.get("is_retry_challenges"),
                filepath_ca_cert_bundle=_server.get("filepath_ca_cert_bundle"),
                ca_cert_bundle=_server.get("ca_cert_bundle"),
            )
            servers.append(server)

        if not servers:
            raise ValueError("servers not found")

        ctx = new_scripts_setup(config_uri, options=None)
        lib_db.actions.register_acme_servers(ctx, servers, "user")
        ctx.pyramid_transaction_commit()

    elif action == "export":
        assert isinstance(fpath, str)  # typing
        if os.path.exists(fpath):
            raise ValueError("filepath `%s` exists" % fpath)

        ctx = new_scripts_setup(config_uri, options=None)

        exportServers = []
        dbServers = lib_db.get.get__AcmeServer__paginated(ctx, limit=None, offset=0)
        for _dbserver in dbServers:
            _exportServer = AcmeServerInput(
                name=_dbserver.name,
                directory_url=_dbserver.directory_url,
                protocol=_dbserver.protocol,
                is_supports_ari__version=_dbserver.is_supports_ari__version,
                ca_cert_bundle=_dbserver.server_ca_cert_bundle,
            )
            exportServers.append(_exportServer)

        with open(fpath, "w") as fh:
            fh.write(json.dumps(exportServers))

    elif action == "reset":
        ctx = new_scripts_setup(config_uri, options=None)
        lib_db.actions.register_acme_servers(ctx, lib_db._setup.acme_servers, "reset")
        ctx.pyramid_transaction_commit()
