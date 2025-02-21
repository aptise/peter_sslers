from . import _disable_warnings  # noqa: F401

# stdlib
import json
import os
import sys
from typing import List

# pypi
from pyramid.paster import get_appsettings
from pyramid.paster import setup_logging

# local
from ..models import get_engine
from ..models import get_session_factory
from ...lib import db as lib_db
from ...lib.config_utils import ApplicationSettings
from ...lib.utils import ApiContext
from ...lib.utils import RequestCommandline
from ...model.meta import Base
from ...model.utils import AcmeServerInput

# ==============================================================================


INSTRUCTIONS = """\

for "register" action:

<file> should be the path to a JSON encoded file that lists the servers to add
in the following format:

[
    {"name": "letsencrypt",
     "directory": "https://127.0.0.1:14000/dir",
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

"""


def usage(argv):
    cmd = os.path.basename(argv[0])
    print("usage: %s <config_uri> <action> <file>\n" % cmd)
    print('(example: "%s conf/example_development.ini register imports.json")\n' % cmd)
    print('(example: "%s conf/example_development.ini export exports.json")\n' % cmd)
    print(INSTRUCTIONS)
    sys.exit(1)


def main(argv=sys.argv):
    if len(argv) != 4:
        usage(argv)
    config_uri = argv[1]
    action = argv[2]
    if action not in ("register", "export"):
        raise ValueError("action must be `register` or `export`")
    fpath = argv[3]

    if action == "register":
        if not os.path.exists(fpath):
            raise ValueError("%s is not a file" % fpath)
        with open(fpath, "r") as fh:
            _data = fh.read()
        _acme_servers = json.loads(_data)
        servers: List[AcmeServerInput] = []
        for _server in _acme_servers:
            assert _server["name"] is not None
            assert _server["directory"] is not None
            assert _server["protocol"] is not None
            if _server.get("filepath_ca_cert_bundle") and _server.get("ca_cert_bundle"):
                raise ValueError(
                    "you may only supply `filepath_ca_cert_bundle` or ``ca_cert_bundle"
                )
            server = AcmeServerInput(
                name=_server["name"],
                directory=_server["directory"],
                protocol=_server["protocol"],
                is_supports_ari__version=_server.get("is_supports_ari__version"),
                filepath_ca_cert_bundle=_server.get("filepath_ca_cert_bundle"),
                ca_cert_bundle=_server.get("ca_cert_bundle"),
            )
            servers.append(server)

        if not servers:
            raise ValueError("servers not found")

        #
        setup_logging(config_uri)
        settings = get_appsettings(config_uri)

        engine = get_engine(settings)
        Base.metadata.create_all(engine)
        session_factory = get_session_factory(engine)

        application_settings = ApplicationSettings(config_uri)
        application_settings.from_settings_dict(settings)

        dbSession = session_factory()
        ctx = ApiContext(
            dbSession=dbSession,
            request=RequestCommandline(
                dbSession, application_settings=application_settings
            ),
            config_uri=config_uri,
            application_settings=application_settings,
        )

        lib_db.actions.register_acme_servers(ctx, servers, "user")

    elif action == "export":

        if os.path.exists(fpath):
            raise ValueError("filepath `%s` exists" % fpath)

        #
        setup_logging(config_uri)
        settings = get_appsettings(config_uri)

        engine = get_engine(settings)
        Base.metadata.create_all(engine)
        session_factory = get_session_factory(engine)

        application_settings = ApplicationSettings(config_uri)
        application_settings.from_settings_dict(settings)

        dbSession = session_factory()
        ctx = ApiContext(
            dbSession=dbSession,
            request=RequestCommandline(
                dbSession, application_settings=application_settings
            ),
            config_uri=config_uri,
            application_settings=application_settings,
        )

        exportServers = []
        dbServers = lib_db.get.get__AcmeServers__paginated(ctx, limit=None, offset=0)
        for _dbserver in dbServers:
            _exportServer = AcmeServerInput(
                name=_dbserver.name,
                directory=_dbserver.directory,
                protocol=_dbserver.protocol,
                is_supports_ari__version=_dbserver.is_supports_ari__version,
                ca_cert_bundle=_dbserver.server_ca_cert_bundle,
            )
            exportServers.append(_exportServer)

        with open(fpath, "w") as fh:
            fh.write(json.dumps(exportServers))
