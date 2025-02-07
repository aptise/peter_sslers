# stdlib
import datetime
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
from ...model.meta import Base
from ...model.utils import AcmeServerInput

# ==============================================================================


INSTRUCTIONS = """\

<file> should be the path to a JSON encoded file that lists the servers to add
in the following format:

[
    {"name": "letsencrypt",
     "directory": "https://127.0.0.1:14000/dir",
     "protocol": "acme-v2",
     "is_supports_ari__version": "draft-ietf-acme-ari-03",
     "filepath_ca_cert_bundle": "/path/to/pem"
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

If an AcmeServer already exists on this server, the request will be considered
an "Edit" and not an "Addition".

Currently, the only fields supported by "Edit" are:
    filepath_ca_cert_bundle

"""


def usage(argv):
    cmd = os.path.basename(argv[0])
    print(
        "usage: %s <config_uri> <file>\n"
        '(example: "%s conf/example_development.ini")' % (cmd, cmd)
    )
    print(INSTRUCTIONS)
    sys.exit(1)


def main(argv=sys.argv):
    if len(argv) < 3:
        usage(argv)
    config_uri = argv[1]
    source_file = argv[2]
    if not os.path.exists(source_file):
        raise ValueError("%s is not a file" % source_file)
    with open(source_file, "r") as fh:
        _data = fh.read()
    _acme_servers = json.loads(_data)
    servers: List[AcmeServerInput] = []
    for _server in _acme_servers:
        assert _server["name"] is not None
        assert _server["directory"] is not None
        assert _server["protocol"] is not None
        server = AcmeServerInput(
            name=_server["name"],
            directory=_server["directory"],
            protocol=_server["protocol"],
            is_supports_ari__version=_server.get("is_supports_ari__version"),
            filepath_ca_cert_bundle=_server.get("filepath_ca_cert_bundle"),
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

    app_settings = ApplicationSettings(config_uri)
    app_settings.from_settings_dict(settings)

    dbSession = session_factory()
    ctx = ApiContext(
        timestamp=datetime.datetime.now(datetime.timezone.utc),
        dbSession=dbSession,
        request=None,
        config_uri=config_uri,
    )

    lib_db.actions.register_acme_servers(ctx, servers, "user")
