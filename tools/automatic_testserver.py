"""
this script spins up the actual testserver used by the automatic systems
"""

from peter_sslers.lib.db.actions import _create_public_server
from pyramid.paster import get_appsettings

import sys

conf = sys.argv[1]
print("conf:", conf)

try:
    settings = get_appsettings(conf)
    print(settings)
    wsgi_server = _create_public_server(settings)
    print(wsgi_server)
    while True:
        pass
finally:
    wsgi_server.shutdown()
