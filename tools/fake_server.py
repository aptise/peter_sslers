"""
`fake_serverpy`

usage:
    python fake_server.py
    python fake_server.py 8080

purpose:
    this spins up a server with some simple routes for testing purposes with
    your webserver/proxy:
    * /
    * /.well-known/acme-challenge/{challenge}
    * /.well-known/public/whoami
    * /.well-known/admin

By default, the server will run on 127.0.0.1:7201, which is the default port
used by the peter_sslers Pyramid application.

    python fake_server.py

To run on an alternate port, you can invoke this script with a single argument
to identify the port. For example, to run on 127.0.0.1:8080 :

    python fake_server.py 8080

requirements:

    This script requires the Pyramid framework. To install it:

        pip install pyramid

This script is intended as a lightweight tool that can be used to setup your
integration, without exposing peter_sslers.  It is also useful to troubleshoot
proxy issues with Certbot and other ACME clients.

The server will respond to requests with the following header to more easily
identify responses that it generates.

    X-Peter-SSLers: fakeserver
"""

# stlib
import sys
from wsgiref.simple_server import make_server

# pypi
from pyramid.config import Configurator
from pyramid.response import Response

# ==============================================================================


def header_tween_factory(handler, registry):
    def header_tween(request):
        response = handler(request)
        response.headers["X-Peter-SSLers"] = "fakeserver"
        return response

    return header_tween


def hello_world(request):
    print("Incoming request")
    return Response("<body><h1>Hello World!</h1></body>")


def public_challenge(request):
    print("Incoming request")
    return Response(
        "<body><h1>public_challenge</h1>%s</body>" % request.matchdict["challenge"]
    )


def public_whoami(request):
    print("Incoming request - public_whoami")
    return Response(
        "<body><h1>public_whoami</h1>%s</body>" % request.active_domain_name
    )


def admin(request):
    print("Incoming request - admin")
    return Response("<body><h1>admin</h1>%s</body>" % request.active_domain_name)


if __name__ == "__main__":
    print("running test server...")

    PORT = 7201
    if len(sys.argv) == 2:
        PORT = int(sys.argv[1])
        print("... on CUSTOM port %s" % PORT)
    else:
        print("... on DEFAULT port %s" % PORT)

    config = Configurator()
    config.add_tween(".header_tween_factory")
    config.add_route("hello", "/")
    config.add_route("public_challenge", "/.well-known/acme-challenge/{challenge}")
    config.add_route("public_whoami", "/.well-known/public/whoami")
    config.add_route("admin", "/.well-known/admin")

    config.add_view(hello_world, route_name="hello")
    config.add_view(public_challenge, route_name="public_challenge")
    config.add_view(public_whoami, route_name="public_whoami")
    config.add_view(admin, route_name="admin")

    config.add_request_method(
        lambda request: request.environ["HTTP_HOST"].split(":")[0],
        "active_domain_name",
        reify=True,
    )

    app = config.make_wsgi_app()
    server = make_server("127.0.0.1", PORT, app)
    server.serve_forever()
