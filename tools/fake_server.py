from __future__ import print_function

"""
fake_server

usage:
    python fake_server.py

purpose:
    this spins up a server with some simple routes for testing purposes with your webserver/proxy
    * /
    * /.well-known/acme-challenge/{challenge}
    * /.well-known/public/whoami
    * /.well-known/admin

This is intended as a lightweight tool that can be used to setup your integration, without exposing peter_sselers

You may need to edit this to change your proxy ports location
"""


from wsgiref.simple_server import make_server
from pyramid.config import Configurator
from pyramid.response import Response


# ==============================================================================


def header_tween_factory(handler, registry):
    def header_tween(request):
        response = handler(request)
        response.headers['X-Peter-SSLers'] = "fakeserver"
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
    config = Configurator()
    config.add_tween('.header_tween_factory')
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
    server = make_server("127.0.0.1", 7201, app)
    server.serve_forever()
