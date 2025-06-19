# stdlib
import logging

# pyramid
from pyramid.httpexceptions import HTTPException
from pyramid.view import view_config

# ==============================================================================

log = logging.getLogger("peter_sslers.web")

# ------------------------------------------------------------------------------


@view_config(context=HTTPException)
def exception_view__upgrade(exc, request):
    """if we end with .json, serve json."""
    if (request.path[-5:]).lower() == ".json":
        request.environ["HTTP_ACCEPT"] = "application/json"
    return exc
