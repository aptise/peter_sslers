import logging
log = logging.getLogger(__name__)

# pyramid
from pyramid.httpexceptions import HTTPException
from pyramid.view import view_config


# ==============================================================================


@view_config(context=HTTPException)
def exception_view__dispatch(exc, request):
    """if we end with .json, serve json."""
    if (request.path[-5:]).lower() == '.json':
        request.environ['HTTP_ACCEPT'] = "application/json"
        return exc
    return exc


@view_config(context=HTTPException, renderer='json', accept="application/json")
def exception_view__JSON(exc, request):
    """This view will generate a custom json error"""
    rval = {'error': exc.message,
            'status_code': None,
            }
    if exc.status_code is not None:
        request.response.status_code = exc.status_code
        rval['status_code'] = exc.status_code
    return rval

