# pypi
import pyramid_formencode_classic as formhandling

# localapp
import lib.text


# ==============================================================================


class Handler(object):
    request = None

    def __init__(self, request):
        self.request = request
        self.request.formhandling = formhandling
        self.request.text_library = lib.text
