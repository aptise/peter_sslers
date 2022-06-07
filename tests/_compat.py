import six
from six import PY2  # noqa: F401
from six.moves import http_client  # noqa: F401
from six.moves.urllib.response import addinfourl  # noqa: F401

if six.PY3:
    from io import BytesIO  # noqa: F401
    from io import StringIO  # noqa: F401
else:
    BytesIO = None  # noqa: F401
    from StringIO import StringIO  # noqa: F401
