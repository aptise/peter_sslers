# ==============================================================================

API_DOCS = {}

_elements_required = [
    "endpoint",
    "section",
    "about",
    "POST",  # if True, then POST is required
    "GET",  # if None, will generate docs on GET
]
_elements_optional = [
    "args",
    "example",
    "instructions",
    "form_fields",
    "variant_of",
]


def formatted_get_docs(request, endpoint):
    _endpoint_docs = API_DOCS.get(endpoint)
    if not _endpoint_docs:
        raise ValueError("could not find docs for: %s" % endpoint)
    docs = {}
    for field in ("instructions", "example", "examples"):
        if field in _endpoint_docs:
            docs[field] = []
            if not isinstance(_endpoint_docs[field], list):
                _endpoint_docs[field] = [
                    _endpoint_docs[field],
                ]
            for line in _endpoint_docs[field]:
                docs[field].append(line.replace("{ADMIN_PREFIX}", request.admin_url))
                if "%s" in line:
                    raise ValueError("malformed input")
    if "form_fields" in _endpoint_docs:
        docs["form_fields"] = _endpoint_docs["form_fields"]

    if _endpoint_docs.get("POST") is True:
        if "instructions" not in docs:
            docs["instructions"] = []
        docs["instructions"].append("HTTP POST required")
    return docs


def docify(endpoint_data):
    """A class :term:`decorator` which, when applied to a class, will"""
    endpoint = endpoint_data.get("endpoint")
    if not endpoint:
        raise ValueError("missing 'endpoint'")
    if endpoint in API_DOCS:
        raise ValueError("already registered API_DOCS endpoint: %s" % endpoint)
    if "variant_of" not in endpoint_data:
        for _elem in _elements_required:
            if _elem not in endpoint_data:
                raise ValueError("missing endpoint_data element: %s" % _elem)
    API_DOCS[endpoint] = endpoint_data

    def wrap(wrapped):
        return wrapped

    return wrap
