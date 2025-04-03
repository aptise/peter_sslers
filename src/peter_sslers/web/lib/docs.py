# stdlib
import logging
from typing import Dict

# ==============================================================================

log = logging.getLogger(__name__)

# ------------------------------------------------------------------------------


API_DOCS: Dict = {}

_elements_required = [
    "about",
    "endpoint",
    "GET",  # if None, will generate docs on GET
    "POST",  # if True, then POST is required
    "section",
]
_elements_optional = [
    "args",
    "example",
    "form_fields",
    "instructions",
    "notes",
    "requirements",
    "variant_of",
]
_elements_dict = [
    "form_fields",
    "valid_options",
]
_elements_list = [
    "examples",
    "form_fields_related",
    "instructions",
    "notes",
    "requirements",
]
_elements_disallowed = [
    "extra",
]


def formatted_get_docs(view_instance, endpoint):
    """
    :param view_instance: a Pyramid view instance
    :param endpoint: the route name of the endpoint
    :type endpoint: str
    """
    _endpoint_docs = API_DOCS.get(endpoint)
    if not _endpoint_docs:
        raise ValueError("could not find docs for: %s" % endpoint)

    def _instructions_append(_msg):
        if "instructions" not in docs:
            docs["instructions"] = []
        docs["instructions"].append(_msg)

    def _process_line(_line):
        "this is a microtemplating routine"
        _line = _line.replace("{ADMIN_PREFIX}", view_instance.request.admin_url)
        if "%s" in _line:
            raise ValueError("malformed input")
        return _line

    # what we're generating...
    docs = {}

    for _field in _elements_dict:
        if _field in _endpoint_docs:
            docs[_field] = _endpoint_docs[_field].copy()

    for _field in _elements_list:
        if _field in _endpoint_docs:
            if not isinstance(_endpoint_docs[_field], list):
                _endpoint_docs[_field] = [
                    _endpoint_docs[_field],
                ]
            docs[_field] = _endpoint_docs[_field][:]

    for field in ("instructions", "example", "examples"):
        if field in _endpoint_docs:
            if isinstance(_endpoint_docs[field], list):
                docs[field] = [_process_line(line) for line in _endpoint_docs[field]]
            else:
                docs[field] = _endpoint_docs[field]

    # define these with a placeholder like "{RENDER_ON_REQUEST}"
    if "valid_options" in docs:

        # !!!: Render `acme_server_id`
        try:
            if "acme_server_id" in docs["valid_options"]:
                docs["valid_options"]["acme_server_id"] = {
                    i.id: "%s (%s)" % (i.name, i.url)
                    for i in view_instance.request.api_context.dbAcmeServers
                }
        except Exception as exc:  # noqa: F841
            log.critical("@docify error: valid_options:acme_server_id %s", endpoint)
            log.critical(exc)
            pass

        # !!!: Render `acme_dns_server_id`
        try:
            if "acme_dns_server_id" in docs["valid_options"]:
                docs["valid_options"]["acme_dns_server_id"] = [
                    i.id for i in view_instance.dbAcmeDnsServers_all
                ]
        except Exception as exc:  # noqa: F841
            log.critical("@docify error: valid_options:acme_dns_server_id %s", endpoint)
            log.critical(exc)
            pass

        # !!!: Render `AcmeAccounts`
        try:
            if "AcmeAccounts" in docs["valid_options"]:
                if (
                    docs["valid_options"]["AcmeAccounts"]
                    == "{RENDER_ON_REQUEST::as_json_label}"
                ):
                    docs["valid_options"]["AcmeAccounts"] = []
                    if view_instance.dbAcmeAccounts_all:
                        docs["valid_options"]["AcmeAccounts"] = [
                            i.as_json_labels for i in view_instance.dbAcmeAccounts_all
                        ]
        except Exception as exc:  # noqa: F841
            log.critical("@docify error: valid_options:AcmeAccounts %s", endpoint)
            log.critical(exc)
            pass

        # !!!: Render `SystemConfiguration_Global`
        try:
            if "SystemConfigurations" in docs["valid_options"]:
                docs["valid_options"]["SystemConfigurations"] = {}

                # !!! Required- global
                dbSystemConfiguration_global = (
                    view_instance.request.api_context.dbSystemConfiguration_global
                )
                if dbSystemConfiguration_global:
                    docs["valid_options"]["SystemConfigurations"][
                        "global"
                    ] = dbSystemConfiguration_global.as_json_docs
                # !!!: Conditional- Autocert
                if view_instance.request.api_context.dbSystemConfiguration_autocert:
                    docs["valid_options"]["SystemConfigurations"][
                        "autocert"
                    ] = (
                        view_instance.request.api_context.dbSystemConfiguration_autocert.as_json_docs
                    )
                # !!!: Conditional- CertificateIfNeeeded
                if view_instance.request.api_context.dbSystemConfiguration_cin:
                    docs["valid_options"]["SystemConfigurations"][
                        "certificate-if-needed"
                    ] = (
                        view_instance.request.api_context.dbSystemConfiguration_cin.as_json_docs
                    )

        except Exception as exc:  # noqa: F841
            log.critical(
                "@docify error: valid_options:SystemConfiguration_Global %s", endpoint
            )
            log.critical(exc)
            pass

    if _endpoint_docs.get("POST") is True:
        _instructions_append("HTTP POST required")
    system_requires = _endpoint_docs.get("system.requires")
    if system_requires:
        if "dbSystemConfiguration_autocert" in system_requires:
            if (
                view_instance.request.api_context.dbSystemConfiguration_autocert is None
            ) or (
                view_instance.request.api_context.dbSystemConfiguration_autocert.is_configured
                is not True
            ):
                _instructions_append(
                    "IMPORTANT: The `autocert` System Configurations MUST be configured."
                )

    return docs


def docify(endpoint_data):
    """
    A class :term:`decorator` which, when applied to a class,
    will register a dict of documentation for an "endpoint" into the
    centralized API_DOCS variable

    :param endpoint_data: a dict of structured data providing documentation for
        the endpoint.
    :type endpoint_data: dict
    """
    endpoint = endpoint_data.get("endpoint")
    if not endpoint:
        raise ValueError("missing 'endpoint'")
    if endpoint in API_DOCS:
        raise ValueError("already registered API_DOCS endpoint: %s" % endpoint)
    if "variant_of" not in endpoint_data:
        for _elem in _elements_required:
            if _elem not in endpoint_data:
                raise ValueError("missing endpoint_data element: %s" % _elem)
    for _elem in _elements_disallowed:
        if _elem in endpoint_data:
            raise ValueError("found invalid endpoint_data element: %s" % _elem)
    API_DOCS[endpoint] = endpoint_data

    def wrap(wrapped):
        return wrapped

    return wrap
