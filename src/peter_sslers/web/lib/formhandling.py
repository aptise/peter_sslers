# pypi
import formencode.rewritingparser
import pyramid_formencode_classic
from pyramid_formencode_classic.exceptions import FormFieldInvalid  # noqa: F401
from pyramid_formencode_classic.exceptions import FormInvalid  # noqa: F401


# ==============================================================================


TEMPLATE_FORMSTASH_ERRORS = (
    """<div class="alert alert-danger"><div class="control-group error">"""
    """<span class="help-inline">%(error)s</span>"""
    """</div></div>"""
)


def formatter_error(error):
    """
    custom error formatter
    """
    return (
        TEMPLATE_FORMSTASH_ERRORS
        % {"error": formencode.rewritingparser.html_quote(error)}
    ) + "\n"


def form_reprint(request, form_print_method, **kwargs):
    """
    overwrite the `pyramid_formencode_classic` version

    between `form_reprint` and `form_validate` some correlated magic happens:

    1. `form_validate` sets the formStash to render the 'main' error with a special attribute:
        formStash.html_error_placeholder_template = '<form:error name="%s" format="main"/>'
        formStash.html_error_placeholder_form_template = '<form:error name="%(field)s" format="main" data-formencode-form="%(form)s"/>'

    2. `form_reprint` registers a special error formatter for 'main'
    """
    kwargs["force_defaults"] = False
    kwargs["data_formencode_ignore"] = True

    # regular error formatters
    error_formatters = {"main": formatter_error}
    # override the default?
    if "default_error_formatter" in kwargs:
        default_formatter = kwargs.pop("default_error_formatter")
        error_formatters["default"] = default_formatter
    # override the main?
    if "main_error_formatter" in kwargs:
        main_formatter = kwargs.pop("main_error_formatter")
        error_formatters["main"] = main_formatter
    # pass it in
    kwargs["error_formatters"] = error_formatters

    if "auto_error_formatter" not in kwargs:
        # wait what? why?
        # by default we handle our own formatters.
        kwargs["auto_error_formatter"] = formatter_error

    return pyramid_formencode_classic.form_reprint(request, form_print_method, **kwargs)


def form_validate(request, **kwargs):
    """
    kwargs
        things of interest...
        is_unicode_params - webob 1.x+ transfers to unicode.

    see `form_reprint` for why some of the following are set.
    """
    if "is_unicode_params" not in kwargs:
        kwargs["is_unicode_params"] = True
    if "error_main_text" not in kwargs:
        kwargs["error_main_text"] = "There was an error with your form."
    (result, formStash) = pyramid_formencode_classic.form_validate(request, **kwargs)
    formStash.html_error_main_template = TEMPLATE_FORMSTASH_ERRORS
    formStash.html_error_placeholder_template = '<form:error name="%s" format="main"/>'
    formStash.html_error_placeholder_form_template = (
        '<form:error name="%(field)s" format="main" data-formencode-form="%(form)s"/>'
    )
    return (result, formStash)


def slurp_file_field(formStash, field):
    try:
        if field not in formStash.results:
            return None
        file = formStash.results[field].file
        return file.read()
    finally:
        file.close()
