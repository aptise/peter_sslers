import cert_utils

__VERSION__ = "1.0.0"
USER_AGENT = "peter_sslers/%s" % __VERSION__


if cert_utils.NEEDS_TEMPFILES:
    raise ValueError("cert_utils.NEEDS_TEMPFILES is no longer supported")
