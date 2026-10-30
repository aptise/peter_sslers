import cert_utils

from .logging_utils import install_logging_safety

install_logging_safety()

__VERSION__ = "1.0.0dev0"
USER_AGENT = "peter_sslers/%s" % __VERSION__


if cert_utils.NEEDS_TEMPFILES:
    raise ValueError("cert_utils.NEEDS_TEMPFILES is no longer supported")
