# stdlib
import hashlib


# ==============================================================================


def md5_text(text):
    return hashlib.md5(text).hexdigest()
