# stdlib
import hashlib
import logging
import re

# pypi
import six


# ==============================================================================


RE_domain = re.compile("^(?:[\w\-]+\.)+[\w]{2,5}$")


# ==============================================================================


def validate_domains(domain_names):
    for d in domain_names:
        if not RE_domain.match(d):
            raise ValueError("invalid name: `%s`", d)
    return True


def domains_from_list(domain_names):
    domain_names = [d for d in [d.strip().lower() for d in domain_names] if d]
    # make the list unique
    domain_names = list(set(domain_names))
    # validate the list
    validate_domains(domain_names)
    return domain_names


def domains_from_string(text):
    # generate list
    domain_names = text.split(",")
    return domains_from_list(domain_names)


def md5_text(text):
    if six.PY3:
        if isinstance(text, str):
            text = text.encode()
    return hashlib.md5(text).hexdigest()


# ------------------------------------------------------------------------------


def new_event_payload_dict():
    return {"v": 1}


# ------------------------------------------------------------------------------


class ApiContext(object):
    """
    A context object
    API Calls can rely on this object to assist in logging.

    This implements an interface that guarantees several properties.  Substitutes may be used-

    :request: - pyramid request object
    :timestamp: `datetime.datetime.utcnow()`
    :dbSession: - sqlalchemy `session` object
    :dbSessionLogger: - sqlalchemy `session` object with autocommit
    :dbOperationsEvent: - a topline SslOperationsEvent object for this request, if any
    """

    dbOperationsEvent = None
    dbSession = None
    dbSessionLogger = None
    timestamp = None
    request = None

    def __init__(
        self,
        request=None,
        dbOperationsEvent=None,
        dbSession=None,
        dbSessionLogger=None,
        timestamp=None,
    ):
        self.request = request
        self.dbOperationsEvent = dbOperationsEvent
        self.dbSession = dbSession
        self.dbSessionLogger = dbSessionLogger
        self.timestamp = timestamp


# ------------------------------------------------------------------------------
