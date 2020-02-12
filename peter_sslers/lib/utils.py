# stdlib
import hashlib
import logging
import re

# pypi
import six
from zope.sqlalchemy import mark_changed


# ==============================================================================


RE_domain = re.compile(r"^(?:[\w\-]+\.)+[\w]{2,5}$")


# ==============================================================================


def validate_domains(domain_names):
    """
    Ensures each items of the iterable `domain_names` matches a regular expression.

    :param domain_names: (required) An iterable list of strings
    """
    for d in domain_names:
        if not RE_domain.match(d):
            raise ValueError("invalid name: `%s`", d)
    return True


def domains_from_list(domain_names):
    """
    Turns a list of strings into a standardized list of domain names.

    Will raise Exceptions if non-conforming elements are encountered.

    :param domain_names: (required) An iterable list of strings
    """
    domain_names = [d for d in [d.strip().lower() for d in domain_names] if d]
    # make the list unique
    domain_names = list(set(domain_names))
    # validate the list
    validate_domains(domain_names)
    return domain_names


def domains_from_string(text):
    """
    :param text: (required) Turns a comma-separated-list of domain names into a list
    """
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

    :param request: - Pyramid `request` object
    :param timestamp: `datetime.datetime.utcnow()`
    :param dbSession: - SqlAlchemy `Session` object
    :param dbSessionLogger: - SqlAlchemy `Session` object with autocommit
    :param dbOperationsEvent: - the top OperationsEvent object for the active `request`, if any
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

    @property
    def transaction_manager(self):
        # this is the pyramid_tm interface
        return self.request.tm

    def pyramid_transaction_commit(self):
        """this method does some ugly stuff to commit the pyramid transaction"""
        mark_changed(self.dbSession)
        self.transaction_manager.commit()
        self.transaction_manager.begin()


# ------------------------------------------------------------------------------
