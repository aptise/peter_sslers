# stdlib
import datetime
from typing import Any
from typing import Dict
from typing import Optional
from typing import TYPE_CHECKING

# pypi
from zope.sqlalchemy import mark_changed

if TYPE_CHECKING:
    from pyramid.request import Request
    from sqlalchemy.orm.session import Session
    import transaction

# ==============================================================================


PLACEHOLDER_TEXT__KEY = "*placeholder-key*"
PLACEHOLDER_TEXT__SHA1 = "*placeholder-sha1*"


# ------------------------------------------------------------------------------


def url_to_server(url: str) -> str:
    url = url.lower()
    if url[:8] == "https://":
        url = url[8:]
    elif url[:7] == "http://":
        url = url[7:]
    url = url.split("/")[0]
    return url


# ------------------------------------------------------------------------------


def new_event_payload_dict() -> Dict:
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
    :param dbOperationsEvent: - the top OperationsEvent object for the active `request`, if any
    """

    dbOperationsEvent: Optional[Any] = None
    dbSession: "Session"
    timestamp: datetime.datetime
    request: Optional["Request"] = None

    def __init__(
        self,
        request: Optional["Request"] = None,
        dbOperationsEvent=None,
        dbSession: Optional["Session"] = None,
        timestamp: Optional[datetime.datetime] = None,
    ):
        self.request = request
        self.dbOperationsEvent = dbOperationsEvent
        if dbSession:
            self.dbSession = dbSession
        if timestamp is None:
            timestamp = datetime.datetime.utcnow()
        self.timestamp = timestamp

    @property
    def transaction_manager(self) -> "transaction.manager":
        # this is the pyramid_tm interface
        if self.request is None:
            raise ValueError("self.request not set")
        return self.request.tm

    def pyramid_transaction_commit(self) -> None:
        """this method does some ugly stuff to commit the pyramid transaction"""
        # mark_changed is oblivious to the `keep_session` we created the session with
        mark_changed(self.dbSession, keep_session=True)
        self.transaction_manager.commit()
        self.transaction_manager.begin()

    def pyramid_transaction_rollback(self) -> None:
        """this method does some ugly stuff to rollback the pyramid transaction"""
        self.transaction_manager.abort()
        self.transaction_manager.begin()


# ------------------------------------------------------------------------------
