# stdlib
import datetime
from typing import List
from typing import Optional
from typing import TYPE_CHECKING

# pypi
import transaction
from zope.sqlalchemy import mark_changed

# local
from . import db as lib_db
from .errors import InvalidRequest

if TYPE_CHECKING:
    from pyramid.request import Request
    from paste.deploy.config import PrefixMiddleware
    from sqlalchemy.orm.session import Session
    from .config_utils import ApplicationSettings
    from ..model.objects import AcmeServer
    from ..model.objects import AcmeDnsServer
    from ..model.objects import OperationsEvent
    from ..model.objects import SystemConfiguration


# ==============================================================================


class ApiContext(object):
    """
    A context object
    API Calls can rely on this object to assist in logging.

    This implements an interface that guarantees several properties.  Substitutes may be used-

    :param request: - Pyramid `request` object
    :param timestamp: `datetime.datetime.now(datetime.timezone.utc)`
    :param dbSession: - SqlAlchemy `Session` object
    :param dbOperationsEvent: - the top OperationsEvent object for the active `request`, if any
    """

    dbOperationsEvent: Optional["OperationsEvent"] = None
    dbSession: "Session"
    timestamp: datetime.datetime
    request: Optional["Request"] = None
    config_uri: Optional[str] = None
    application_settings: Optional["ApplicationSettings"] = None
    app: Optional["PrefixMiddleware"] = None

    def __init__(
        self,
        request: Optional["Request"] = None,
        dbOperationsEvent: Optional["OperationsEvent"] = None,
        dbSession: Optional["Session"] = None,
        timestamp: Optional[datetime.datetime] = None,
        config_uri: Optional[str] = None,
        application_settings: Optional["ApplicationSettings"] = None,
        app: Optional["PrefixMiddleware"] = None,
    ):
        self.request = request
        self.dbOperationsEvent = dbOperationsEvent
        if dbSession:
            self.dbSession = dbSession
        if timestamp is None:
            timestamp = datetime.datetime.now(datetime.timezone.utc)
        self.timestamp = timestamp
        self.config_uri = config_uri
        self.application_settings = application_settings
        self.app = app

    @property
    def transaction_manager(self) -> "transaction.manager":
        # this is the pyramid_tm interface
        if self.request is None:
            raise ValueError("`self.request` not set")
        return self.request.tm

    def pyramid_transaction_commit(self) -> None:
        """this method does some ugly stuff to commit the pyramid transaction"""
        # mark_changed is oblivious to the `keep_session` we created the session with
        # raise ValueError("COMMIT")
        mark_changed(self.dbSession, keep_session=True)
        self.transaction_manager.commit()
        self.transaction_manager.begin()
        if self.dbOperationsEvent:
            self.dbOperationsEvent = self.dbSession.merge(self.dbOperationsEvent)

    def pyramid_transaction_rollback(self) -> None:
        """this method does some ugly stuff to rollback the pyramid transaction"""
        self.transaction_manager.abort()
        self.transaction_manager.begin()

    # -----

    # Official SystemConfigurations
    dbSystemConfiguration_autocert: Optional["SystemConfiguration"] = None
    dbSystemConfiguration_cin: Optional["SystemConfiguration"] = None
    dbSystemConfiguration_global: Optional["SystemConfiguration"] = None
    dbAcmeServers: Optional[List["AcmeServer"]] = None
    dbAcmeDnsServer_GlobalDefault: Optional["AcmeDnsServer"] = None

    # -----

    def _load_SystemConfiguration_autocert(
        self, force: bool = False
    ) -> Optional["SystemConfiguration"]:
        """
        Loads the autocert :class:`model.objects.SystemConfiguration` into the view's :attr:`.dbSystemConfiguration_autocert`.
        """
        if not self.dbSystemConfiguration_autocert or force:
            self.dbSystemConfiguration_autocert = (
                lib_db.get.get__SystemConfiguration__by_name(self, "autocert")
            )
        return self.dbSystemConfiguration_autocert

    def _load_SystemConfiguration_cin(
        self, force: bool = False
    ) -> Optional["SystemConfiguration"]:
        """
        Loads the certificate-if-needed :class:`model.objects.SystemConfiguration` into the view's :attr:`.dbSystemConfiguration_cin`.
        """
        if not self.dbSystemConfiguration_cin or force:
            self.dbSystemConfiguration_cin = (
                lib_db.get.get__SystemConfiguration__by_name(
                    self, "certificate-if-needed"
                )
            )
        return self.dbSystemConfiguration_cin

    def _load_SystemConfiguration_global(
        self, force: bool = False
    ) -> Optional["SystemConfiguration"]:
        """
        Loads the global :class:`model.objects.SystemConfiguration` into the view's :attr:`.dbSystemConfiguration_global`.
        """
        if not self.dbSystemConfiguration_global or force:
            self.dbSystemConfiguration_global = (
                lib_db.get.get__SystemConfiguration__by_name(self, "global")
            )
        return self.dbSystemConfiguration_global

    # -----

    def _ensure_nginx(self):
        """
        if nginx is not enabled, raise a HTTPFound to the admin dashboard
        """
        assert self.application_settings
        if not self.application_settings["enable_nginx"]:
            raise InvalidRequest("nginx is not enabled")

    def _ensure_redis(self):
        """
        if redis is not enabled, raise a HTTPFound to the admin dashboard
        """
        assert self.application_settings
        if not self.application_settings["enable_redis"]:
            raise InvalidRequest("redis is not enabled")

    def _load_AcmeDnsServer_GlobalDefault(
        self, force: bool = False
    ) -> Optional["AcmeDnsServer"]:
        """
        Loads the default :class:`model.objects.AcmeDnsServer` into the view's :attr:`.dbAcmeDnsServer_GlobalDefault`.
        """
        if not self.dbAcmeDnsServer_GlobalDefault or force:
            self.dbAcmeDnsServer_GlobalDefault = (
                lib_db.get.get__AcmeDnsServer__GlobalDefault(
                    self,
                )
            )
        return self.dbAcmeDnsServer_GlobalDefault

    def _load_AcmeServers(self, force: bool = False) -> Optional[List["AcmeServer"]]:
        """
        Loads the options for :class:`model.objects.AcmeServer` into the view's :attr:`.dbAcmeServers`.
        """
        if self.dbAcmeServers is None or force:
            self.dbAcmeServers = lib_db.get.get__AcmeServer__paginated(
                self, is_enabled=True
            )
        return self.dbAcmeServers
