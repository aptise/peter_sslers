# stdlib
import datetime
import logging
from typing import Dict
from typing import Optional
from typing import TYPE_CHECKING

# localapp
from .. import utils
from ...model import objects as model_objects
from ...model import utils as model_utils

if TYPE_CHECKING:
    from ...model.objects import AcmeAccount
    from ...model.objects import AcmeAccountKey
    from ...model.objects import AcmeAuthorization
    from ...model.objects import AcmeChallenge
    from ...model.objects import AcmeDnsServer
    from ...model.objects import AcmeEventLog
    from ...model.objects import AcmeOrder
    from ...model.objects import AcmeServer
    from ...model.objects import CertificateCA
    from ...model.objects import CertificateCAChain
    from ...model.objects import CertificateRequest
    from ...model.objects import CertificateSigned
    from ...model.objects import CoverageAssuranceEvent
    from ...model.objects import Domain
    from ...model.objects import OperationsEvent
    from ...model.objects import OperationsObjectEvent
    from ...model.objects import PrivateKey
    from ...model.objects import RenewalConfiguration
    from ...model.objects import UniqueFQDNSet
    from ...model.objects import UniquelyChallengedFQDNSet
    from ..utils import ApiContext

# ==============================================================================

log = logging.getLogger(__name__)
# logging.getLogger("sqlalchemy.engine").setLevel(logging.INFO)

# ------------------------------------------------------------------------------


class AcmeLogger(object):
    """
    AcmeLogger is an interface used to log interactions with the LetsEncrypt API
    This is designed to monitor usage and potential throttling concerns
    """

    ctx: "ApiContext"
    dbAcmeAccount: "AcmeAccount"
    dbAcmeOrder: Optional["AcmeOrder"] = None  # only set on orders

    def __init__(
        self,
        ctx: "ApiContext",
        dbAcmeAccount: "AcmeAccount",
    ):
        """
        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param dbAcmeAccount: (optional) The :class:`model.objects.AcmeAccount`
        """
        self.ctx = ctx
        self.dbAcmeAccount = dbAcmeAccount

    @property
    def dbSession(self):
        return self.ctx.dbSession

    def register_dbAcmeOrder(
        self,
        dbAcmeOrder: "AcmeOrder",
    ) -> None:
        """
        Registers a :class:`model.objects.AcmeOrder` onto the event logger.

        :param dbAcmeOrder: (required) The :class:`model.objects.AcmeOrder`
        """
        self.dbAcmeOrder = dbAcmeOrder

    def log_newAccount(
        self,
        acme_version: str,
        transaction_commit: Optional[bool] = None,
    ) -> "AcmeEventLog":
        """
        Logs a call for the ACME Registration event

        :param acme_version: (required) The ACME version of the API we are using.
        :param transaction_commit: (option) Boolean. If True, commit the transaction
        """
        # ???: update with result?
        if acme_version != "v2":
            raise ValueError("invalid `acme_version``: %s" % acme_version)

        acme_event_id = model_utils.AcmeEvent.from_string("v2|newAccount")
        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.acme_event_id = acme_event_id
        dbAcmeEventLog.timestamp_event = datetime.datetime.now(datetime.timezone.utc)
        dbAcmeEventLog.acme_account_id = self.dbAcmeAccount.id
        self.dbSession.add(dbAcmeEventLog)
        self.dbSession.flush()

        # persist to the database
        if transaction_commit:
            self.ctx.pyramid_transaction_commit()

        return dbAcmeEventLog

    def log_deactivateAccount(
        self,
        acme_version: str,
        transaction_commit: Optional[bool] = None,
    ) -> "AcmeEventLog":
        """
        Logs a call for the ACME Deactivation event

        :param acme_version: (required) The ACME version of the API we are using.
        :param transaction_commit: (option) Boolean. If True, commit the transaction
        """
        # ???: update with result?
        if acme_version != "v2":
            raise ValueError("invalid `acme_version``: %s" % acme_version)

        acme_event_id = model_utils.AcmeEvent.from_string("v2|Account-deactivate")
        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.acme_event_id = acme_event_id
        dbAcmeEventLog.timestamp_event = datetime.datetime.now(datetime.timezone.utc)
        dbAcmeEventLog.acme_account_id = self.dbAcmeAccount.id
        self.dbSession.add(dbAcmeEventLog)
        self.dbSession.flush()

        # persist to the database
        if transaction_commit:
            self.ctx.pyramid_transaction_commit()

        return dbAcmeEventLog

    def log_newOrder(
        self,
        acme_version: str,
        dbUniqueFQDNSet: "UniqueFQDNSet",
        transaction_commit: Optional[bool] = None,
    ) -> "AcmeEventLog":
        """
        Logs a call for the ACME Registration event

        :param acme_version: (required) The ACME version of the API we are using.
        :param dbUniqueFQDNSet: (required) The :class:`model.objects.UniqueFQDNSet` for the new order
        :param transaction_commit: (option) Boolean. If True, commit the transaction

        This WILL NOT SET:
            `dbAcmeEventLog.acme_order_id` - must be set AFTER creating the database object
            `self.dbAcmeOrder` - call `AcmeLogger.register_dbAcmeOrder(dbAcmeOrder)`
        """
        if acme_version != "v2":
            raise ValueError("invalid version: %s" % acme_version)
        acme_event_id = model_utils.AcmeEvent.from_string("v2|newOrder")

        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.acme_event_id = acme_event_id
        dbAcmeEventLog.timestamp_event = datetime.datetime.now(datetime.timezone.utc)
        dbAcmeEventLog.acme_account_id = self.dbAcmeAccount.id
        dbAcmeEventLog.unique_fqdn_set_id = dbUniqueFQDNSet.id
        self.dbSession.add(dbAcmeEventLog)
        self.dbSession.flush()

        # persist to the database
        if transaction_commit:
            self.ctx.pyramid_transaction_commit()

        return dbAcmeEventLog

    def log_order_load(
        self,
        acme_version: str,
        dbAcmeOrder: "AcmeOrder",
        transaction_commit: Optional[bool] = None,
    ) -> "AcmeEventLog":
        """
        Logs a call for the ACME order's endpint

        :param acme_version: (required) The ACME version of the API we are using.
        :param dbAcmeOrder: (required) The :class:`model.objects.AcmeOrder` for the existing order
        """
        if acme_version != "v2":
            raise ValueError("invalid version: %s" % acme_version)

        acme_event_id = model_utils.AcmeEvent.from_string("v2|-order-location")

        # ensure we have the right order
        if self.dbAcmeOrder:
            if self.dbAcmeOrder.id != dbAcmeOrder.id:
                raise ValueError("Received an unexpected AcmeOrder")

        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.acme_event_id = acme_event_id
        dbAcmeEventLog.timestamp_event = datetime.datetime.now(datetime.timezone.utc)
        dbAcmeEventLog.acme_account_id = self.dbAcmeAccount.id
        dbAcmeEventLog.acme_order_id = dbAcmeOrder.id
        dbAcmeEventLog.unique_fqdn_set_id = dbAcmeOrder.unique_fqdn_set_id
        self.dbSession.add(dbAcmeEventLog)
        self.dbSession.flush()

        # persist to the database
        if transaction_commit:
            self.ctx.pyramid_transaction_commit()

        return dbAcmeEventLog

    def log_authorization_request(
        self,
        acme_version: str,
        dbAcmeAuthorization: "AcmeAuthorization",
        transaction_commit: Optional[bool] = None,
    ) -> "AcmeEventLog":
        """
        Logs a new authorization and creates a challenge object

        :param acme_version: (required) The ACME version of the API we are using.
        :param dbAcmeAuthorization: (required) The :class:`model.objects.AcmeAuthorization` we fetched
        :param transaction_commit: (option) Boolean. If True, commit the transaction
        """
        if acme_version != "v2":
            raise ValueError("invalid version: %s" % acme_version)

        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.timestamp_event = datetime.datetime.now(datetime.timezone.utc)
        dbAcmeEventLog.acme_event_id = model_utils.AcmeEvent.from_string(
            "v2|-authorization-request"
        )
        dbAcmeEventLog.acme_account_id = self.dbAcmeAccount.id
        dbAcmeEventLog.acme_authorization_id = dbAcmeAuthorization.id
        dbAcmeEventLog.acme_order_id = self.dbAcmeOrder.id if self.dbAcmeOrder else None
        dbAcmeEventLog.unique_fqdn_set_id = (
            self.dbAcmeOrder.unique_fqdn_set_id if self.dbAcmeOrder else None
        )
        self.dbSession.add(dbAcmeEventLog)
        self.dbSession.flush()

        # persist to the database
        if transaction_commit:
            self.ctx.pyramid_transaction_commit()

        return dbAcmeEventLog

    def log_authorization_deactivate(
        self,
        acme_version: str,
        dbAcmeAuthorization: "AcmeAuthorization",
        transaction_commit: Optional[bool] = None,
    ) -> "AcmeEventLog":
        if acme_version != "v2":
            raise ValueError("invalid version: %s" % acme_version)

        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.timestamp_event = datetime.datetime.now(datetime.timezone.utc)
        dbAcmeEventLog.acme_event_id = model_utils.AcmeEvent.from_string(
            "v2|-authorization-deactivate"
        )
        dbAcmeEventLog.acme_account_id = self.dbAcmeAccount.id
        dbAcmeEventLog.acme_authorization_id = dbAcmeAuthorization.id
        dbAcmeEventLog.acme_order_id = self.dbAcmeOrder.id if self.dbAcmeOrder else None
        dbAcmeEventLog.unique_fqdn_set_id = (
            self.dbAcmeOrder.unique_fqdn_set_id if self.dbAcmeOrder else None
        )
        self.dbSession.add(dbAcmeEventLog)
        self.dbSession.flush()

        # persist to the database
        if transaction_commit:
            self.ctx.pyramid_transaction_commit()

        return dbAcmeEventLog

    def log_challenge_PostAsGet(
        self,
        acme_version: str,
        dbAcmeChallenge: "AcmeChallenge",
        transaction_commit: Optional[bool] = None,
    ) -> "AcmeEventLog":
        """
        :param acme_version: (required) The ACME version of the API we are using.
        :param dbAcmeChallenge: (required) The :class:`model.objects.AcmeChallenge` we asked to trigger
        :param transaction_commit: (option) Boolean. If True, commit the transaction
        """
        if acme_version != "v2":
            raise ValueError("invalid version: %s" % acme_version)

        assert self.dbAcmeOrder

        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.timestamp_event = datetime.datetime.now(datetime.timezone.utc)
        dbAcmeEventLog.acme_event_id = model_utils.AcmeEvent.from_string(
            "v2|-challenge-PostAsGet"
        )
        dbAcmeEventLog.acme_account_id = self.dbAcmeAccount.id
        dbAcmeEventLog.acme_authorization_id = dbAcmeChallenge.acme_authorization_id
        dbAcmeEventLog.acme_challenge_id = dbAcmeChallenge.id
        dbAcmeEventLog.acme_order_id = self.dbAcmeOrder.id
        dbAcmeEventLog.unique_fqdn_set_id = (
            self.dbAcmeOrder.unique_fqdn_set_id if self.dbAcmeOrder else None
        )
        self.dbSession.add(dbAcmeEventLog)
        self.dbSession.flush()

        # persist to the database
        if transaction_commit:
            self.ctx.pyramid_transaction_commit()

        return dbAcmeEventLog

    def log_challenge_trigger(
        self,
        acme_version: str,
        dbAcmeChallenge: "AcmeChallenge",
        transaction_commit: Optional[bool] = None,
    ) -> "AcmeEventLog":
        """
        Logs a new authorization and creates a challenge object

        :param acme_version: (required) The ACME version of the API we are using.
        :param dbAcmeChallenge: (required) The :class:`model.objects.AcmeChallenge` we asked to trigger
        :param transaction_commit: (option) Boolean. If True, commit the transaction
        """
        if acme_version != "v2":
            raise ValueError("invalid version: %s" % acme_version)

        assert self.dbAcmeOrder

        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.timestamp_event = datetime.datetime.now(datetime.timezone.utc)
        dbAcmeEventLog.acme_event_id = model_utils.AcmeEvent.from_string(
            "v2|-challenge-trigger"
        )
        dbAcmeEventLog.acme_account_id = self.dbAcmeAccount.id
        dbAcmeEventLog.acme_authorization_id = dbAcmeChallenge.acme_authorization_id
        dbAcmeEventLog.acme_challenge_id = dbAcmeChallenge.id
        dbAcmeEventLog.acme_order_id = self.dbAcmeOrder.id
        dbAcmeEventLog.unique_fqdn_set_id = (
            self.dbAcmeOrder.unique_fqdn_set_id if self.dbAcmeOrder else None
        )
        self.dbSession.add(dbAcmeEventLog)
        self.dbSession.flush()

        # persist to the database
        if transaction_commit:
            self.ctx.pyramid_transaction_commit()

        return dbAcmeEventLog

    def log_challenge_error(
        self,
        acme_version: str,
        dbAcmeChallenge: "AcmeChallenge",
        failtype: str,
        transaction_commit: Optional[bool] = None,
    ) -> "AcmeEventLog":
        """
        Logs a challenge as error

        :param acme_version: (required) The ACME version of the API we are using.
        :param dbAcmeChallenge: (required) The :class:`model.objects.AcmeChallenge` we asked to trigger
        :param failtype: (required) A string from :class:`model_utils.AcmeChallengeFailType`
        :param transaction_commit: (option) Boolean. If True, commit the transaction
        """
        if acme_version != "v2":
            raise ValueError("invalid version: %s" % acme_version)
        if failtype in ("pretest-1", "pretest-2"):
            dbAcmeChallenge.acme_challenge_fail_type_id = (
                model_utils.AcmeChallengeFailType.from_string("setup-prevalidation")
            )
            self.dbSession.flush()
        elif failtype in ("fail-1", "fail-2"):
            dbAcmeChallenge.acme_challenge_fail_type_id = (
                model_utils.AcmeChallengeFailType.from_string("upstream-validation")
            )
            self.dbSession.flush()
        else:
            raise ValueError("unknown `failtype")
        assert self.dbAcmeOrder

        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.timestamp_event = datetime.datetime.now(datetime.timezone.utc)
        dbAcmeEventLog.acme_event_id = model_utils.AcmeEvent.from_string(
            "v2|-challenge-fail"
        )
        dbAcmeEventLog.acme_account_id = self.dbAcmeAccount.id
        dbAcmeEventLog.acme_authorization_id = dbAcmeChallenge.acme_authorization_id
        dbAcmeEventLog.acme_challenge_id = dbAcmeChallenge.id
        dbAcmeEventLog.acme_order_id = self.dbAcmeOrder.id
        dbAcmeEventLog.unique_fqdn_set_id = (
            self.dbAcmeOrder.unique_fqdn_set_id if self.dbAcmeOrder else None
        )
        self.dbSession.add(dbAcmeEventLog)
        self.dbSession.flush()

        # persist to the database
        if transaction_commit:
            self.ctx.pyramid_transaction_commit()

        return dbAcmeEventLog

    def log_challenge_pass(
        self,
        acme_version: str,
        dbAcmeChallenge: "AcmeChallenge",
        transaction_commit: Optional[bool] = None,
    ) -> "AcmeEventLog":
        """
        Logs a challenge as passed

        :param acme_version: (required) The ACME version of the API we are using.
        :param dbAcmeChallenge: (required) The :class:`model.objects.AcmeChallenge` we asked to trigger
        :param transaction_commit: (option) Boolean. If True, commit the transaction
        """
        if acme_version != "v2":
            raise ValueError("invalid version: %s" % acme_version)

        assert self.dbAcmeOrder

        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.timestamp_event = datetime.datetime.now(datetime.timezone.utc)
        dbAcmeEventLog.acme_event_id = model_utils.AcmeEvent.from_string(
            "v2|-challenge-pass"
        )
        dbAcmeEventLog.acme_account_id = self.dbAcmeAccount.id
        dbAcmeEventLog.acme_authorization_id = dbAcmeChallenge.acme_authorization_id
        dbAcmeEventLog.acme_challenge_id = dbAcmeChallenge.id
        dbAcmeEventLog.acme_order_id = self.dbAcmeOrder.id
        dbAcmeEventLog.unique_fqdn_set_id = (
            self.dbAcmeOrder.unique_fqdn_set_id if self.dbAcmeOrder else None
        )
        self.dbSession.add(dbAcmeEventLog)
        self.dbSession.flush()

        # persist to the database
        if transaction_commit:
            self.ctx.pyramid_transaction_commit()

        return dbAcmeEventLog

    def log_order_finalize(
        self,
        acme_version: str,
        transaction_commit: bool = True,
    ) -> "AcmeEventLog":
        """
        Logs an AcmeOrder as finalized

        :param acme_version: (required) The ACME version of the API we are using.
        :param transaction_commit: (option) Boolean. If True, commit the transaction
        """
        if acme_version != "v2":
            raise ValueError("invalid version: %s" % acme_version)

        if not self.dbAcmeOrder:
            raise ValueError(
                "the logger MUST be configured with a :attr:`.dbAcmeOrder`"
            )

        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.timestamp_event = datetime.datetime.now(datetime.timezone.utc)
        dbAcmeEventLog.acme_event_id = model_utils.AcmeEvent.from_string(
            "v2|Order-finalize"
        )
        dbAcmeEventLog.acme_account_id = self.dbAcmeAccount.id
        dbAcmeEventLog.acme_order_id = self.dbAcmeOrder.id
        dbAcmeEventLog.unique_fqdn_set_id = (
            self.dbAcmeOrder.unique_fqdn_set_id if self.dbAcmeOrder else None
        )
        self.dbSession.add(dbAcmeEventLog)
        self.dbSession.flush()

        # persist to the database
        if transaction_commit:
            self.ctx.pyramid_transaction_commit()

        return dbAcmeEventLog

    # ==========================================================================

    def log_CertificateProcured(
        self,
        acme_version: str,
        dbCertificateSigned: "CertificateSigned",
        dbCertificateRequest: "CertificateRequest",
        transaction_commit: bool = True,
    ) -> "AcmeEventLog":
        """
        Logs an AcmeOrder as finalized

        :param acme_version: (required) The ACME version of the API we are using.
        :param dbCertificateSigned: (required) The :class:`model.objects.CertificateSigned`
        :param dbCertificateRequest: (required) The :class:`model.objects.CertificateRequest`
        :param transaction_commit: (option) Boolean. If True, commit the transaction
        """
        if acme_version != "v2":
            raise ValueError("invalid version: %s" % acme_version)

        if not self.dbAcmeOrder:
            raise ValueError(
                "the logger MUST be configured with a :attr:`.dbAcmeOrder`"
            )

        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.timestamp_event = datetime.datetime.now(datetime.timezone.utc)
        dbAcmeEventLog.acme_event_id = model_utils.AcmeEvent.from_string(
            "v2|Certificate-procured"
        )
        dbAcmeEventLog.acme_account_id = self.dbAcmeAccount.id
        dbAcmeEventLog.acme_order_id = self.dbAcmeOrder.id
        dbAcmeEventLog.unique_fqdn_set_id = (
            self.dbAcmeOrder.unique_fqdn_set_id if self.dbAcmeOrder else None
        )
        dbAcmeEventLog.certificate_request_id = dbCertificateRequest.id
        dbAcmeEventLog.certificate_signed_id = dbCertificateSigned.id
        self.dbSession.add(dbAcmeEventLog)
        self.dbSession.flush()

        # persist to the database
        if transaction_commit:
            self.ctx.pyramid_transaction_commit()

        return dbAcmeEventLog


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def log__OperationsEvent(
    ctx,
    event_type_id: int,
    event_payload_dict: Optional[Dict] = None,
    dbOperationsEvent_child_of: Optional["OperationsEvent"] = None,
    timestamp_event: Optional[datetime.datetime] = None,
) -> "OperationsEvent":
    """
    creates a OperationsEvent instance
    if needed, registers it into the ctx
    """
    # defaults
    # timestamp overwrite?
    timestamp_event = timestamp_event or ctx.timestamp
    # if we didn't pass in an explicit dbOperationsEvent_child_of, use the global
    dbOperationsEvent_child_of = dbOperationsEvent_child_of or ctx.dbOperationsEvent

    # if dbOperationsEvent_child_of and (dbOperationsEvent_child_of not in ctx.dbSession):
    #    dbOperationsEvent_child_of = ctx.dbSession.merge(dbOperationsEvent_child_of)

    if event_payload_dict is None:
        event_payload_dict = utils.new_event_payload_dict()

    # bookkeeping
    dbOperationsEvent = model_objects.OperationsEvent()
    dbOperationsEvent.operations_event_type_id = event_type_id
    dbOperationsEvent.timestamp_event = timestamp_event
    dbOperationsEvent.set_event_payload(event_payload_dict)
    if dbOperationsEvent_child_of:
        dbOperationsEvent.operations_event_id__child_of = dbOperationsEvent_child_of.id
    ctx.dbSession.add(dbOperationsEvent)
    ctx.dbSession.flush(objects=[dbOperationsEvent])

    # shortcut!
    # if there isn't a global dbOperationsEvent, set it!
    if not ctx.dbOperationsEvent:
        ctx.dbOperationsEvent = dbOperationsEvent

    return dbOperationsEvent


def _log_object_event(
    ctx: "ApiContext",
    dbOperationsEvent: "OperationsEvent",
    event_status_id: int,
    dbAcmeAccount: Optional["AcmeAccount"] = None,
    dbAcmeAccountKey: Optional["AcmeAccountKey"] = None,
    dbAcmeDnsServer: Optional["AcmeDnsServer"] = None,
    dbAcmeOrder: Optional["AcmeOrder"] = None,
    dbAcmeServer: Optional["AcmeServer"] = None,
    dbCertificateCA: Optional["CertificateCA"] = None,
    dbCertificateCAChain: Optional["CertificateCAChain"] = None,
    dbCertificateRequest: Optional["CertificateRequest"] = None,
    dbCoverageAssuranceEvent: Optional["CoverageAssuranceEvent"] = None,
    dbDomain: Optional["Domain"] = None,
    dbPrivateKey: Optional["PrivateKey"] = None,
    dbCertificateSigned: Optional["CertificateSigned"] = None,
    dbUniqueFQDNSet: Optional["UniqueFQDNSet"] = None,
    dbUniquelyChallengedFQDNSet: Optional["UniquelyChallengedFQDNSet"] = None,
    dbRenewalConfiguration: Optional["RenewalConfiguration"] = None,
) -> "OperationsObjectEvent":
    """additional logging for objects"""
    dbOperationsObjectEvent = model_objects.OperationsObjectEvent()
    dbOperationsObjectEvent.operations_event_id = dbOperationsEvent.id
    dbOperationsObjectEvent.operations_object_event_status_id = event_status_id

    if dbAcmeAccount:
        dbOperationsObjectEvent.acme_account_id = dbAcmeAccount.id
    elif dbAcmeAccountKey:
        dbOperationsObjectEvent.acme_account_key_id = dbAcmeAccountKey.id
    elif dbAcmeDnsServer:
        dbOperationsObjectEvent.acme_dns_server_id = dbAcmeDnsServer.id
    elif dbAcmeOrder:
        dbOperationsObjectEvent.acme_order_id = dbAcmeOrder.id
    elif dbAcmeServer:
        dbOperationsObjectEvent.acme_server_id = dbAcmeServer.id
    elif dbCertificateCA:
        dbOperationsObjectEvent.certificate_ca_id = dbCertificateCA.id
    elif dbCertificateCAChain:
        dbOperationsObjectEvent.certificate_ca_chain_id = dbCertificateCAChain.id
    elif dbCertificateRequest:
        dbOperationsObjectEvent.certificate_request_id = dbCertificateRequest.id
    elif dbCoverageAssuranceEvent:
        dbOperationsObjectEvent.coverage_assurance_event_id = (
            dbCoverageAssuranceEvent.id
        )
    elif dbDomain:
        dbOperationsObjectEvent.domain_id = dbDomain.id
    elif dbPrivateKey:
        dbOperationsObjectEvent.private_key_id = dbPrivateKey.id
    elif dbCertificateSigned:
        dbOperationsObjectEvent.certificate_signed_id = dbCertificateSigned.id
    elif dbRenewalConfiguration:
        dbOperationsObjectEvent.renewal_configuration_id = dbRenewalConfiguration.id
    elif dbUniqueFQDNSet:
        dbOperationsObjectEvent.unique_fqdn_set_id = dbUniqueFQDNSet.id
    elif dbUniquelyChallengedFQDNSet:
        dbOperationsObjectEvent.uniquely_challenged_fqdn_set_id = (
            dbUniquelyChallengedFQDNSet.id
        )

    ctx.dbSession.add(dbOperationsObjectEvent)
    ctx.dbSession.flush(objects=[dbOperationsObjectEvent])

    return dbOperationsObjectEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = ("AcmeLogger", "log__OperationsEvent", "_log_object_event")
