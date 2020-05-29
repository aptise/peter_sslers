# logging
import logging

log = logging.getLogger(__name__)

# stdlib
import datetime
import pdb

# localapp
from .. import utils
from ...model import utils as model_utils
from ...model import objects as model_objects


# logging.getLogger("sqlalchemy.engine").setLevel(logging.INFO)

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class AcmeLogger(object):
    """
    AcmeLogger is an interface used to log interactions with the LetsEncrypt API
    This is designed to monitor usage and potential throttling concerns
    """

    ctx = None
    dbAcmeAccount = None
    dbAcmeOrder = None  # only set on orders

    def __init__(self, ctx, dbAcmeAccount=None):
        """
        :param ctx: (required) A :class:`lib.utils.ApiContext` instance
        :param dbAcmeAccount: (optional) The :class:`model.objects.AcmeAccount`
        """
        self.ctx = ctx
        self.dbAcmeAccount = dbAcmeAccount

    @property
    def dbSession(self):
        return self.ctx.dbSession

    def register_dbAcmeOrder(self, dbAcmeOrder):
        """
        Registers a :class:`model.objects.AcmeOrder` onto the event logger.

        :param dbAcmeOrder: (required) The :class:`model.objects.AcmeOrder`
        """
        self.dbAcmeOrder = dbAcmeOrder

    def log_newAccount(self, acme_version, transaction_commit=None):
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
        dbAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
        dbAcmeEventLog.acme_account_id = self.dbAcmeAccount.id
        self.dbSession.add(dbAcmeEventLog)
        self.dbSession.flush()

        # persist to the database
        if transaction_commit:
            self.ctx.pyramid_transaction_commit()

        return dbAcmeEventLog

    def log_newOrder(self, acme_version, dbUniqueFQDNSet, transaction_commit=None):
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
        dbAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
        dbAcmeEventLog.acme_account_id = self.dbAcmeAccount.id
        dbAcmeEventLog.unique_fqdn_set_id = dbUniqueFQDNSet.id
        self.dbSession.add(dbAcmeEventLog)
        self.dbSession.flush()

        # persist to the database
        if transaction_commit:
            self.ctx.pyramid_transaction_commit()

        return dbAcmeEventLog

    def log_order_load(self, acme_version, dbAcmeOrder, transaction_commit=None):
        """
        Logs a call for the ACME order's endpint

        :param acme_version: (required) The ACME version of the API we are using.
        :param dbAcmeOrder: (required) The :class:`model.objects.AcmeOrder` for the existing order
        """
        if acme_version != "v2":
            raise ValueError("invalid version: %s" % acme_version)

        acme_event_id = model_utils.AcmeEvent.from_string("v2|-order-location")

        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.acme_event_id = acme_event_id
        dbAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
        dbAcmeEventLog.acme_account_id = self.dbAcmeAccount.id
        dbAcmeEventLog.acme_order_id = self.dbAcmeOrder.id
        dbAcmeEventLog.unique_fqdn_set_id = self.dbAcmeOrder.unique_fqdn_set_id
        self.dbSession.add(dbAcmeEventLog)
        self.dbSession.flush()

        # persist to the database
        if transaction_commit:
            self.ctx.pyramid_transaction_commit()

        return dbAcmeEventLog

    def log_authorization_request(
        self, acme_version, dbAcmeAuthorization, transaction_commit=None
    ):
        """
        Logs a new authorization and creates a challenge object

        :param acme_version: (required) The ACME version of the API we are using.
        :param dbAcmeAuthorization: (required) The :class:`model.objects.AcmeAuthorization` we fetched
        :param transaction_commit: (option) Boolean. If True, commit the transaction
        """
        if acme_version != "v2":
            raise ValueError("invalid version: %s" % acme_version)

        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
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
        self, acme_version, dbAcmeAuthorization, transaction_commit=None
    ):
        if acme_version != "v2":
            raise ValueError("invalid version: %s" % acme_version)

        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
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
        self, acme_version, dbAcmeChallenge, transaction_commit=None
    ):
        """
        :param acme_version: (required) The ACME version of the API we are using.
        :param dbAcmeChallenge: (required) The :class:`model.objects.AcmeChallenge` we asked to trigger
        :param transaction_commit: (option) Boolean. If True, commit the transaction
        """
        if acme_version != "v2":
            raise ValueError("invalid version: %s" % acme_version)

        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
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
        self, acme_version, dbAcmeChallenge, transaction_commit=None
    ):
        """
        Logs a new authorization and creates a challenge object

        :param acme_version: (required) The ACME version of the API we are using.
        :param dbAcmeChallenge: (required) The :class:`model.objects.AcmeChallenge` we asked to trigger
        :param transaction_commit: (option) Boolean. If True, commit the transaction
        """
        if acme_version != "v2":
            raise ValueError("invalid version: %s" % acme_version)

        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
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
        self, acme_version, dbAcmeChallenge, failtype, transaction_commit=None
    ):
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
            dbAcmeChallenge.acme_challenge_fail_type_id = model_utils.AcmeChallengeFailType.from_string(
                "setup-prevalidation"
            )
            self.dbSession.flush()
        elif failtype in ("fail-1", "fail-2"):
            dbAcmeChallenge.acme_challenge_fail_type_id = model_utils.AcmeChallengeFailType.from_string(
                "upstream-validation"
            )
            self.dbSession.flush()
        else:
            raise ValueError("unknown `failtype")

        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
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

    def log_challenge_pass(
        self, acme_version, dbAcmeChallenge, transaction_commit=None
    ):
        """
        Logs a challenge as passed

        :param acme_version: (required) The ACME version of the API we are using.
        :param dbAcmeChallenge: (required) The :class:`model.objects.AcmeChallenge` we asked to trigger
        :param transaction_commit: (option) Boolean. If True, commit the transaction
        """
        if acme_version != "v2":
            raise ValueError("invalid version: %s" % acme_version)

        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
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

    def log_order_finalize(self, acme_version, transaction_commit=True):
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
        dbAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
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
        acme_version,
        dbServerCertificate=None,
        dbCertificateRequest=None,
        transaction_commit=True,
    ):
        """
        Logs an AcmeOrder as finalized

        :param acme_version: (required) The ACME version of the API we are using.
        :param dbServerCertificate: (required) The :class:`model.objects.ServerCertificate`
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
        dbAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
        dbAcmeEventLog.acme_event_id = model_utils.AcmeEvent.from_string(
            "v2|Certificate-procured"
        )
        dbAcmeEventLog.acme_account_id = self.dbAcmeAccount.id
        dbAcmeEventLog.acme_order_id = self.dbAcmeOrder.id
        dbAcmeEventLog.unique_fqdn_set_id = (
            self.dbAcmeOrder.unique_fqdn_set_id if self.dbAcmeOrder else None
        )
        dbAcmeEventLog.certificate_request_id = dbCertificateRequest.id
        dbAcmeEventLog.server_certificate_id = dbServerCertificate.id
        self.dbSession.add(dbAcmeEventLog)
        self.dbSession.flush()

        # persist to the database
        if transaction_commit:
            self.ctx.pyramid_transaction_commit()

        return dbAcmeEventLog


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def log__OperationsEvent(
    ctx,
    event_type_id,
    event_payload_dict=None,
    dbOperationsEvent_child_of=None,
    timestamp_event=None,
):
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
    ctx,
    dbOperationsEvent=None,
    event_status_id=None,
    dbAcmeAccount=None,
    dbAcmeAccountKey=None,
    dbAcmeOrder=None,
    dbCACertificate=None,
    dbDomain=None,
    dbPrivateKey=None,
    dbServerCertificate=None,
    dbUniqueFQDNSet=None,
    dbCertificateRequest=None,
    dbQueueCertificate=None,
    dbQueueDomain=None,
):
    """additional logging for objects"""
    dbOperationsObjectEvent = model_objects.OperationsObjectEvent()
    dbOperationsObjectEvent.operations_event_id = dbOperationsEvent.id
    dbOperationsObjectEvent.operations_object_event_status_id = event_status_id

    if dbAcmeAccount:
        dbOperationsObjectEvent.acme_account_id = dbAcmeAccount.id
    elif dbAcmeAccountKey:
        dbOperationsObjectEvent.acme_account_key_id = dbAcmeAccountKey.id
    elif dbAcmeOrder:
        dbOperationsObjectEvent.acme_order_id = dbAcmeOrder.id
    elif dbCACertificate:
        dbOperationsObjectEvent.ca_certificate_id = dbCACertificate.id
    elif dbDomain:
        dbOperationsObjectEvent.domain_id = dbDomain.id
    elif dbPrivateKey:
        dbOperationsObjectEvent.private_key_id = dbPrivateKey.id
    elif dbServerCertificate:
        dbOperationsObjectEvent.server_certificate_id = dbServerCertificate.id
    elif dbUniqueFQDNSet:
        dbOperationsObjectEvent.unique_fqdn_set_id = dbUniqueFQDNSet.id
    elif dbCertificateRequest:
        dbOperationsObjectEvent.certificate_request_id = dbCertificateRequest.id
    elif dbQueueCertificate:
        dbOperationsObjectEvent.queue_certificate_id = dbQueueCertificate.id
    elif dbQueueDomain:
        dbOperationsObjectEvent.queue_domain_id = dbQueueDomain.id

    ctx.dbSession.add(dbOperationsObjectEvent)
    ctx.dbSession.flush(objects=[dbOperationsObjectEvent])

    return dbOperationsObjectEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = ("AcmeLogger", "log__OperationsEvent", "_log_object_event")
