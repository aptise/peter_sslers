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


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class AcmeLogger(object):
    """
    AcmeLogger is an interface used to log interactions with the LetsEncrypt API
    This is designed to monitor usage and potential throttling concerns
    """

    ctx = None
    dbAcmeAccountKey = None
    dbAcmeOrder = None  # only set on orders

    def __init__(self, ctx, dbAcmeAccountKey=None):
        """
        :param ctx: (required) A :class:`lib.utils.ApiContext` object
        :param dbAcmeAccountKey: (optional) The :class:`model.objects.AcmeAccountKey`
        """
        self.ctx = ctx
        self.dbAcmeAccountKey = dbAcmeAccountKey

    def register_dbAcmeOrder(self, dbAcmeOrder):
        """
        Registers a :class:`model.objects.AcmeOrder` onto the event logger.

        :param dbAcmeOrder: (required) The :class:`model.objects.AcmeOrder`
        """
        self.dbAcmeOrder = dbAcmeOrder

    def log_newAccount(self, acme_version):
        """
        Logs a call for the ACME Registration event

        :param acme_version: (required) The ACME version of the API we are using.
        """
        # ???: update with result?
        if acme_version != "v2":
            raise ValueError("invalid `acme_version``: %s" % acme_version)
        acme_event_id = model_utils.AcmeEvent.from_string("v2|newAccount")

        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.acme_event_id = acme_event_id
        dbAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
        dbAcmeEventLog.acme_account_key_id = self.dbAcmeAccountKey.id
        self.ctx.dbSessionLogger.add(dbAcmeEventLog)
        self.ctx.dbSessionLogger.flush()
        return dbAcmeEventLog

    def log_newOrder(self, acme_version, dbCertificateRequest):
        """
        Logs a call for the ACME Registration event
        
        :param acme_version: (required) The ACME version of the API we are using.
        :param dbCertificateRequest: (required) The :class:`model.objects.CertificateRequest` for the new order

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
        dbAcmeEventLog.acme_account_key_id = self.dbAcmeAccountKey.id
        dbAcmeEventLog.certificate_request_id = dbCertificateRequest.id
        self.ctx.dbSessionLogger.add(dbAcmeEventLog)
        self.ctx.dbSessionLogger.flush()
        return dbAcmeEventLog

    def log_authorization_request(self, acme_version, dbAcmeAuthorization):
        """
        Logs a new authorization and creates a challenge object

        :param acme_version: (required) The ACME version of the API we are using.
        :param dbAcmeAuthorization: (required) The :class:`model.objects.AcmeAuthorization` we fetched
        """
        if acme_version != "v2":
            raise ValueError("invalid version: %s" % acme_version)

        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
        dbAcmeEventLog.acme_event_id = model_utils.AcmeEvent.from_string(
            "v2|-authorization-request"
        )
        dbAcmeEventLog.acme_account_key_id = self.dbAcmeAccountKey.id
        dbAcmeEventLog.acme_authorization_id = dbAcmeAuthorization.id
        dbAcmeEventLog.acme_order_id = self.dbAcmeOrder.id
        self.ctx.dbSessionLogger.add(dbAcmeEventLog)
        self.ctx.dbSessionLogger.flush()
        return dbAcmeEventLog

    def log_challenge_trigger(self, acme_version, dbAcmeChallenge):
        """
        Logs a new authorization and creates a challenge object

        :param acme_version: (required) The ACME version of the API we are using.
        :param dbAcmeChallenge: (required) The :class:`model.objects.AcmeChallenge` we asked to trigger
        """
        if acme_version != "v2":
            raise ValueError("invalid version: %s" % acme_version)

        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
        dbAcmeEventLog.acme_event_id = model_utils.AcmeEvent.from_string(
            "v2|-challenge-trigger"
        )
        dbAcmeEventLog.acme_account_key_id = self.dbAcmeAccountKey.id
        dbAcmeEventLog.acme_authorization_id = dbAcmeChallenge.acme_authorization_id
        dbAcmeEventLog.acme_challenge_id = dbAcmeChallenge.id
        dbAcmeEventLog.acme_order_id = self.dbAcmeOrder.id
        self.ctx.dbSessionLogger.add(dbAcmeEventLog)
        self.ctx.dbSessionLogger.flush()
        return dbAcmeEventLog

    # ==========================================================================

    def log_challenge_error(self, acme_version, dbAcmeChallenge, failtype):
        """
        Logs a challenge as error

        :param acme_version: (required) The ACME version of the API we are using.
        :param dbAcmeChallenge: (required) The :class:`model.objects.AcmeChallenge` we asked to trigger
        :param failtype: (required) A string from :class:`model_utils.AcmeChallengeFailType`
        """
        raise ValueError("not compaitible with current api")
        if acme_version != "v2":
            raise ValueError("invalid version: %s" % acme_version)
        if failtype in ("pretest-1", "pretest-2"):
            dbAcmeChallenge.acme_challenge_fail_type_id = model_utils.AcmeChallengeFailType.from_string(
                "setup-prevalidation"
            )
            self.ctx.dbSessionLogger.add(dbAcmeChallenge)
            self.ctx.dbSessionLogger.flush()
        elif failtype in ("fail-1", "fail-2"):
            dbAcmeChallenge.acme_challenge_fail_type_id = model_utils.AcmeChallengeFailType.from_string(
                "upstream-validation"
            )
            self.ctx.dbSessionLogger.add(dbAcmeChallenge)
            self.ctx.dbSessionLogger.flush()
        else:
            raise ValueError("unknown `failtype")

    def log_new_cert(self, dbCertificateRequest, version):
        if version not in ("v1", "v2"):
            raise ValueError("invalid version: %s" % version)

        pdb.set_trace()
        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
        dbAcmeEventLog.acme_event_id = model_utils.AcmeEvent.from_string(
            "v1|/acme/new-cert"
        )
        dbAcmeEventLog.acme_account_key_id = self.dbAcmeAccountKey.id
        dbAcmeEventLog.certificate_request_id = dbCertificateRequest.id
        self.ctx.dbSessionLogger.add(dbAcmeEventLog)
        self.ctx.dbSessionLogger.flush()
        return dbAcmeEventLog

    def log_order_finalize(self, version, dbCertificateRequest):
        if version != "v2":
            raise ValueError("invalid version: %s" % version)

        pdb.set_trace()
        dbAcmeEventLog = model_objects.AcmeEventLog()
        dbAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
        dbAcmeEventLog.acme_event_id = model_utils.AcmeEvent.from_string(
            "v2|-order-finalize"
        )
        dbAcmeEventLog.acme_account_key_id = self.dbAcmeAccountKey.id
        dbAcmeEventLog.certificate_request_id = dbCertificateRequest.id
        self.ctx.dbSessionLogger.add(dbAcmeEventLog)
        self.ctx.dbSessionLogger.flush()
        return dbAcmeEventLog

    def log_event_certificate(self, dbAcmeEventLog, dbServerCertificate):
        """
        Logs a challenge request
        """
        pdb.set_trace()
        dbAcmeEventLog.server_certificate_id = dbServerCertificate.id
        self.ctx.dbSessionLogger.add(dbAcmeEventLog)
        self.ctx.dbSessionLogger.flush()

    def log_challenge_pass(self, dbAcmeChallenge):
        """
        Logs a challenge as passed
        """
        raise ValueError("this is not consistent with current api")
        dbAcmeChallenge.timestamp_challenge_pass = datetime.datetime.utcnow()
        self.ctx.dbSessionLogger.add(dbAcmeChallenge)
        self.ctx.dbSessionLogger.flush()


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
    dbAcmeAccountKey=None,
    dbCACertificate=None,
    dbDomain=None,
    dbPrivateKey=None,
    dbServerCertificate=None,
    dbUniqueFQDNSet=None,
    dbCertificateRequest=None,
    dbQueueRenewal=None,
    dbQueueDomain=None,
):
    """additional logging for objects"""
    dbOperationsObjectEvent = model_objects.OperationsObjectEvent()
    dbOperationsObjectEvent.operations_event_id = dbOperationsEvent.id
    dbOperationsObjectEvent.operations_object_event_status_id = event_status_id

    if dbAcmeAccountKey:
        dbOperationsObjectEvent.acme_account_key_id = dbAcmeAccountKey.id
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
    elif dbQueueRenewal:
        dbOperationsObjectEvent.queue_renewal_id = dbQueueRenewal.id
    elif dbQueueDomain:
        dbOperationsObjectEvent.queue_domain_id = dbQueueDomain.id

    ctx.dbSession.add(dbOperationsObjectEvent)
    ctx.dbSession.flush(objects=[dbOperationsObjectEvent])

    return dbOperationsObjectEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = ("AcmeLogger", "log__OperationsEvent", "_log_object_event")
