# logging
import logging

log = logging.getLogger(__name__)

# pypi
import datetime

# localapp
from ....lib import utils
from ....model import utils as model_utils
from ....model import objects as model_objects


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class AcmeLogger(object):
    def __init__(self, ctx, dbAccountKey=None):
        self.ctx = ctx
        self.dbAccountKey = dbAccountKey

    def log_registration(self, version):
        """
        logs a call to v1|/acme/new-reg
        TODO: update with result?
        """
        if version not in ("v1", "v2"):
            raise ValueError("invalid version: %s" % version)

        if version == "v1":
            acme_event_id = model_utils.AcmeEvent.from_string("v1|/acme/new-reg")
        elif version == "v2":
            acme_event_id = model_utils.AcmeEvent.from_string("v2|newAccount")

        sslAcmeEventLog = model_objects.SslAcmeEventLog()
        sslAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
        sslAcmeEventLog.acme_event_id = acme_event_id
        self.ctx.dbSessionLogger.add(sslAcmeEventLog)
        self.ctx.dbSessionLogger.flush()
        return sslAcmeEventLog

    def log_newOrder(self, version, dbCertificateRequest):
        """
        v2 New Order
        """
        if version != "v2":
            raise ValueError("invalid version: %s" % version)

        acme_event_id = model_utils.AcmeEvent.from_string("v2|newOrder")

        sslAcmeEventLog = model_objects.SslAcmeEventLog()
        sslAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
        sslAcmeEventLog.acme_event_id = acme_event_id
        self.ctx.dbSessionLogger.add(sslAcmeEventLog)
        sslAcmeEventLog.ssl_acme_account_key_id = self.dbAccountKey.id
        sslAcmeEventLog.ssl_certificate_request_id = dbCertificateRequest.id
        self.ctx.dbSessionLogger.flush()
        return sslAcmeEventLog

    def log_new_authorization(self, version, dbCertificateRequest, domain):
        """
        Logs a new authorization and creates a challenge object
        """
        if version != "v2":
            raise ValueError("invalid version: %s" % version)

        sslAcmeEventLog = model_objects.SslAcmeEventLog()
        sslAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
        sslAcmeEventLog.acme_event_id = model_utils.AcmeEvent.from_string(
            "v2|-authorization"
        )
        sslAcmeEventLog.ssl_acme_account_key_id = self.dbAccountKey.id
        sslAcmeEventLog.ssl_certificate_request_id = dbCertificateRequest.id
        self.ctx.dbSessionLogger.add(sslAcmeEventLog)
        self.ctx.dbSessionLogger.flush()

        sslAcmeChallengeLog = model_objects.SslAcmeChallengeLog()
        sslAcmeChallengeLog.timestamp_created = datetime.datetime.utcnow()
        sslAcmeChallengeLog.ssl_acme_event_log_id = sslAcmeEventLog.id
        sslAcmeChallengeLog.domain = domain
        sslAcmeChallengeLog.ssl_acme_account_key_id = self.dbAccountKey.id
        self.ctx.dbSessionLogger.add(sslAcmeChallengeLog)
        self.ctx.dbSessionLogger.flush()
        return (sslAcmeEventLog, sslAcmeChallengeLog)

    def log_new_authz(self, version, dbCertificateRequest, domain):
        """
        Logs a newauthz and creates a challenge object
        """
        if version != "v1":
            raise ValueError("invalid version: %s" % version)

        sslAcmeEventLog = model_objects.SslAcmeEventLog()
        sslAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
        sslAcmeEventLog.acme_event_id = model_utils.AcmeEvent.from_string(
            "v1|/acme/new-authz"
        )
        sslAcmeEventLog.ssl_acme_account_key_id = self.dbAccountKey.id
        sslAcmeEventLog.ssl_certificate_request_id = dbCertificateRequest.id
        self.ctx.dbSessionLogger.add(sslAcmeEventLog)
        self.ctx.dbSessionLogger.flush()

        sslAcmeChallengeLog = model_objects.SslAcmeChallengeLog()
        sslAcmeChallengeLog.timestamp_created = datetime.datetime.utcnow()
        sslAcmeChallengeLog.ssl_acme_event_log_id = sslAcmeEventLog.id
        sslAcmeChallengeLog.domain = domain
        sslAcmeChallengeLog.ssl_acme_account_key_id = self.dbAccountKey.id
        self.ctx.dbSessionLogger.add(sslAcmeChallengeLog)
        self.ctx.dbSessionLogger.flush()
        return (sslAcmeEventLog, sslAcmeChallengeLog)

    def log_new_cert(self, dbCertificateRequest, version):
        if version not in ("v1", "v2"):
            raise ValueError("invalid version: %s" % version)

        sslAcmeEventLog = model_objects.SslAcmeEventLog()
        sslAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
        sslAcmeEventLog.acme_event_id = model_utils.AcmeEvent.from_string(
            "v1|/acme/new-cert"
        )
        sslAcmeEventLog.ssl_acme_account_key_id = self.dbAccountKey.id
        sslAcmeEventLog.ssl_certificate_request_id = dbCertificateRequest.id
        self.ctx.dbSessionLogger.add(sslAcmeEventLog)
        self.ctx.dbSessionLogger.flush()
        return sslAcmeEventLog

    def log_order_finalize(self, version, dbCertificateRequest):
        if version != "v2":
            raise ValueError("invalid version: %s" % version)

        sslAcmeEventLog = model_objects.SslAcmeEventLog()
        sslAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
        sslAcmeEventLog.acme_event_id = model_utils.AcmeEvent.from_string(
            "v2|-order-finalize"
        )
        sslAcmeEventLog.ssl_acme_account_key_id = self.dbAccountKey.id
        sslAcmeEventLog.ssl_certificate_request_id = dbCertificateRequest.id
        self.ctx.dbSessionLogger.add(sslAcmeEventLog)
        self.ctx.dbSessionLogger.flush()
        return sslAcmeEventLog

    def log_event_certificate(self, sslAcmeEventLog, dbServerCertificate):
        """
        Logs a challenge request
        """
        sslAcmeEventLog.ssl_server_certificate_id = dbServerCertificate.id
        self.ctx.dbSessionLogger.add(sslAcmeEventLog)
        self.ctx.dbSessionLogger.flush()

    def log_challenge_trigger(self, sslAcmeChallengeLog):
        """
        Logs a challenge request
        """
        sslAcmeChallengeLog.timestamp_challenge_trigger = datetime.datetime.utcnow()
        sslAcmeChallengeLog.count_polled = 0
        self.ctx.dbSessionLogger.add(sslAcmeChallengeLog)
        self.ctx.dbSessionLogger.flush()

    def log_challenge_polled(self, sslAcmeChallengeLog):
        """
        Logs a challenge poll
        """
        sslAcmeChallengeLog.count_polled += 1
        self.ctx.dbSessionLogger.add(sslAcmeChallengeLog)
        self.ctx.dbSessionLogger.flush()

    def log_challenge_pass(self, sslAcmeChallengeLog):
        """
        Logs a challenge as passed
        """
        sslAcmeChallengeLog.timestamp_challenge_pass = datetime.datetime.utcnow()
        self.ctx.dbSessionLogger.add(sslAcmeChallengeLog)
        self.ctx.dbSessionLogger.flush()

    def log_challenge_error(self, sslAcmeChallengeLog, failtype):
        """
        Logs a challenge as error
        """
        if failtype in ("pretest-1", "pretest-2"):
            sslAcmeChallengeLog.acme_challenge_fail_type_id = model_utils.AcmeChallengeFailType.from_string(
                "setup-prevalidation"
            )
            self.ctx.dbSessionLogger.add(sslAcmeChallengeLog)
            self.ctx.dbSessionLogger.flush()
        elif failtype in ("fail-1", "fail-2"):
            sslAcmeChallengeLog.acme_challenge_fail_type_id = model_utils.AcmeChallengeFailType.from_string(
                "upstream-validation"
            )
            self.ctx.dbSessionLogger.add(sslAcmeChallengeLog)
            self.ctx.dbSessionLogger.flush()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def log__SslOperationsEvent(
    ctx,
    event_type_id,
    event_payload_dict=None,
    dbOperationsEvent_child_of=None,
    timestamp_event=None,
):
    """
    creates a SslOperationsEvent instance
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
    dbOperationsEvent = model_objects.SslOperationsEvent()
    dbOperationsEvent.ssl_operations_event_type_id = event_type_id
    dbOperationsEvent.timestamp_event = timestamp_event
    dbOperationsEvent.set_event_payload(event_payload_dict)
    if dbOperationsEvent_child_of:
        dbOperationsEvent.ssl_operations_event_id__child_of = (
            dbOperationsEvent_child_of.id
        )
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
    dbOperationsObjectEvent = model_objects.SslOperationsObjectEvent()
    dbOperationsObjectEvent.ssl_operations_event_id = dbOperationsEvent.id
    dbOperationsObjectEvent.ssl_operations_object_event_status_id = event_status_id

    if dbAcmeAccountKey:
        dbOperationsObjectEvent.ssl_acme_account_key_id = dbAcmeAccountKey.id
    elif dbCACertificate:
        dbOperationsObjectEvent.ssl_ca_certificate_id = dbCACertificate.id
    elif dbDomain:
        dbOperationsObjectEvent.ssl_domain_id = dbDomain.id
    elif dbPrivateKey:
        dbOperationsObjectEvent.ssl_private_key_id = dbPrivateKey.id
    elif dbServerCertificate:
        dbOperationsObjectEvent.ssl_server_certificate_id = dbServerCertificate.id
    elif dbUniqueFQDNSet:
        dbOperationsObjectEvent.ssl_unique_fqdn_set_id = dbUniqueFQDNSet.id
    elif dbCertificateRequest:
        dbOperationsObjectEvent.ssl_certificate_request_id = dbCertificateRequest.id
    elif dbQueueRenewal:
        dbOperationsObjectEvent.ssl_queue_renewal_id = dbQueueRenewal.id
    elif dbQueueDomain:
        dbOperationsObjectEvent.ssl_queue_domain_id = dbQueueDomain.id

    ctx.dbSession.add(dbOperationsObjectEvent)
    ctx.dbSession.flush(objects=[dbOperationsObjectEvent])

    return dbOperationsObjectEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = ("AcmeLogger", "log__SslOperationsEvent", "_log_object_event")
