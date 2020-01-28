# logging
import logging

log = logging.getLogger(__name__)

# pypi
import datetime

# localapp
from ...models import models
from .. import utils


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class AcmeLogger(object):
    def __init__(self, ctx, dbAccountKey=None, dbCertificateRequest=None):
        self.ctx = ctx
        self.dbAccountKey = dbAccountKey
        self.dbCertificateRequest = dbCertificateRequest

    def log_registration(self):
        """
        logs a call to v1|/acme/new-reg
        TODO: update with result?
        """
        sslAcmeEventLog = models.SslAcmeEventLog()
        sslAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
        sslAcmeEventLog.acme_event_id = models.AcmeEvent.from_string("v1|/acme/new-reg")
        self.ctx.dbSessionLogger.add(sslAcmeEventLog)
        self.ctx.dbSessionLogger.flush()
        return sslAcmeEventLog

    def log_new_authz(self, domain):
        """
        Logs a newauthz and the challenge option
        """
        sslAcmeEventLog = models.SslAcmeEventLog()
        sslAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
        sslAcmeEventLog.acme_event_id = models.AcmeEvent.from_string(
            "v1|/acme/new-authz"
        )
        sslAcmeEventLog.ssl_acme_account_key_id = self.dbAccountKey.id
        sslAcmeEventLog.ssl_certificate_request_id = self.dbCertificateRequest.id
        self.ctx.dbSessionLogger.add(sslAcmeEventLog)
        self.ctx.dbSessionLogger.flush()

        sslAcmeChallengeLog = models.SslAcmeChallengeLog()
        sslAcmeChallengeLog.timestamp_created = datetime.datetime.utcnow()
        sslAcmeChallengeLog.ssl_acme_event_log_id = sslAcmeEventLog.id
        sslAcmeChallengeLog.domain = domain
        sslAcmeChallengeLog.ssl_acme_account_key_id = self.dbAccountKey.id
        self.ctx.dbSessionLogger.add(sslAcmeChallengeLog)
        self.ctx.dbSessionLogger.flush()
        return (sslAcmeEventLog, sslAcmeChallengeLog)

    def log_new_cert(self):
        sslAcmeEventLog = models.SslAcmeEventLog()
        sslAcmeEventLog.timestamp_event = datetime.datetime.utcnow()
        sslAcmeEventLog.acme_event_id = models.AcmeEvent.from_string(
            "v1|/acme/new-cert"
        )
        sslAcmeEventLog.ssl_acme_account_key_id = self.dbAccountKey.id
        sslAcmeEventLog.ssl_certificate_request_id = self.dbCertificateRequest.id
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
            sslAcmeChallengeLog.acme_challenge_fail_type_id = models.AcmeChallengeFailType.from_string(
                "setup-prevalidation"
            )
            self.ctx.dbSessionLogger.add(sslAcmeChallengeLog)
            self.ctx.dbSessionLogger.flush()
        elif failtype in ("fail-1", "fail-2"):
            sslAcmeChallengeLog.acme_challenge_fail_type_id = models.AcmeChallengeFailType.from_string(
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
    dbOperationsEvent = models.SslOperationsEvent()
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
    dbOperationsObjectEvent = models.SslOperationsObjectEvent()
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
