# logging
import logging

log = logging.getLogger(__name__)

# stdlib
import datetime

# pypi
import sqlalchemy
import transaction
from zope.sqlalchemy import mark_changed

# localapp
from ...models import models
from ... import lib
from ....lib import acme_v1
from ....lib import cert_utils
from ....lib import letsencrypt_info
from ....lib import errors
from ....lib import utils as lib_utils
from .. import events
from .. import utils


# local
from .logger import AcmeLogger
from .logger import log__SslOperationsEvent
from .logger import _log_object_event
from . import get


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def disable_Domain(
    ctx,
    dbDomain,
    dbOperationsEvent=None,
    event_status="domain__mark__inactive",
    action="deactivated",
):
    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict["ssl_domain.id"] = dbDomain.id
    event_payload_dict["action"] = action
    dbDomain.is_active = False
    ctx.dbSession.flush(objects=[dbDomain])

    _log_object_event(
        ctx,
        dbOperationsEvent=dbOperationsEvent,
        event_status_id=models.SslOperationsObjectEventStatus.from_string(event_status),
        dbDomain=dbDomain,
    )
    return True


def enable_Domain(
    ctx,
    dbDomain,
    dbOperationsEvent=None,
    event_status="domain__mark__active",
    action="activated",
):
    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict["ssl_domain.id"] = dbDomain.id
    event_payload_dict["action"] = action
    dbDomain.is_active = True
    ctx.dbSession.flush(objects=[dbDomain])

    _log_object_event(
        ctx,
        dbOperationsEvent=dbOperationsEvent,
        event_status_id=models.SslOperationsObjectEventStatus.from_string(event_status),
        dbDomain=dbDomain,
    )
    return True


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def ca_certificate_probe(ctx):
    """
    Probes the LetsEncrypt Certificate Authority for new certificates
    2016.06.04 - dbOperationsEvent compliant
    """

    # create a bookkeeping object
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__SslOperationsEvent(
        ctx, models.SslOperationsEventType.from_string("ca_certificate__probe")
    )

    certs = letsencrypt_info.probe_letsencrypt_certificates()
    certs_discovered = []
    certs_modified = []
    for c in certs:
        _is_created = False
        dbCACertificate = lib.db.get.get__SslCaCertificate__by_pem_text(
            ctx, c["cert_pem"]
        )
        if not dbCACertificate:
            (
                dbCACertificate,
                _is_created,
            ) = lib.db.getcreate.getcreate__SslCaCertificate__by_pem_text(
                ctx, c["cert_pem"], c["name"]
            )
            if _is_created:
                certs_discovered.append(dbCACertificate)
        if "is_ca_certificate" in c:
            if dbCACertificate.is_ca_certificate != c["is_ca_certificate"]:
                dbCACertificate.is_ca_certificate = c["is_ca_certificate"]
                if dbCACertificate not in certs_discovered:
                    certs_modified.append(dbCACertificate)
        else:
            attrs = (
                "le_authority_name",
                "is_authority_certificate",
                "is_cross_signed_authority_certificate",
            )
            for _k in attrs:
                if getattr(dbCACertificate, _k) is None:
                    setattr(dbCACertificate, _k, c[_k])
                    if dbCACertificate not in certs_discovered:
                        certs_modified.append(dbCACertificate)

    # bookkeeping update
    event_payload_dict["is_certificates_discovered"] = (
        True if certs_discovered else False
    )
    event_payload_dict["is_certificates_updated"] = True if certs_modified else False
    event_payload_dict["ids_discovered"] = [c.id for c in certs_discovered]
    event_payload_dict["ids_modified"] = [c.id for c in certs_modified]

    dbOperationsEvent.set_event_payload(event_payload_dict)
    ctx.dbSession.flush(objects=[dbOperationsEvent])

    return dbOperationsEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def do__SslAcmeAccountKey_authenticate(ctx, dbAcmeAccountKey, account_key_path=None):
    """
    Authenticates the AccountKey against the LetsEncrypt ACME servers
    2016.06.04 - dbOperationsEvent compliant
    """
    _tmpfile = None
    try:
        if account_key_path is None:
            _tmpfile = cert_utils.new_pem_tempfile(dbAcmeAccountKey.key_pem)
            account_key_path = _tmpfile.name

        # parse account key to get public key
        header, thumbprint = acme_v1.account_key__header_thumbprint(
            account_key_path=account_key_path
        )

        acmeLogger = AcmeLogger(ctx)

        # result is either: `new-account` or `existing-account`
        # failing will raise an exception
        result = acme_v1.acme_register_account(
            header,
            account_key_path=account_key_path,
            acmeLogger=acmeLogger,
            acmeAccountKey=dbAcmeAccountKey,
        )

        # this would raise if we couldn't authenticate
        dbAcmeAccountKey.timestamp_last_authenticated = ctx.timestamp
        ctx.dbSession.flush(objects=[dbAcmeAccountKey])

        # log this
        event_payload_dict = utils.new_event_payload_dict()
        event_payload_dict["ssl_acme_account_key.id"] = dbAcmeAccountKey.id
        dbOperationsEvent = log__SslOperationsEvent(
            ctx,
            models.SslOperationsEventType.from_string("acme_account_key__authenticate"),
            event_payload_dict,
        )
        return result

    finally:
        if _tmpfile:
            _tmpfile.close()


def do__CertificateRequest__AcmeAutomated(
    ctx,
    domain_names,
    dbAccountKey=None,
    dbPrivateKey=None,
    private_key_pem=None,
    dbServerCertificate__renewal_of=None,
    dbQueueRenewal__of=None,
):
    """
    2016.06.04 - dbOperationsEvent compliant

    #for a single domain
    openssl req -new -sha256 -key domain.key -subj "/CN=yoursite.com" > domain.csr

    #for multiple domains (use this one if you want both www.yoursite.com and yoursite.com)
    openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:yoursite.com,DNS:www.yoursite.com")) > domain.csr

    # homebrew?
    /usr/local/opt/openssl/bin/openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat /usr/local/etc/openssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:example.com,DNS:www.example.com")) > domain_multi.csr</code>

    # scratch
    openssl req -new -sha256 -key /var/folders/4o/4oYQL09OGcSwJ2-Uj2T+dE+++TI/-Tmp-/tmp9mT8V6 -subj "/" -reqexts SAN -config < /var/folders/4o/4oYQL09OGcSwJ2-Uj2T+dE+++TI/-Tmp-/tmpK9tsl9 >STDOUT
    (cat /System/Library/OpenSSL/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:yoursite.com,DNS:www.yoursite.com"))
    cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:yoursite.com,DNS:www.yoursite.com")
    cat  /usr/local/etc/openssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:yoursite.com,DNS:www.yoursite.com")
    cat /System/Library/OpenSSL/openssl.cnf printf "[SAN]\nsubjectAltName=DNS:yoursite.com,DNS:www.yoursite.com"
    /usr/local/opt/openssl/bin/openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <

    """
    if not dbAccountKey:
        raise ValueError("Must submit `dbAccountKey`")

    if not any((dbPrivateKey, private_key_pem)) or all((dbPrivateKey, private_key_pem)):
        raise ValueError(
            "Submit one and only one of: `dbPrivateKey`, `private_key_pem`"
        )

    if domain_names is None:
        if not dbServerCertificate__renewal_of:
            raise ValueError("`domain_names` must be provided unless this is a renewal")
        domain_names = dbServerCertificate__renewal_of.domains_as_list

    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__SslOperationsEvent(
        ctx,
        models.SslOperationsEventType.from_string("certificate_request__do__automated"),
    )

    tmpfiles = []
    dbCertificateRequest = None
    dbServerCertificate = None
    try:

        # we should have cleaned this up before, but just be safe
        domain_names = [i.lower() for i in [d.strip() for d in domain_names] if i]
        domain_names = set(domain_names)
        if not domain_names:
            raise ValueError("no domain names!")
        # we need a list
        domain_names = list(domain_names)

        # pull the pem out of the account_key
        account_key_pem = dbAccountKey.key_pem

        # we need to use tmpfiles on the disk
        tmpfile_account = cert_utils.new_pem_tempfile(account_key_pem)
        tmpfiles.append(tmpfile_account)

        if dbPrivateKey is None:
            private_key_pem = cert_utils.cleanup_pem_text(private_key_pem)
            (
                dbPrivateKey,
                _is_created,
            ) = lib.db.getcreate.getcreate__SslPrivateKey__by_pem_text(
                ctx, private_key_pem
            )
        else:
            private_key_pem = dbPrivateKey.key_pem

        # we need to use tmpfiles on the disk
        tmpfile_pkey = cert_utils.new_pem_tempfile(private_key_pem)
        tmpfiles.append(tmpfile_pkey)

        # make the CSR
        csr_pem = cert_utils.new_csr_for_domain_names(
            domain_names, private_key_path=tmpfile_pkey.name, tmpfiles_tracker=tmpfiles
        )
        tmpfile_csr = cert_utils.new_pem_tempfile(csr_pem)
        tmpfiles.append(tmpfile_csr)

        # these MUST commit
        with transaction.manager as tx:
            (
                dbCertificateRequest,
                dbDomainObjects,
            ) = lib.db.create.create__SslCertificateRequest(
                ctx,
                csr_pem,
                certificate_request_type_id=models.SslCertificateRequestType.ACME_AUTOMATED,
                dbAccountKey=dbAccountKey,
                dbPrivateKey=dbPrivateKey,
                dbServerCertificate__issued=None,
                dbServerCertificate__renewal_of=dbServerCertificate__renewal_of,
                domain_names=domain_names,
            )

        def process_keyauth_challenge(domain, token, keyauthorization):
            log.info("-process_keyauth_challenge %s", domain)
            with transaction.manager as tx:
                (dbDomain, dbCertificateRequest2D) = dbDomainObjects[domain]
                dbCertificateRequest2D.challenge_key = token
                dbCertificateRequest2D.challenge_text = keyauthorization
                ctx.dbSession.flush(objects=[dbCertificateRequest2D])

        def process_keyauth_cleanup(domain, token, keyauthorization):
            log.info("-process_keyauth_cleanup %s", domain)

        # ######################################################################
        # THIS BLOCK IS FROM acme-tiny

        # pull domains from csr
        csr_domains = cert_utils.parse_csr_domains(
            csr_path=tmpfile_csr.name, submitted_domain_names=domain_names
        )
        if set(csr_domains) != set(domain_names):
            raise ValueError("Did not make a valid set")

        # parse account key to get public key
        header, thumbprint = acme_v1.account_key__header_thumbprint(
            account_key_path=tmpfile_account.name
        )

        # register the account / ensure that it is registered
        if not dbAccountKey.timestamp_last_authenticated:
            do__SslAcmeAccountKey_authenticate(
                ctx, dbAccountKey, account_key_path=tmpfile_account.name
            )

        acmeLogger = AcmeLogger(
            ctx, dbAccountKey=dbAccountKey, dbCertificateRequest=dbCertificateRequest
        )

        # verify each domain
        acme_v1.acme_verify_domains(
            csr_domains=csr_domains,
            account_key_path=tmpfile_account.name,
            handle_keyauth_challenge=process_keyauth_challenge,
            handle_keyauth_cleanup=process_keyauth_cleanup,
            thumbprint=thumbprint,
            header=header,
            acmeLogger=acmeLogger,
            acmeAccountKey=dbAccountKey,
        )

        # sign it
        (
            cert_pem,
            chained_pem,
            chain_url,
            datetime_signed,
            datetime_expires,
            acmeLoggedEvent,
        ) = acme_v1.acme_sign_certificate(
            csr_path=tmpfile_csr.name,
            account_key_path=tmpfile_account.name,
            header=header,
            acmeLogger=acmeLogger,
            acmeAccountKey=dbAccountKey,
        )
        #
        # end acme-tiny
        # ######################################################################

        # let's make sure we have the right domains in the cert!!
        # this only happens on development during tests when we use a single cert
        # for all requests...
        # so we don't need to handle this or save it
        tmpfile_signed_cert = cert_utils.new_pem_tempfile(cert_pem)
        tmpfiles.append(tmpfile_signed_cert)
        cert_domains = cert_utils.parse_cert_domains(tmpfile_signed_cert.name)
        if set(domain_names) != set(cert_domains):
            # if not acme_v1.TESTING_ENVIRONMENT:
            log.error("set(domain_names) != set(cert_domains)")
            log.error(domain_names)
            log.error(cert_domains)
            # current version of fakeboulder will sign the csr and give us the right domains !
            raise ValueError("this should not happen!")

        # these MUST commit
        with transaction.manager as tx:
            dbServerCertificate = lib.db.create.create__SslServerCertificate(
                ctx,
                timestamp_signed=datetime_signed,
                timestamp_expires=datetime_expires,
                is_active=True,
                cert_pem=cert_pem,
                chained_pem=chained_pem,
                chain_name=chain_url,
                dbCertificateRequest=dbCertificateRequest,
                dbAcmeAccountKey=dbAccountKey,
                dbPrivateKey=dbPrivateKey,
                dbDomains=[v[0] for v in dbDomainObjects.values()],
                dbServerCertificate__renewal_of=dbServerCertificate__renewal_of,
            )
            if dbServerCertificate__renewal_of:
                dbServerCertificate__renewal_of.is_auto_renew = False
                dbServerCertificate__renewal_of.is_renewed = True
                ctx.dbSession.flush(objects=[dbServerCertificate__renewal_of])
            if dbQueueRenewal__of:
                dbQueueRenewal__of.timestamp_processed = ctx.timestamp
                dbQueueRenewal__of.process_result = True
                dbQueueRenewal__of.is_active = False
                ctx.dbSession.flush(objects=[dbQueueRenewal__of])
            # update the logger
            acmeLogger.log_event_certificate(acmeLoggedEvent, dbServerCertificate)

        log.debug("mark_changed(ctx.dbSession) - is this necessary?")
        mark_changed(ctx.dbSession)  # not sure why this is needed, but it is
        # don't commit here, as that will trigger an error on object refresh
        return dbServerCertificate

    except Exception as exc:
        if dbCertificateRequest:
            dbCertificateRequest.is_active = False
            dbCertificateRequest.is_error = True
            ctx.dbSession.flush(objects=[dbCertificateRequest])
            log.debug("mark_changed(ctx.dbSession) - is this necessary?")
            mark_changed(ctx.dbSession)  # not sure why this is needed, but it is
            transaction.commit()
        raise

    finally:
        # cleanup tmpfiles
        for tf in tmpfiles:
            tf.close()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def operations_deactivate_expired(ctx):
    """
    deactivates expired certificates automatically
    2016.06.04 - dbOperationsEvent compliant
    """
    # create an event first
    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict["count_deactivated"] = 0
    operationsEvent = log__SslOperationsEvent(
        ctx,
        models.SslOperationsEventType.from_string("certificate__deactivate_expired"),
        event_payload_dict,
    )

    # update the recents, this will automatically create a subevent
    subevent = operations_update_recents(ctx)

    # okay, go!

    # deactivate expired certificates
    expired_certs = (
        ctx.dbSession.query(models.SslServerCertificate)
        .filter(
            models.SslServerCertificate.is_active.is_(True),
            models.SslServerCertificate.timestamp_expires < ctx.timestamp,
        )
        .all()
    )
    for c in expired_certs:
        c.is_active = False
        ctx.dbSession.flush(objects=[c])
        events.Certificate_expired(ctx, c)

    # update the event
    if len(expired_certs):
        event_payload_dict["count_deactivated"] = len(expired_certs)
        event_payload_dict["ssl_server_certificate.ids"] = [c.id for c in expired_certs]
        operationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[operationsEvent])

    return operationsEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def operations_deactivate_duplicates(ctx, ran_operations_update_recents=None):
    """
    this is kind of weird.
    because we have multiple domains, it is hard to figure out which certs we should use
    the simplest approach is this:

    1. cache the most recent certs via `operations_update_recents`
    2. find domains that have multiple active certs
    3. don't turn off any certs that are a latest_single or latest_multi
    """
    raise ValueError("Don't run this. It's not needed anymore")
    raise errors.OperationsContextError("Not Compliant")

    if ran_operations_update_recents is not True:
        raise ValueError("MUST run `operations_update_recents` first")

    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    event_payload_dict["count_deactivated"] = 0
    operationsEvent = log__SslOperationsEvent(
        ctx,
        models.SslOperationsEventType.from_string("deactivate_duplicate"),
        event_payload_dict,
    )

    _q_ids__latest_single = (
        ctx.dbSession.query(models.SslDomain.ssl_server_certificate_id__latest_single)
        .distinct()
        .filter(
            models.SslDomain.ssl_server_certificate_id__latest_single != None  # noqa
        )
        .subquery()
    )
    _q_ids__latest_multi = (
        ctx.dbSession.query(models.SslDomain.ssl_server_certificate_id__latest_multi)
        .distinct()
        .filter(
            models.SslDomain.ssl_server_certificate_id__latest_single != None  # noqa
        )
        .subquery()
    )

    # now grab the domains with many certs...
    q_inner = (
        ctx.dbSession.query(
            models.SslUniqueFQDNSet2SslDomain.ssl_domain_id,
            sqlalchemy.func.count(
                models.SslUniqueFQDNSet2SslDomain.ssl_domain_id
            ).label("counted"),
        )
        .join(
            models.SslServerCertificate,
            models.SslUniqueFQDNSet2SslDomain.ssl_unique_fqdn_set_id
            == models.SslServerCertificate.ssl_unique_fqdn_set_id,
        )
        .filter(models.SslServerCertificate.is_active.is_(True))
        .group_by(models.SslUniqueFQDNSet2SslDomain.ssl_domain_id)
    )
    q_inner = q_inner.subquery()
    q_domains = ctx.dbSession.query(q_inner).filter(q_inner.c.counted >= 2)
    result = q_domains.all()
    domain_ids_with_multiple_active_certs = [i.ssl_domain_id for i in result]

    if False:
        _turned_off = []
        for _domain_id in domain_ids_with_multiple_active_certs:
            domain_certs = (
                ctx.dbSession.query(models.SslServerCertificate)
                .join(
                    models.SslUniqueFQDNSet2SslDomain,
                    models.SslServerCertificate.ssl_unique_fqdn_set_id
                    == models.SslUniqueFQDNSet2SslDomain.ssl_unique_fqdn_set_id,
                )
                .filter(
                    models.SslServerCertificate.is_active.is_(True),
                    models.SslUniqueFQDNSet2SslDomain.ssl_domain_id == _domain_id,
                    models.SslServerCertificate.id.notin_(_q_ids__latest_single),
                    models.SslServerCertificate.id.notin_(_q_ids__latest_multi),
                )
                .order_by(models.SslServerCertificate.timestamp_expires.desc())
                .all()
            )
            if len(domain_certs) > 1:
                for cert in domain_certs[1:]:
                    cert.is_active = False
                    _turned_off.append(cert)
                    events.Certificate_deactivated(ctx, cert)

    # update the event
    if len(_turned_off):
        event_payload_dict["count_deactivated"] = len(_turned_off)
        operationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[operationsEvent])

    return operationsEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def operations_update_recents(ctx):
    """
    updates all the objects to their most-recent relations
    2016.06.04 - dbOperationsEvent compliant
    """
    # first the single
    # _t_domain = models.SslDomain.__table__.alias('domain')

    _q_sub = (
        ctx.dbSession.query(models.SslServerCertificate.id)
        .join(
            models.SslUniqueFQDNSet2SslDomain,
            models.SslServerCertificate.ssl_unique_fqdn_set_id
            == models.SslUniqueFQDNSet2SslDomain.ssl_unique_fqdn_set_id,
        )
        .filter(
            models.SslServerCertificate.is_active.is_(True),
            models.SslServerCertificate.is_single_domain_cert.is_(True),
            models.SslUniqueFQDNSet2SslDomain.ssl_domain_id == models.SslDomain.id,
        )
        .order_by(models.SslServerCertificate.timestamp_expires.desc())
        .limit(1)
        .scalar_subquery()
    )
    ctx.dbSession.execute(
        models.SslDomain.__table__.update().values(
            ssl_server_certificate_id__latest_single=_q_sub
        )
    )

    # then the multiple
    # _t_domain = models.SslDomain.__table__.alias('domain')
    _q_sub = (
        ctx.dbSession.query(models.SslServerCertificate.id)
        .join(
            models.SslUniqueFQDNSet2SslDomain,
            models.SslServerCertificate.ssl_unique_fqdn_set_id
            == models.SslUniqueFQDNSet2SslDomain.ssl_unique_fqdn_set_id,
        )
        .filter(
            models.SslServerCertificate.is_active.is_(True),
            models.SslServerCertificate.is_single_domain_cert.is_(False),
            models.SslUniqueFQDNSet2SslDomain.ssl_domain_id == models.SslDomain.id,
        )
        .order_by(models.SslServerCertificate.timestamp_expires.desc())
        .limit(1)
        .scalar_subquery()
    )
    ctx.dbSession.execute(
        models.SslDomain.__table__.update().values(
            ssl_server_certificate_id__latest_multi=_q_sub
        )
    )

    # update the count of active certs
    SslServerCertificate1 = sqlalchemy.orm.aliased(models.SslServerCertificate)
    SslServerCertificate2 = sqlalchemy.orm.aliased(models.SslServerCertificate)
    _q_sub = (
        ctx.dbSession.query(sqlalchemy.func.count(models.SslDomain.id))
        .outerjoin(
            SslServerCertificate1,
            models.SslDomain.ssl_server_certificate_id__latest_single
            == SslServerCertificate1.id,
        )
        .outerjoin(
            SslServerCertificate2,
            models.SslDomain.ssl_server_certificate_id__latest_multi
            == SslServerCertificate2.id,
        )
        .filter(
            sqlalchemy.or_(
                models.SslCaCertificate.id
                == SslServerCertificate1.ssl_ca_certificate_id__upchain,
                models.SslCaCertificate.id
                == SslServerCertificate2.ssl_ca_certificate_id__upchain,
            )
        )
        .scalar_subquery()
    )
    ctx.dbSession.execute(
        models.SslCaCertificate.__table__.update().values(
            count_active_certificates=_q_sub
        )
    )

    # update the count of active PrivateKeys
    SslServerCertificate1 = sqlalchemy.orm.aliased(models.SslServerCertificate)
    SslServerCertificate2 = sqlalchemy.orm.aliased(models.SslServerCertificate)
    _q_sub = (
        ctx.dbSession.query(sqlalchemy.func.count(models.SslDomain.id))
        .outerjoin(
            SslServerCertificate1,
            models.SslDomain.ssl_server_certificate_id__latest_single
            == SslServerCertificate1.id,
        )
        .outerjoin(
            SslServerCertificate2,
            models.SslDomain.ssl_server_certificate_id__latest_multi
            == SslServerCertificate2.id,
        )
        .filter(
            sqlalchemy.or_(
                models.SslPrivateKey.id
                == SslServerCertificate1.ssl_private_key_id__signed_by,
                models.SslPrivateKey.id
                == SslServerCertificate2.ssl_private_key_id__signed_by,
            )
        )
        .scalar_subquery()
    )
    ctx.dbSession.execute(
        models.SslPrivateKey.__table__.update().values(count_active_certificates=_q_sub)
    )

    # the following works, but this is currently tracked
    """
        # update the counts on Account Keys
        _q_sub_req = ctx.dbSession.query(sqlalchemy.func.count(models.SslCertificateRequest.id))\
            .filter(models.SslCertificateRequest.ssl_acme_account_key_id == models.SslAcmeAccountKey.id,
                    )\
            .scalar_subquery()
        ctx.dbSession.execute(models.SslAcmeAccountKey.__table__
                              .update()
                              .values(count_certificate_requests=_q_sub_req,
                                      # count_certificates_issued=_q_sub_iss,
                                      )
                              )
        # update the counts on Private Keys
        _q_sub_req = ctx.dbSession.query(sqlalchemy.func.count(models.SslCertificateRequest.id))\
            .filter(models.SslCertificateRequest.ssl_private_key_id__signed_by == models.SslPrivateKey.id,
                    )\
            .scalar_subquery()
        _q_sub_iss = ctx.dbSession.query(sqlalchemy.func.count(models.SslServerCertificate.id))\
            .filter(models.SslServerCertificate.ssl_private_key_id__signed_by == models.SslPrivateKey.id,
                    )\
            .scalar_subquery()

        ctx.dbSession.execute(models.SslPrivateKey.__table__
                              .update()
                              .values(count_certificate_requests=_q_sub_req,
                                      count_certificates_issued=_q_sub_iss,
                                      )
                              )
    """

    # should we do the timestamps?
    """
    UPDATE ssl_acme_account_key SET timestamp_last_certificate_request = (
    SELECT MAX(timestamp_finished) FROM ssl_certificate_request
    WHERE ssl_certificate_request.ssl_acme_account_key_id = ssl_acme_account_key.id);

    UPDATE ssl_acme_account_key SET timestamp_last_certificate_issue = (
    SELECT MAX(timestamp_signed) FROM ssl_server_certificate
    WHERE ssl_server_certificate.ssl_acme_account_key_id = ssl_acme_account_key.id);

    UPDATE ssl_private_key SET timestamp_last_certificate_request = (
    SELECT MAX(timestamp_finished) FROM ssl_certificate_request
    WHERE ssl_certificate_request.ssl_private_key_id__signed_by = ssl_private_key.id);

    UPDATE ssl_private_key SET timestamp_last_certificate_issue = (
    SELECT MAX(timestamp_signed) FROM ssl_server_certificate
    WHERE ssl_server_certificate.ssl_private_key_id__signed_by = ssl_private_key.id);
    """

    # bookkeeping, doing this will mark the session as changed!
    dbOperationsEvent = log__SslOperationsEvent(
        ctx, models.SslOperationsEventType.from_string("operations__update_recents")
    )

    # mark the session changed
    # update: we don't need this if we add the bookkeeping object
    # update2: there is an unresolved bug/behavior where including this somehow commits
    log.debug("mark_changed(ctx.dbSession) - is this necessary?")
    mark_changed(ctx.dbSession)

    return dbOperationsEvent


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def api_domains__enable(ctx, domain_names):
    """this is just a proxy around queue_domains__add"""

    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__SslOperationsEvent(
        ctx,
        models.SslOperationsEventType.from_string("api_domains__enable"),
        event_payload_dict,
    )
    results = lib.db.queues.queue_domains__add(ctx, domain_names)
    return results


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def api_domains__disable(ctx, domain_names):
    """
    disables domains
    """
    domain_names = lib_utils.domains_from_list(domain_names)
    results = {d: None for d in domain_names}

    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__SslOperationsEvent(
        ctx,
        models.SslOperationsEventType.from_string("api_domains__disable"),
        event_payload_dict,
    )

    for domain_name in domain_names:
        _dbDomain = lib.db.get.get__SslDomain__by_name(
            ctx, domain_name, preload=False, active_only=False
        )
        if _dbDomain:
            if _dbDomain.is_active:
                disable_Domain(
                    ctx,
                    _dbDomain,
                    dbOperationsEvent=dbOperationsEvent,
                    event_status="domain__mark__inactive",
                    action="deactivated",
                )
                results[domain_name] = "deactivated"
            else:
                results[domain_name] = "already deactivated"
        elif not _dbDomain:
            _dbQueueDomain = lib.db.get.get__SslQueueDomain__by_name(ctx, domain_name)
            if _dbQueueDomain:
                lib.db.queues.dequeue_QueuedDomain(
                    ctx,
                    _dbQueueDomain,
                    dbOperationsEvent=dbOperationsEvent,
                    event_status="queue_domain__mark__cancelled",
                    action="de-queued",
                )
                results[domain_name] = "de-queued"
            else:
                results[domain_name] = "not active or in queue"

    event_payload_dict["results"] = results
    dbOperationsEvent = ctx.dbSession.merge(dbOperationsEvent)
    dbOperationsEvent.set_event_payload(event_payload_dict)
    ctx.dbSession.flush(objects=[dbOperationsEvent])

    return results


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def api_domains__certificate_if_needed(
    ctx, domain_names, account_key_pem=None, dbPrivateKey=None
):
    """
    Adds domains if needed
    2016.06.29

    results will be a dict:

        {%DOMAIN_NAME%: {'domain': # active, activated, new, FAIL
                         'certificate':  # active, new, FAIL

    logging codes
        2010: 'api_domains__certificate_if_needed',
        2011: 'api_domains__certificate_if_needed__domain_exists',
        2012: 'api_domains__certificate_if_needed__domain_activate',
        2013: 'api_domains__certificate_if_needed__domain_new',
        2015: 'api_domains__certificate_if_needed__certificate_exists',
        2016: 'api_domains__certificate_if_needed__certificate_new_success',
        2017: 'api_domains__certificate_if_needed__certificate_new_fail',
    """
    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__SslOperationsEvent(
        ctx,
        models.SslOperationsEventType.from_string("api_domains__certificate_if_needed"),
        event_payload_dict,
    )

    dbAccountKey = None
    if account_key_pem is not None:
        raise ValueError("acmeAccountProvider_id")
        dbAccountKey, _is_created = lib.db.getcreate.getcreate__SslAcmeAccountKey(
            ctx, account_key_pem, acmeAccountProvider_id=None
        )
        if not dbAccountKey:
            raise errors.DisplayableError("Could not create an AccountKey")

    if account_key_pem is None:
        dbAccountKey = lib.db.get.get__SslAcmeAccountKey__default(ctx)
        if not dbAccountKey:
            raise errors.DisplayableError("Could not grab an AccountKey")

    if dbPrivateKey is None:
        dbPrivateKey = lib.db.get.get__SslPrivateKey__current_week(ctx)
        if not dbPrivateKey:
            dbPrivateKey = lib.db.create.create__SslPrivateKey__autogenerated(ctx)
        if not dbPrivateKey:
            raise errors.DisplayableError("Could not grab a PrivateKey")

    domain_names = lib_utils.domains_from_list(domain_names)
    results = {d: None for d in domain_names}
    _timestamp = dbOperationsEvent.timestamp_event
    for domain_name in domain_names:
        _result = {
            "domain.status": None,
            "certificate.status": None,
            "ssl_domain.id": None,
            "ssl_server_certificate.id": None,
        }

        _dbQueueDomain = None

        # go for the domain
        _logger_args = {"event_status_id": None}
        _dbDomain = lib.db.get.get__SslDomain__by_name(
            ctx, domain_name, preload=False, active_only=False
        )
        if _dbDomain:
            _result["ssl_domain.id"] = _dbDomain.id

            if not _dbDomain.is_active:
                _result["domain.status"] = "activated"

                _logger_args[
                    "event_status_id"
                ] = models.SslOperationsObjectEventStatus.from_string(
                    "api_domains__certificate_if_needed__domain_activate"
                )
                _logger_args["dbDomain"] = _dbDomain

                # set this active
                _dbDomain.is_active = True
                ctx.dbSession.flush(objects=[_dbDomain])

            else:
                _result["domain.status"] = "exists"

                _logger_args[
                    "event_status_id"
                ] = models.SslOperationsObjectEventStatus.from_string(
                    "api_domains__certificate_if_needed__domain_exists"
                )
                _logger_args["dbDomain"] = _dbDomain

        elif not _dbDomain:

            _dbDomain = lib.db.getcreate.getcreate__SslDomain__by_domainName(
                ctx, domain_name
            )[
                0
            ]  # (dbDomain, _is_created)
            _result["domain.status"] = "new"
            _result["ssl_domain.id"] = _dbDomain.id
            _logger_args[
                "event_status_id"
            ] = models.SslOperationsObjectEventStatus.from_string(
                "api_domains__certificate_if_needed__domain_new"
            )
            _logger_args["dbDomain"] = _dbDomain

        # log domain event
        _log_object_event(ctx, dbOperationsEvent=dbOperationsEvent, **_logger_args)

        # do commit, just because we may have created a domain, AND THE LOGGGING
        transaction.commit()

        # go for the certificate
        _logger_args = {"event_status_id": None}
        _dbServerCertificate = lib.db.get.get__SslServerCertificate__by_SslDomainId__latest(
            ctx, _dbDomain.id
        )
        if _dbServerCertificate:
            _result["certificate.status"] = "exists"
            _result["ssl_server_certificate.id"] = _dbServerCertificate.id
            _logger_args[
                "event_status_id"
            ] = models.SslOperationsObjectEventStatus.from_string(
                "api_domains__certificate_if_needed__certificate_exists"
            )
            _logger_args["dbServerCertificate"] = _dbServerCertificate
        else:
            try:
                _dbServerCertificate = do__CertificateRequest__AcmeAutomated(
                    ctx,
                    domain_names,
                    dbAccountKey=dbAccountKey,
                    dbPrivateKey=dbPrivateKey,
                )
                _result["certificate.status"] = "new"
                _result["ssl_server_certificate.id"] = _dbServerCertificate.id

                _logger_args[
                    "event_status_id"
                ] = models.SslOperationsObjectEventStatus.from_string(
                    "api_domains__certificate_if_needed__certificate_new_success"
                )
                _logger_args["dbServerCertificate"] = _dbServerCertificate

            except errors.DomainVerificationError as exc:
                _result["certificate.status"] = "fail"
                _result["ssl_server_certificate.id"] = None

                _logger_args[
                    "event_status_id"
                ] = models.SslOperationsObjectEventStatus.from_string(
                    "api_domains__certificate_if_needed__certificate_new_fail"
                )
                _logger_args["dbServerCertificate"] = None

        dbOperationsEvent = ctx.dbSession.merge(dbOperationsEvent)

        # log domain event
        _log_object_event(ctx, dbOperationsEvent=dbOperationsEvent, **_logger_args)

        # do commit, just because THE LOGGGING
        transaction.commit()

        # remove from queue if it exists
        _dbQueueDomain = lib.db.get.get__SslQueueDomain__by_name(ctx, domain_name)
        if _dbQueueDomain:
            lib.db.queues.dequeue_QueuedDomain(
                ctx,
                _dbQueueDomain,
                dbOperationsEvent=dbOperationsEvent,
                event_status="queue_domain__mark__already_processed",
                action="already_processed",
            )

        # do commit, just because THE LOGGGING
        transaction.commit()

        # note result
        results[domain_name] = _result

    event_payload_dict["results"] = results
    dbOperationsEvent = ctx.dbSession.merge(dbOperationsEvent)
    dbOperationsEvent.set_event_payload(event_payload_dict)
    ctx.dbSession.flush(objects=[dbOperationsEvent])

    return results


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def upload__SslCaCertificateBundle__by_pem_text(ctx, bundle_data):
    """
    Uploads a bundle of CaCertificates
    2016.06.04 - dbOperationsEvent compliant
    """
    # bookkeeping
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__SslOperationsEvent(
        ctx,
        models.SslOperationsEventType.from_string("ca_certificate__upload_bundle"),
        event_payload_dict,
    )
    results = {}
    for cert_pem in bundle_data.keys():
        if cert_pem[-4:] != "_pem":
            raise ValueError("key does not end in `_pem`")
        cert_base = cert_pem[:-4]
        cert_pem_text = bundle_data[cert_pem]
        cert_name = None
        le_authority_name = None
        is_authority_certificate = None
        is_cross_signed_authority_certificate = None
        for c in letsencrypt_info.CA_CERTS_DATA:
            if cert_base == c["formfield_base"]:
                cert_name = c["name"]
                if "le_authority_name" in c:
                    le_authority_name = c["le_authority_name"]
                if "is_authority_certificate" in c:
                    is_authority_certificate = c["is_authority_certificate"]
                if "is_cross_signed_authority_certificate" in c:
                    is_cross_signed_authority_certificate = c[
                        "is_cross_signed_authority_certificate"
                    ]
                break

        (
            dbCACertificate,
            is_created,
        ) = lib.db.getcreate.getcreate__SslCaCertificate__by_pem_text(
            ctx,
            cert_pem_text,
            cert_name,
            le_authority_name=None,
            is_authority_certificate=None,
            is_cross_signed_authority_certificate=None,
        )
        if not is_created:
            if dbCACertificate.name in ("unknown", "manual upload") and cert_name:
                dbCACertificate.name = cert_name
            if dbCACertificate.le_authority_name is None:
                dbCACertificate.le_authority_name = le_authority_name
            if dbCACertificate.is_authority_certificate is None:
                dbCACertificate.is_authority_certificate = is_authority_certificate
            if dbCACertificate.le_authority_name is None:
                dbCACertificate.is_cross_signed_authority_certificate = (
                    is_cross_signed_authority_certificate
                )

        results[cert_pem] = (dbCACertificate, is_created)

    ids_created = [i[0].id for i in results.values() if i[1]]
    ids_updated = [i[0].id for i in results.values() if not i[1]]
    event_payload_dict["ids_created"] = ids_created
    event_payload_dict["ids_updated"] = ids_updated
    dbOperationsEvent.set_event_payload(event_payload_dict)
    ctx.dbSession.flush(objects=[dbOperationsEvent])
    return results
