# logging
import logging

log = logging.getLogger(__name__)

# pypi
import json

# localapp
from ...models import models
from ... import lib
from .. import cert_utils
from .. import utils

# local
from .get import get__SslCaCertificate__by_pem_text
from .get import get__SslCertificateRequest__by_pem_text
from .get import get__SslDomain__by_name
from .logger import log__SslOperationsEvent
from .logger import _log_object_event
from .helpers import _certificate_parse_to_record


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__SslAcmeAccountKey(
    ctx,
    key_pem=None,
    le_meta_jsons=None,
    le_pkey_jsons=None,
    le_reg_jsons=None,
    acme_account_provider_id=None,
):
    """
    Gets or Creates AccountKeys for LetsEncrypts' ACME server
    2018.05.18 - extend creation args
        key_pem
        le_meta_json
        le_pkey_json
        le_reg_json
    2018.05.17 - add acmeAccountProvider_id
    2016.06.04 - dbOperationsEvent compliant
    """
    if (key_pem) and any((le_meta_jsons, le_pkey_jsons, le_reg_jsons)):
        raise ValueError(
            "Must supply `key_pem` OR all of `le_meta_jsons, le_pkey_jsons, le_reg_jsons`."
        )
    if not (key_pem) and not all((le_meta_jsons, le_pkey_jsons, le_reg_jsons)):
        raise ValueError(
            "Must supply `key_pem` OR all of `le_meta_jsons, le_pkey_jsons, le_reg_jsons`."
        )

    if key_pem:
        key_pem = cert_utils.cleanup_pem_text(key_pem)
        key_pem_md5 = utils.md5_text(key_pem)
        is_created = False
        dbAcmeAccountKey = (
            ctx.dbSession.query(models.SslAcmeAccountKey)
            .filter(
                models.SslAcmeAccountKey.key_pem_md5 == key_pem_md5,
                models.SslAcmeAccountKey.key_pem == key_pem,
            )
            .first()
        )
        if not dbAcmeAccountKey:
            if acme_account_provider_id is None:
                raise ValueError(
                    "no `acme_account_provider_id`. required if PEM key is uploaded."
                )
            try:
                _tmpfile = cert_utils.new_pem_tempfile(key_pem)

                # validate
                cert_utils.validate_key__pem_filepath(_tmpfile.name)

                # grab the modulus
                key_pem_modulus_md5 = cert_utils.modulus_md5_key__pem_filepath(
                    _tmpfile.name
                )
            except Exception as exc:
                raise
            finally:
                _tmpfile.close()

            event_payload_dict = utils.new_event_payload_dict()
            dbOperationsEvent = log__SslOperationsEvent(
                ctx,
                models.SslOperationsEventType.from_string("acme_account_key__insert"),
            )

            dbAcmeAccountKey = models.SslAcmeAccountKey()
            dbAcmeAccountKey.timestamp_first_seen = ctx.timestamp
            dbAcmeAccountKey.key_pem = key_pem
            dbAcmeAccountKey.key_pem_md5 = key_pem_md5
            dbAcmeAccountKey.key_pem_modulus_md5 = key_pem_modulus_md5
            dbAcmeAccountKey.ssl_operations_event_id__created = dbOperationsEvent.id
            dbAcmeAccountKey.acme_account_provider_id = acme_account_provider_id
            ctx.dbSession.add(dbAcmeAccountKey)
            ctx.dbSession.flush(objects=[dbAcmeAccountKey])
            is_created = True

            event_payload_dict["ssl_acme_account_key.id"] = dbAcmeAccountKey.id
            dbOperationsEvent.set_event_payload(event_payload_dict)
            ctx.dbSession.flush(objects=[dbOperationsEvent])

            _log_object_event(
                ctx,
                dbOperationsEvent=dbOperationsEvent,
                event_status_id=models.SslOperationsObjectEventStatus.from_string(
                    "acme_account_key__insert"
                ),
                dbAcmeAccountKey=dbAcmeAccountKey,
            )
    else:
        le_meta_json = json.loads(le_meta_jsons)
        le_reg_json = json.loads(le_reg_jsons)
        """
        There is some useful data in here...
            meta.json = creation_dt DATETIME; save as created
            meta.json = creation_host STRING; save for info
            regr.json = contact: email, save for info
            regr.json = agreement: url, save for info
            regr.json = key, save for info
            regr.json = uri, save for info
            regr.json = tos, save for info
        """
        letsencrypt_data = {"meta.json": le_meta_json, "regr.json": le_reg_json}
        letsencrypt_data = json.dumps(letsencrypt_data)

        # derive the api server
        try:
            account_uri = le_reg_json["uri"]
            for acme_provider in models.AcmeAccountProvider.registry.values():
                if not acme_provider["endpoint"]:
                    # the custom might not be enabled...
                    continue
                if account_uri.startswith(acme_provider["endpoint"]):
                    acme_account_provider_id = acme_provider["id"]
            if acme_account_provider_id is None:
                raise ValueError("could not derive an account")
        except KeyError:
            raise ValueError("could not parse an account")

        key_pem = cert_utils.convert_lejson(le_pkey_jsons)
        key_pem = cert_utils.cleanup_pem_text(key_pem)
        key_pem_md5 = utils.md5_text(key_pem)
        is_created = False
        dbAcmeAccountKey = (
            ctx.dbSession.query(models.SslAcmeAccountKey)
            .filter(
                models.SslAcmeAccountKey.key_pem_md5 == key_pem_md5,
                models.SslAcmeAccountKey.key_pem == key_pem,
            )
            .first()
        )
        if not dbAcmeAccountKey:
            try:
                _tmpfile = cert_utils.new_pem_tempfile(key_pem)

                # validate
                cert_utils.validate_key__pem_filepath(_tmpfile.name)

                # grab the modulus
                key_pem_modulus_md5 = cert_utils.modulus_md5_key__pem_filepath(
                    _tmpfile.name
                )
            except Exception as exc:
                raise
            finally:
                _tmpfile.close()

            event_payload_dict = utils.new_event_payload_dict()
            dbOperationsEvent = log__SslOperationsEvent(
                ctx,
                models.SslOperationsEventType.from_string("acme_account_key__insert"),
            )

            dbAcmeAccountKey = models.SslAcmeAccountKey()
            dbAcmeAccountKey.timestamp_first_seen = ctx.timestamp
            dbAcmeAccountKey.key_pem = key_pem
            dbAcmeAccountKey.key_pem_md5 = key_pem_md5
            dbAcmeAccountKey.key_pem_modulus_md5 = key_pem_modulus_md5
            dbAcmeAccountKey.ssl_operations_event_id__created = dbOperationsEvent.id
            dbAcmeAccountKey.acme_account_provider_id = acme_account_provider_id
            dbAcmeAccountKey.letsencrypt_data = letsencrypt_data

            ctx.dbSession.add(dbAcmeAccountKey)
            ctx.dbSession.flush(objects=[dbAcmeAccountKey])
            is_created = True

            event_payload_dict["ssl_acme_account_key.id"] = dbAcmeAccountKey.id
            dbOperationsEvent.set_event_payload(event_payload_dict)
            ctx.dbSession.flush(objects=[dbOperationsEvent])

            _log_object_event(
                ctx,
                dbOperationsEvent=dbOperationsEvent,
                event_status_id=models.SslOperationsObjectEventStatus.from_string(
                    "acme_account_key__insert"
                ),
                dbAcmeAccountKey=dbAcmeAccountKey,
            )

    return dbAcmeAccountKey, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__SslCaCertificate__by_pem_text(
    ctx,
    cert_pem,
    chain_name,
    le_authority_name=None,
    is_authority_certificate=None,
    is_cross_signed_authority_certificate=None,
):
    """
    Gets or Creates CaCertificates
    2016.06.04 - dbOperationsEvent compliant
    """
    dbCACertificate = get__SslCaCertificate__by_pem_text(ctx, cert_pem)
    is_created = False
    if not dbCACertificate:
        cert_pem = cert_utils.cleanup_pem_text(cert_pem)
        cert_pem_md5 = utils.md5_text(cert_pem)
        try:
            _tmpfile = cert_utils.new_pem_tempfile(cert_pem)

            # validate
            cert_utils.validate_cert__pem_filepath(_tmpfile.name)

            # grab the modulus
            cert_pem_modulus_md5 = cert_utils.modulus_md5_cert__pem_filepath(
                _tmpfile.name
            )

            # bookkeeping
            event_payload_dict = utils.new_event_payload_dict()
            dbOperationsEvent = log__SslOperationsEvent(
                ctx, models.SslOperationsEventType.from_string("ca_certificate__insert")
            )

            dbCACertificate = models.SslCaCertificate()
            dbCACertificate.name = chain_name or "unknown"

            dbCACertificate.le_authority_name = le_authority_name
            dbCACertificate.is_ca_certificate = True
            dbCACertificate.is_authority_certificate = is_authority_certificate
            dbCACertificate.is_cross_signed_authority_certificate = (
                is_cross_signed_authority_certificate
            )
            dbCACertificate.id_cross_signed_of = None
            dbCACertificate.timestamp_first_seen = ctx.timestamp
            dbCACertificate.cert_pem = cert_pem
            dbCACertificate.cert_pem_md5 = cert_pem_md5
            dbCACertificate.cert_pem_modulus_md5 = cert_pem_modulus_md5

            dbCACertificate.timestamp_signed = cert_utils.parse_startdate_cert__pem_filepath(
                _tmpfile.name
            )
            dbCACertificate.timestamp_expires = cert_utils.parse_enddate_cert__pem_filepath(
                _tmpfile.name
            )
            dbCACertificate.cert_subject = cert_utils.cert_single_op__pem_filepath(
                _tmpfile.name, "-subject"
            )
            dbCACertificate.cert_subject_hash = cert_utils.cert_single_op__pem_filepath(
                _tmpfile.name, "-subject_hash"
            )
            dbCACertificate.cert_issuer = cert_utils.cert_single_op__pem_filepath(
                _tmpfile.name, "-issuer"
            )
            dbCACertificate.cert_issuer_hash = cert_utils.cert_single_op__pem_filepath(
                _tmpfile.name, "-issuer_hash"
            )
            dbCACertificate.ssl_operations_event_id__created = dbOperationsEvent.id

            ctx.dbSession.add(dbCACertificate)
            ctx.dbSession.flush(objects=[dbCACertificate])
            is_created = True

            event_payload_dict["ssl_ca_certificate.id"] = dbCACertificate.id
            dbOperationsEvent.set_event_payload(event_payload_dict)
            ctx.dbSession.flush(objects=[dbOperationsEvent])

            _log_object_event(
                ctx,
                dbOperationsEvent=dbOperationsEvent,
                event_status_id=models.SslOperationsObjectEventStatus.from_string(
                    "ca_certificate__insert"
                ),
                dbCACertificate=dbCACertificate,
            )

        except Exception as exc:
            raise
        finally:
            _tmpfile.close()

    return dbCACertificate, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__SslCertificateRequest__by_pem_text(
    ctx,
    csr_pem,
    certificate_request_type_id=None,
    dbAccountKey=None,
    dbPrivateKey=None,
    dbServerCertificate__issued=None,
    dbServerCertificate__renewal_of=None,
):
    """
    getcreate for a CSR
    log__SslOperationsEvent takes place in `create__SslCertificateRequest`
    2016.06.04 - dbOperationsEvent compliant
    """
    dbCertificateRequest = get__SslCertificateRequest__by_pem_text(ctx, csr_pem)
    is_created = False
    if not dbCertificateRequest:
        (
            dbCertificateRequest,
            dbDomainObjects,
        ) = lib.db.create.create__SslCertificateRequest(
            ctx,
            csr_pem,
            certificate_request_type_id=certificate_request_type_id,
            dbAccountKey=dbAccountKey,
            dbPrivateKey=dbPrivateKey,
            dbServerCertificate__issued=dbServerCertificate__issued,
            dbServerCertificate__renewal_of=dbServerCertificate__renewal_of,
        )
        is_created = True

    return dbCertificateRequest, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__SslDomain__by_domainName(ctx, domain_name, is_from_queue_domain=None):
    """
    getcreate wrapping a domain

    return dbDomain, is_created

    2016.06.04 - dbOperationsEvent compliant
    """
    is_created = False
    dbDomain = get__SslDomain__by_name(ctx, domain_name, preload=False)
    if not dbDomain:
        event_payload_dict = utils.new_event_payload_dict()
        dbOperationsEvent = log__SslOperationsEvent(
            ctx, models.SslOperationsEventType.from_string("domain__insert")
        )
        dbDomain = models.SslDomain()
        dbDomain.domain_name = domain_name
        dbDomain.timestamp_first_seen = ctx.timestamp
        dbDomain.is_from_queue_domain = is_from_queue_domain
        dbDomain.ssl_operations_event_id__created = dbOperationsEvent.id
        ctx.dbSession.add(dbDomain)
        ctx.dbSession.flush(objects=[dbDomain])
        is_created = True

        event_payload_dict["ssl_domain.id"] = dbDomain.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent])

        _log_object_event(
            ctx,
            dbOperationsEvent=dbOperationsEvent,
            event_status_id=models.SslOperationsObjectEventStatus.from_string(
                "domain__insert"
            ),
            dbDomain=dbDomain,
        )

    return dbDomain, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__SslPrivateKey__by_pem_text(ctx, key_pem, is_autogenerated_key=None):
    """
    getcreate wrapping private keys
    2016.06.04 - dbOperationsEvent compliant
    """
    key_pem = cert_utils.cleanup_pem_text(key_pem)
    key_pem_md5 = utils.md5_text(key_pem)
    is_created = False
    dbPrivateKey = (
        ctx.dbSession.query(models.SslPrivateKey)
        .filter(
            models.SslPrivateKey.key_pem_md5 == key_pem_md5,
            models.SslPrivateKey.key_pem == key_pem,
        )
        .first()
    )
    if not dbPrivateKey:
        try:
            _tmpfile = cert_utils.new_pem_tempfile(key_pem)

            # validate
            cert_utils.validate_key__pem_filepath(_tmpfile.name)

            # grab the modulus
            key_pem_modulus_md5 = cert_utils.modulus_md5_key__pem_filepath(
                _tmpfile.name
            )
        except Exception as exc:
            raise
        finally:
            _tmpfile.close()

        event_payload_dict = utils.new_event_payload_dict()
        _event_type_id = models.SslOperationsEventType.from_string(
            "private_key__insert"
        )
        if is_autogenerated_key:
            _event_type_id = models.SslOperationsEventType.from_string(
                "private_key__insert_autogenerated"
            )
        dbOperationsEvent = log__SslOperationsEvent(ctx, _event_type_id)

        dbPrivateKey = models.SslPrivateKey()
        dbPrivateKey.timestamp_first_seen = ctx.timestamp
        dbPrivateKey.key_pem = key_pem
        dbPrivateKey.key_pem_md5 = key_pem_md5
        dbPrivateKey.key_pem_modulus_md5 = key_pem_modulus_md5
        dbPrivateKey.is_autogenerated_key = is_autogenerated_key
        dbPrivateKey.ssl_operations_event_id__created = dbOperationsEvent.id
        ctx.dbSession.add(dbPrivateKey)
        ctx.dbSession.flush(objects=[dbPrivateKey])
        is_created = True

        event_payload_dict["ssl_private_key.id"] = dbPrivateKey.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent])

        _log_object_event(
            ctx,
            dbOperationsEvent=dbOperationsEvent,
            event_status_id=models.SslOperationsObjectEventStatus.from_string(
                "private_key__insert"
            ),
            dbPrivateKey=dbPrivateKey,
        )

    return dbPrivateKey, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__SslServerCertificate__by_pem_text(
    ctx,
    cert_pem,
    dbCACertificate=None,
    dbAccountKey=None,
    dbPrivateKey=None,
    dbServerCertificate__renewal_of=None,
):
    """
    getcreate wrapping issued certs
    2016.06.04 - dbOperationsEvent compliant
    """
    cert_pem = cert_utils.cleanup_pem_text(cert_pem)
    cert_pem_md5 = utils.md5_text(cert_pem)
    is_created = False
    dbServerCertificate = (
        ctx.dbSession.query(models.SslServerCertificate)
        .filter(
            models.SslServerCertificate.cert_pem_md5 == cert_pem_md5,
            models.SslServerCertificate.cert_pem == cert_pem,
        )
        .first()
    )
    if dbServerCertificate:
        if dbPrivateKey and (
            dbServerCertificate.ssl_private_key_id__signed_by != dbPrivateKey.id
        ):
            if dbServerCertificate.ssl_private_key_id__signed_by:
                raise ValueError("Integrity Error. Competing PrivateKey (!?)")
            elif dbServerCertificate.ssl_private_key_id__signed_by is None:
                dbServerCertificate.ssl_private_key_id__signed_by = dbPrivateKey.id
                dbPrivateKey.count_certificates_issued += 1
                if not dbPrivateKey.timestamp_last_certificate_issue or (
                    dbPrivateKey.timestamp_last_certificate_issue
                    < dbServerCertificate.timestamp_signed
                ):
                    dbPrivateKey.timestamp_last_certificate_issue = (
                        dbServerCertificate.timestamp_signed
                    )
                ctx.dbSession.flush(objects=[dbServerCertificate, dbPrivateKey])
        if dbAccountKey and (
            dbServerCertificate.ssl_acme_account_key_id != dbAccountKey.id
        ):
            if dbServerCertificate.ssl_acme_account_key_id:
                raise ValueError("Integrity Error. Competing AccountKey (!?)")
            elif dbServerCertificate.ssl_acme_account_key_id is None:
                dbServerCertificate.ssl_acme_account_key_id = dbAccountKey.id
                dbAccountKey.count_certificates_issued += 1
                if not dbAccountKey.timestamp_last_certificate_issue or (
                    dbAccountKey.timestamp_last_certificate_issue
                    < dbServerCertificate.timestamp_signed
                ):
                    dbAccountKey.timestamp_last_certificate_issue = (
                        dbAccountKey.timestamp_signed
                    )
                ctx.dbSession.flush(objects=[dbServerCertificate, dbAccountKey])
    elif not dbServerCertificate:
        _tmpfileCert = None
        try:
            _tmpfileCert = cert_utils.new_pem_tempfile(cert_pem)

            # validate
            cert_utils.validate_cert__pem_filepath(_tmpfileCert.name)

            # bookkeeping
            event_payload_dict = utils.new_event_payload_dict()
            dbOperationsEvent = log__SslOperationsEvent(
                ctx, models.SslOperationsEventType.from_string("certificate__insert")
            )

            dbServerCertificate = models.SslServerCertificate()
            _certificate_parse_to_record(_tmpfileCert, dbServerCertificate)

            dbServerCertificate.is_active = True
            dbServerCertificate.cert_pem = cert_pem
            dbServerCertificate.cert_pem_md5 = cert_pem_md5

            if dbServerCertificate__renewal_of:
                dbServerCertificate.ssl_server_certificate_id__renewal_of = (
                    dbServerCertificate__renewal_of.id
                )

            # this is the LetsEncrypt key
            if dbCACertificate is None:
                raise ValueError("dbCACertificate is None")
            # we should make sure it issued the certificate:
            if (
                dbServerCertificate.cert_issuer_hash
                != dbCACertificate.cert_subject_hash
            ):
                raise ValueError("dbCACertificate did not sign the certificate")
            dbServerCertificate.ssl_ca_certificate_id__upchain = dbCACertificate.id

            # this is the private key
            # we should make sure it signed the certificate
            # the md5 check isn't exact, BUT ITS CLOSE
            if dbPrivateKey is None:
                raise ValueError("dbPrivateKey is None")
            if (
                dbServerCertificate.cert_pem_modulus_md5
                != dbPrivateKey.key_pem_modulus_md5
            ):
                raise ValueError("dbPrivateKey did not sign the certificate")
            dbServerCertificate.ssl_private_key_id__signed_by = dbPrivateKey.id
            dbPrivateKey.count_certificates_issued += 1
            if not dbPrivateKey.timestamp_last_certificate_issue or (
                dbPrivateKey.timestamp_last_certificate_issue
                < dbServerCertificate.timestamp_signed
            ):
                dbPrivateKey.timestamp_last_certificate_issue = (
                    dbServerCertificate.timestamp_signed
                )

            # did we submit an account key?
            if dbAccountKey:
                dbServerCertificate.ssl_acme_account_key_id = dbAccountKey.id
                dbAccountKey.count_certificates_issued += 1
                if not dbAccountKey.timestamp_last_certificate_issue or (
                    dbAccountKey.timestamp_last_certificate_issue
                    < dbAccountKey.timestamp_signed
                ):
                    dbAccountKey.timestamp_last_certificate_issue = (
                        dbServerCertificate.timestamp_signed
                    )

            _subject_domain, _san_domains = cert_utils.parse_cert_domains__segmented(
                cert_path=_tmpfileCert.name
            )
            certificate_domain_names = _san_domains
            if (
                _subject_domain is not None
                and _subject_domain not in certificate_domain_names
            ):
                certificate_domain_names.insert(0, _subject_domain)
            if not certificate_domain_names:
                raise ValueError("could not find any domain names in the certificate")
            # getcreate__SslDomain__by_domainName returns a tuple of (domainObject, is_created)
            dbDomainObjects = [
                getcreate__SslDomain__by_domainName(ctx, _domain_name)[0]
                for _domain_name in certificate_domain_names
            ]
            (
                dbUniqueFqdnSet,
                is_created_fqdn,
            ) = getcreate__SslUniqueFQDNSet__by_domainObjects(ctx, dbDomainObjects)
            dbServerCertificate.ssl_unique_fqdn_set_id = dbUniqueFqdnSet.id

            if len(certificate_domain_names) == 1:
                dbServerCertificate.is_single_domain_cert = True
            elif len(certificate_domain_names) > 1:
                dbServerCertificate.is_single_domain_cert = False

            dbServerCertificate.ssl_operations_event_id__created = dbOperationsEvent.id
            ctx.dbSession.add(dbServerCertificate)
            ctx.dbSession.flush(objects=[dbServerCertificate])
            is_created = True

            event_payload_dict["ssl_server_certificate.id"] = dbServerCertificate.id
            dbOperationsEvent.set_event_payload(event_payload_dict)
            ctx.dbSession.flush(objects=[dbOperationsEvent])

            _log_object_event(
                ctx,
                dbOperationsEvent=dbOperationsEvent,
                event_status_id=models.SslOperationsObjectEventStatus.from_string(
                    "certificate__insert"
                ),
                dbServerCertificate=dbServerCertificate,
            )

        except Exception as exc:
            raise
        finally:
            if _tmpfileCert:
                _tmpfileCert.close()

    return dbServerCertificate, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__SslUniqueFQDNSet__by_domainObjects(ctx, domainObjects):
    """
    getcreate wrapping unique fqdn
    2016.06.04 - dbOperationsEvent compliant
    """
    is_created = False

    domain_ids = [dbDomain.id for dbDomain in domainObjects]
    domain_ids.sort()
    domain_ids_string = ",".join([str(id_) for id_ in domain_ids])

    dbUniqueFQDNSet = (
        ctx.dbSession.query(models.SslUniqueFQDNSet)
        .filter(models.SslUniqueFQDNSet.domain_ids_string == domain_ids_string)
        .first()
    )

    if not dbUniqueFQDNSet:
        event_payload_dict = utils.new_event_payload_dict()
        dbOperationsEvent = log__SslOperationsEvent(
            ctx, models.SslOperationsEventType.from_string("unqiue_fqdn__insert")
        )

        dbUniqueFQDNSet = models.SslUniqueFQDNSet()
        dbUniqueFQDNSet.domain_ids_string = domain_ids_string
        dbUniqueFQDNSet.timestamp_first_seen = ctx.timestamp
        dbUniqueFQDNSet.ssl_operations_event_id__created = dbOperationsEvent.id
        ctx.dbSession.add(dbUniqueFQDNSet)
        ctx.dbSession.flush(objects=[dbUniqueFQDNSet])

        for dbDomain in domainObjects:
            dbAssoc = models.SslUniqueFQDNSet2SslDomain()
            dbAssoc.ssl_unique_fqdn_set_id = dbUniqueFQDNSet.id
            dbAssoc.ssl_domain_id = dbDomain.id
            ctx.dbSession.add(dbAssoc)
            ctx.dbSession.flush(objects=[dbAssoc])
        is_created = True

        event_payload_dict["ssl_unique_fqdn_set.id"] = dbUniqueFQDNSet.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent])

        _log_object_event(
            ctx,
            dbOperationsEvent=dbOperationsEvent,
            event_status_id=models.SslOperationsObjectEventStatus.from_string(
                "unqiue_fqdn__insert"
            ),
            dbUniqueFQDNSet=dbUniqueFQDNSet,
        )

    return dbUniqueFQDNSet, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = (
    "getcreate__SslAcmeAccountKey",
    "getcreate__SslCaCertificate__by_pem_text",
    "getcreate__SslCertificateRequest__by_pem_text",
    "getcreate__SslDomain__by_domainName",
    "getcreate__SslPrivateKey__by_pem_text",
    "getcreate__SslServerCertificate__by_pem_text",
    "getcreate__SslUniqueFQDNSet__by_domainObjects",
)
