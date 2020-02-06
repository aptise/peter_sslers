# logging
import logging

log = logging.getLogger(__name__)

# stdlib
import json
import pdb

# pypi
from dateutil import parser as dateutil_parser

# localapp
from .. import utils
from ... import lib
from .. import cert_utils
from .. import utils
from ...model import utils as model_utils
from ...model import objects as model_objects

# local
from .get import get__AcmeAuthorization__by_authorization_url
from .get import get__AcmeChallenge__by_challenge_url
from .get import get__CaCertificate__by_pem_text
from .get import get__CertificateRequest__by_pem_text
from .get import get__Domain__by_name
from .logger import log__OperationsEvent
from .logger import _log_object_event
from .helpers import _certificate_parse_to_record


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__AcmeAccountKey(
    ctx,
    key_pem=None,
    le_meta_jsons=None,
    le_pkey_jsons=None,
    le_reg_jsons=None,
    acme_account_provider_id=None,
):
    """
    Gets or Creates AccountKeys for LetsEncrypts' ACME server

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param key_pem: (optional) an account key in PEM format.
        if not provided, all of the following must be supplied:
        * le_meta_jsons
        * le_pkey_jsons
        * le_reg_jsons
    :param le_meta_jsons: (optional) data from certbot account key format
        if not provided, `key_pem` must be supplied
    :param le_pkey_jsons: (optional) data from certbot account key format
        if not provided, `key_pem` must be supplied
    :param le_reg_jsons: (optional) data from certbot account key format
        if not provided, `key_pem` must be supplied
    :param acme_account_provider_id: (optional) id corresponding to a :class:`model.utils.AcmeAccountProvider` server
    """
    is_created = False
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
        dbAcmeAccountKey = (
            ctx.dbSession.query(model_objects.AcmeAccountKey)
            .filter(
                model_objects.AcmeAccountKey.key_pem_md5 == key_pem_md5,
                model_objects.AcmeAccountKey.key_pem == key_pem,
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

            finally:
                _tmpfile.close()

            event_payload_dict = utils.new_event_payload_dict()
            dbOperationsEvent = log__OperationsEvent(
                ctx,
                model_utils.OperationsEventType.from_string("acme_account_key__insert"),
            )

            dbAcmeAccountKey = model_objects.AcmeAccountKey()
            dbAcmeAccountKey.timestamp_first_seen = ctx.timestamp
            dbAcmeAccountKey.key_pem = key_pem
            dbAcmeAccountKey.key_pem_md5 = key_pem_md5
            dbAcmeAccountKey.key_pem_modulus_md5 = key_pem_modulus_md5
            dbAcmeAccountKey.operations_event_id__created = dbOperationsEvent.id
            dbAcmeAccountKey.acme_account_provider_id = acme_account_provider_id
            ctx.dbSession.add(dbAcmeAccountKey)
            ctx.dbSession.flush(objects=[dbAcmeAccountKey])
            is_created = True

            event_payload_dict["acme_account_key.id"] = dbAcmeAccountKey.id
            dbOperationsEvent.set_event_payload(event_payload_dict)
            ctx.dbSession.flush(objects=[dbOperationsEvent])

            _log_object_event(
                ctx,
                dbOperationsEvent=dbOperationsEvent,
                event_status_id=model_utils.OperationsObjectEventStatus.from_string(
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
            for acme_provider in model_utils.AcmeAccountProvider.registry.values():
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
        dbAcmeAccountKey = (
            ctx.dbSession.query(model_objects.AcmeAccountKey)
            .filter(
                model_objects.AcmeAccountKey.key_pem_md5 == key_pem_md5,
                model_objects.AcmeAccountKey.key_pem == key_pem,
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
            dbOperationsEvent = log__OperationsEvent(
                ctx,
                model_utils.OperationsEventType.from_string("acme_account_key__insert"),
            )

            dbAcmeAccountKey = model_objects.AcmeAccountKey()
            dbAcmeAccountKey.timestamp_first_seen = ctx.timestamp
            dbAcmeAccountKey.key_pem = key_pem
            dbAcmeAccountKey.key_pem_md5 = key_pem_md5
            dbAcmeAccountKey.key_pem_modulus_md5 = key_pem_modulus_md5
            dbAcmeAccountKey.operations_event_id__created = dbOperationsEvent.id
            dbAcmeAccountKey.acme_account_provider_id = acme_account_provider_id
            dbAcmeAccountKey.letsencrypt_data = letsencrypt_data

            ctx.dbSession.add(dbAcmeAccountKey)
            ctx.dbSession.flush(objects=[dbAcmeAccountKey])
            is_created = True

            event_payload_dict["acme_account_key.id"] = dbAcmeAccountKey.id
            dbOperationsEvent.set_event_payload(event_payload_dict)
            ctx.dbSession.flush(objects=[dbOperationsEvent])

            _log_object_event(
                ctx,
                dbOperationsEvent=dbOperationsEvent,
                event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                    "acme_account_key__insert"
                ),
                dbAcmeAccountKey=dbAcmeAccountKey,
            )

    return dbAcmeAccountKey, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__AcmeAuthorization(
    ctx, authorization_url, authorization_payload, authenticatedUser=None
):
    """
    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param authorization_url: (required) the url of an RFC-8555 authorization
    :param authorization_payload: (required) an RFC-8555 authorization payload
    :param authenticatedUser: (optional) an object which contains a `accountkey_thumbprint` attribute

    https://tools.ietf.org/html/rfc8555#section-7.1.4
    Authorization Payload Contents:
        identifier (required, object):  The identifier that the account is authorized to represent.
              type (required, string):  The type of identifier (see below and Section 9.7.7).
              value (required, string):  The identifier itself.
       expires (optional, string):  The timestamp after which the server will consider this authorization invalid, encoded in the format specified in [RFC3339].  This field is REQUIRED for objects with "valid" in the "status" field.
        status (required, string):  
        challenges (required, array of objects):
        wildcard (optional, boolean)
    """
    is_created = False
    dbAuthorization = get__AcmeAuthorization__by_authorization_url(
        ctx, authorization_url
    )
    if not dbAuthorization:
        timestamp_expires = authorization_payload.get("expires")
        if timestamp_expires:
            timestamp_expires = dateutil_parser.parse(timestamp_expires)
        identifer = authorization_payload["identifier"]
        if identifer["type"] != "dns":
            raise ValueError("unexpected authorization payload: identifier type")
        domain_name = identifer["value"]

        dbDomain = get__Domain__by_name(ctx, domain_name, preload=False)
        if not dbDomain:
            raise ValueError(
                "this domain name has not been seen before. this should not be possible."
            )

        authorization_status = authorization_payload["status"]
        #
        dbAuthorization = model_objects.AcmeAuthorization()
        dbAuthorization.authorization_url = authorization_url
        dbAuthorization.timestamp_created = ctx.timestamp
        dbAuthorization.domain_id = dbDomain.id
        dbAuthorization.timestamp_expires = timestamp_expires
        dbAuthorization.status = authorization_status
        dbAuthorization.timestamp_updated = ctx.timestamp
        ctx.dbSession.add(dbAuthorization)
        ctx.dbSession.flush(objects=[dbAuthorization])
        is_created = True

    # should we handle the challenge here too?

    # parse the payload for our http01 challenge
    acme_challenge = lib.acme_v2.get_authorization_challenge(
        authorization_payload, http01=True
    )
    challenge_url = acme_challenge["url"]
    challenge_status = acme_challenge["status"]
    dbChallenge = get__AcmeChallenge__by_challenge_url(ctx, challenge_url)
    is_created_challenge = False
    if not dbChallenge:
        challenge_token = acme_challenge["token"]
        dbChallenge = model_objects.AcmeChallenge()
        dbChallenge.acme_authorization_id = dbAuthorization.id
        dbChallenge.challenge_url = challenge_url
        dbChallenge.timestamp_created = ctx.timestamp
        dbChallenge.acme_challenge_type_id = model_utils.AcmeChallengeType.from_string(
            "http-01"
        )
        dbChallenge.status = challenge_status
        dbChallenge.token = challenge_token
        dbChallenge.timestamp_updated = ctx.timestamp
        if authenticatedUser:
            dbChallenge.keyauthorization = lib.acme_v2.create_challenge_keyauthorization(
                challenge_token, authenticatedUser.accountkey_thumbprint
            )

        ctx.dbSession.add(dbChallenge)
        ctx.dbSession.flush(objects=[dbChallenge])
        is_created_challenge = True
    else:
        if dbChallenge.status != challenge_status:
            dbChallenge.status = challenge_status
            dbChallenge.timestamp_updated = ctx.timestamp
            ctx.dbSession.add(dbChallenge)
            ctx.dbSession.flush(objects=[dbChallenge])

    return dbAuthorization, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__CaCertificate__by_pem_text(
    ctx,
    cert_pem,
    chain_name,
    le_authority_name=None,
    is_authority_certificate=None,
    is_cross_signed_authority_certificate=None,
):
    """
    Gets or Creates CaCertificates

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param cert_pem: 
    :param chain_name:
    :param le_authority_name:
    :param is_authority_certificate:
    :param is_cross_signed_authority_certificate:
    """
    is_created = False
    dbCACertificate = get__CaCertificate__by_pem_text(ctx, cert_pem)
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
            dbOperationsEvent = log__OperationsEvent(
                ctx,
                model_utils.OperationsEventType.from_string("ca_certificate__insert"),
            )

            dbCACertificate = model_objects.CaCertificate()
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
            dbCACertificate.operations_event_id__created = dbOperationsEvent.id

            ctx.dbSession.add(dbCACertificate)
            ctx.dbSession.flush(objects=[dbCACertificate])
            is_created = True

            event_payload_dict["ca_certificate.id"] = dbCACertificate.id
            dbOperationsEvent.set_event_payload(event_payload_dict)
            ctx.dbSession.flush(objects=[dbOperationsEvent])

            _log_object_event(
                ctx,
                dbOperationsEvent=dbOperationsEvent,
                event_status_id=model_utils.OperationsObjectEventStatus.from_string(
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


def getcreate__CertificateRequest__by_pem_text(
    ctx,
    csr_pem,
    certificate_request_source_id=None,
    dbAcmeAccountKey=None,
    dbPrivateKey=None,
    dbServerCertificate__issued=None,
    dbServerCertificate__renewal_of=None,
):
    """
    getcreate for a CSR

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param csr_pem: 
    :param certificate_request_source_id:
    :param dbAcmeAccountKey: (required) The :class:`model.objects.AcmeAccountKey` that owns the certificate
    :param dbPrivateKey: (required) The :class:`model.objects.PrivateKey` that signed the certificate
    :param dbServerCertificate__issued: (required) The :class:`model.objects.ServerCertificate` this issued as
    :param dbServerCertificate__renewal_of: (required) The :class:`model.objects.ServerCertificate` this renews

    log__OperationsEvent takes place in `create__CertificateRequest`
    """
    is_created = False
    dbCertificateRequest = get__CertificateRequest__by_pem_text(ctx, csr_pem)
    if not dbCertificateRequest:
        dbCertificateRequest = lib.db.create.create__CertificateRequest(
            ctx,
            csr_pem,
            certificate_request_source_id=certificate_request_source_id,
            dbPrivateKey=dbPrivateKey,
            dbServerCertificate__issued=dbServerCertificate__issued,
            dbServerCertificate__renewal_of=dbServerCertificate__renewal_of,
        )
        is_created = True

    return dbCertificateRequest, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__Domain__by_domainName(ctx, domain_name, is_from_queue_domain=None):
    """
    getcreate wrapping a domain

    return dbDomain, is_created

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param domain_name: 
    :param is_from_queue_domain:
    """
    is_created = False
    dbDomain = get__Domain__by_name(ctx, domain_name, preload=False)
    if not dbDomain:
        event_payload_dict = utils.new_event_payload_dict()
        dbOperationsEvent = log__OperationsEvent(
            ctx, model_utils.OperationsEventType.from_string("domain__insert")
        )
        dbDomain = model_objects.Domain()
        dbDomain.domain_name = domain_name
        dbDomain.timestamp_first_seen = ctx.timestamp
        dbDomain.is_from_queue_domain = is_from_queue_domain
        dbDomain.operations_event_id__created = dbOperationsEvent.id
        ctx.dbSession.add(dbDomain)
        ctx.dbSession.flush(objects=[dbDomain])
        is_created = True

        event_payload_dict["domain.id"] = dbDomain.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent])

        _log_object_event(
            ctx,
            dbOperationsEvent=dbOperationsEvent,
            event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                "domain__insert"
            ),
            dbDomain=dbDomain,
        )

    return dbDomain, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__PrivateKey__by_pem_text(ctx, key_pem, is_autogenerated_key=None):
    """
    getcreate wrapping private keys

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param key_pem: 
    :param is_autogenerated_key:
    """
    is_created = False
    key_pem = cert_utils.cleanup_pem_text(key_pem)
    key_pem_md5 = utils.md5_text(key_pem)
    dbPrivateKey = (
        ctx.dbSession.query(model_objects.PrivateKey)
        .filter(
            model_objects.PrivateKey.key_pem_md5 == key_pem_md5,
            model_objects.PrivateKey.key_pem == key_pem,
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
        _event_type_id = model_utils.OperationsEventType.from_string(
            "private_key__insert"
        )
        if is_autogenerated_key:
            _event_type_id = model_utils.OperationsEventType.from_string(
                "private_key__insert_autogenerated"
            )
        dbOperationsEvent = log__OperationsEvent(ctx, _event_type_id)

        dbPrivateKey = model_objects.PrivateKey()
        dbPrivateKey.timestamp_first_seen = ctx.timestamp
        dbPrivateKey.key_pem = key_pem
        dbPrivateKey.key_pem_md5 = key_pem_md5
        dbPrivateKey.key_pem_modulus_md5 = key_pem_modulus_md5
        dbPrivateKey.is_autogenerated_key = is_autogenerated_key
        dbPrivateKey.operations_event_id__created = dbOperationsEvent.id
        ctx.dbSession.add(dbPrivateKey)
        ctx.dbSession.flush(objects=[dbPrivateKey])
        is_created = True

        event_payload_dict["private_key.id"] = dbPrivateKey.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent])

        _log_object_event(
            ctx,
            dbOperationsEvent=dbOperationsEvent,
            event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                "private_key__insert"
            ),
            dbPrivateKey=dbPrivateKey,
        )

    return dbPrivateKey, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def getcreate__ServerCertificate__by_pem_text(
    ctx,
    cert_pem,
    dbCACertificate=None,
    dbAcmeAccountKey=None,
    dbPrivateKey=None,
    dbServerCertificate__renewal_of=None,
):
    """
    getcreate wrapping issued certs

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param cert_pem: 
    :param dbCACertificate: (required) The upstream :class:`model.objects.CaCertificate` that signed the certificate
    :param dbAcmeAccountKey: (required) The :class:`model.objects.PrivateKey` that owns the certificate
    :param dbPrivateKey: (required) The :class:`model.objects.PrivateKey` that signed the certificate
    :param dbServerCertificate__renewal_of: (required) The :class:`model.objects.ServerCertificate` this renews
    """
    is_created = False
    cert_pem = cert_utils.cleanup_pem_text(cert_pem)
    cert_pem_md5 = utils.md5_text(cert_pem)
    dbServerCertificate = (
        ctx.dbSession.query(model_objects.ServerCertificate)
        .filter(
            model_objects.ServerCertificate.cert_pem_md5 == cert_pem_md5,
            model_objects.ServerCertificate.cert_pem == cert_pem,
        )
        .first()
    )
    if dbServerCertificate:
        if dbPrivateKey and (
            dbServerCertificate.private_key_id__signed_by != dbPrivateKey.id
        ):
            if dbServerCertificate.private_key_id__signed_by:
                raise ValueError("Integrity Error. Competing PrivateKey (!?)")
            elif dbServerCertificate.private_key_id__signed_by is None:
                dbServerCertificate.private_key_id__signed_by = dbPrivateKey.id
                dbPrivateKey.count_certificates_issued += 1
                if not dbPrivateKey.timestamp_last_certificate_issue or (
                    dbPrivateKey.timestamp_last_certificate_issue
                    < dbServerCertificate.timestamp_signed
                ):
                    dbPrivateKey.timestamp_last_certificate_issue = (
                        dbServerCertificate.timestamp_signed
                    )
                ctx.dbSession.flush(objects=[dbServerCertificate, dbPrivateKey])
        if dbAcmeAccountKey and (
            dbServerCertificate.acme_account_key_id != dbAcmeAccountKey.id
        ):
            if dbServerCertificate.acme_account_key_id:
                raise ValueError("Integrity Error. Competing AccountKey (!?)")
            elif dbServerCertificate.acme_account_key_id is None:
                dbServerCertificate.acme_account_key_id = dbAcmeAccountKey.id
                dbAcmeAccountKey.count_certificates_issued += 1
                if not dbAcmeAccountKey.timestamp_last_certificate_issue or (
                    dbAcmeAccountKey.timestamp_last_certificate_issue
                    < dbServerCertificate.timestamp_signed
                ):
                    dbAcmeAccountKey.timestamp_last_certificate_issue = (
                        dbAcmeAccountKey.timestamp_signed
                    )
                ctx.dbSession.flush(objects=[dbServerCertificate, dbAcmeAccountKey])
    elif not dbServerCertificate:
        _tmpfileCert = None
        try:
            _tmpfileCert = cert_utils.new_pem_tempfile(cert_pem)

            # validate
            cert_utils.validate_cert__pem_filepath(_tmpfileCert.name)

            # bookkeeping
            event_payload_dict = utils.new_event_payload_dict()
            dbOperationsEvent = log__OperationsEvent(
                ctx, model_utils.OperationsEventType.from_string("certificate__insert"),
            )

            dbServerCertificate = model_objects.ServerCertificate()
            _certificate_parse_to_record(_tmpfileCert, dbServerCertificate)

            dbServerCertificate.is_active = True
            dbServerCertificate.cert_pem = cert_pem
            dbServerCertificate.cert_pem_md5 = cert_pem_md5

            if dbServerCertificate__renewal_of:
                dbServerCertificate.server_certificate_id__renewal_of = (
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
            dbServerCertificate.ca_certificate_id__upchain = dbCACertificate.id

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
            dbServerCertificate.private_key_id__signed_by = dbPrivateKey.id
            dbPrivateKey.count_certificates_issued += 1
            if not dbPrivateKey.timestamp_last_certificate_issue or (
                dbPrivateKey.timestamp_last_certificate_issue
                < dbServerCertificate.timestamp_signed
            ):
                dbPrivateKey.timestamp_last_certificate_issue = (
                    dbServerCertificate.timestamp_signed
                )

            # did we submit an account key?
            if dbAcmeAccountKey:
                dbServerCertificate.acme_account_key_id = dbAcmeAccountKey.id
                dbAcmeAccountKey.count_certificates_issued += 1
                if not dbAcmeAccountKey.timestamp_last_certificate_issue or (
                    dbAcmeAccountKey.timestamp_last_certificate_issue
                    < dbAcmeAccountKey.timestamp_signed
                ):
                    dbAcmeAccountKey.timestamp_last_certificate_issue = (
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
            # getcreate__Domain__by_domainName returns a tuple of (domainObject, is_created)
            dbDomainObjects = [
                getcreate__Domain__by_domainName(ctx, _domain_name)[0]
                for _domain_name in certificate_domain_names
            ]
            (
                dbUniqueFqdnSet,
                is_created_fqdn,
            ) = getcreate__UniqueFQDNSet__by_domainObjects(ctx, dbDomainObjects)
            dbServerCertificate.unique_fqdn_set_id = dbUniqueFqdnSet.id

            if len(certificate_domain_names) == 1:
                dbServerCertificate.is_single_domain_cert = True
            elif len(certificate_domain_names) > 1:
                dbServerCertificate.is_single_domain_cert = False

            dbServerCertificate.operations_event_id__created = dbOperationsEvent.id
            ctx.dbSession.add(dbServerCertificate)
            ctx.dbSession.flush(objects=[dbServerCertificate])
            is_created = True

            event_payload_dict["server_certificate.id"] = dbServerCertificate.id
            dbOperationsEvent.set_event_payload(event_payload_dict)
            ctx.dbSession.flush(objects=[dbOperationsEvent])

            _log_object_event(
                ctx,
                dbOperationsEvent=dbOperationsEvent,
                event_status_id=model_utils.OperationsObjectEventStatus.from_string(
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


def getcreate__UniqueFQDNSet__by_domainObjects(ctx, domainObjects):
    """
    getcreate wrapping unique fqdn

    :param ctx: (required) A :class:`lib.utils.ApiContext` object
    :param domainObjects: 
    """
    is_created = False

    domain_ids = [dbDomain.id for dbDomain in domainObjects]
    domain_ids.sort()
    domain_ids_string = ",".join([str(id_) for id_ in domain_ids])

    dbUniqueFQDNSet = (
        ctx.dbSession.query(model_objects.UniqueFQDNSet)
        .filter(model_objects.UniqueFQDNSet.domain_ids_string == domain_ids_string)
        .first()
    )

    if not dbUniqueFQDNSet:
        event_payload_dict = utils.new_event_payload_dict()
        dbOperationsEvent = log__OperationsEvent(
            ctx, model_utils.OperationsEventType.from_string("unqiue_fqdn__insert")
        )

        dbUniqueFQDNSet = model_objects.UniqueFQDNSet()
        dbUniqueFQDNSet.domain_ids_string = domain_ids_string
        dbUniqueFQDNSet.timestamp_first_seen = ctx.timestamp
        dbUniqueFQDNSet.operations_event_id__created = dbOperationsEvent.id
        ctx.dbSession.add(dbUniqueFQDNSet)
        ctx.dbSession.flush(objects=[dbUniqueFQDNSet])

        for dbDomain in domainObjects:
            dbAssoc = model_objects.UniqueFQDNSet2Domain()
            dbAssoc.unique_fqdn_set_id = dbUniqueFQDNSet.id
            dbAssoc.domain_id = dbDomain.id
            ctx.dbSession.add(dbAssoc)
            ctx.dbSession.flush(objects=[dbAssoc])
        is_created = True

        event_payload_dict["unique_fqdn_set.id"] = dbUniqueFQDNSet.id
        dbOperationsEvent.set_event_payload(event_payload_dict)
        ctx.dbSession.flush(objects=[dbOperationsEvent])

        _log_object_event(
            ctx,
            dbOperationsEvent=dbOperationsEvent,
            event_status_id=model_utils.OperationsObjectEventStatus.from_string(
                "unqiue_fqdn__insert"
            ),
            dbUniqueFQDNSet=dbUniqueFQDNSet,
        )

    return dbUniqueFQDNSet, is_created


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = (
    "getcreate__AcmeAccountKey",
    "getcreate__CaCertificate__by_pem_text",
    "getcreate__CertificateRequest__by_pem_text",
    "getcreate__Domain__by_domainName",
    "getcreate__PrivateKey__by_pem_text",
    "getcreate__ServerCertificate__by_pem_text",
    "getcreate__UniqueFQDNSet__by_domainObjects",
)
