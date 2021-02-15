from __future__ import print_function

# stdlib
import datetime

# local
from ...model import objects as model_objects
from ...model import utils as model_utils
from ...lib import letsencrypt_info
from ...lib import utils
from .logger import log__OperationsEvent
from . import create as db_create
from . import get as db_get
from . import getcreate as db_getcreate
from . import update as db_update


# ==============================================================================


acme_account_providers = {
    1: {
        "id": 1,
        "name": "pebble",
        "endpoint": None,
        "directory": "https://0.0.0.0:14000/dir",
        "is_default": None,
        "protocol": "acme-v2",
        "is_enabled": False,
        "server": "0.0.0.0:14000",
    },
    2: {
        "id": 2,
        "name": "letsencrypt-v1",
        "endpoint": "https://acme-v01.api.letsencrypt.org",
        "directory": None,
        "is_default": None,
        "protocol": "acme-v1",
        "is_enabled": False,
        "server": "acme-v01.api.letsencrypt.org",
    },
    3: {
        "id": 3,
        "name": "letsencrypt-v1-staging",
        "endpoint": "https://acme-staging.api.letsencrypt.org",
        "directory": None,
        "is_default": None,
        "protocol": "acme-v1",
        "is_enabled": False,
        "server": "acme-staging.api.letsencrypt.org",
    },
    4: {
        "id": 4,
        "name": "letsencrypt-v2",
        "endpoint": None,
        "directory": "https://acme-v02.api.letsencrypt.org/directory",
        "is_default": None,
        "protocol": "acme-v2",
        "is_enabled": False,
        "server": "acme-v02.api.letsencrypt.org",
    },
    5: {
        "id": 5,
        "name": "letsencrypt-v2-staging",
        "endpoint": None,
        "directory": "https://acme-staging-v02.api.letsencrypt.org/directory",
        "is_default": None,
        "protocol": "acme-v2",
        "is_enabled": False,
        "server": "acme-staging-v02.api.letsencrypt.org",
    },
}


def initialize_AcmeAccountProviders(ctx):

    timestamp_now = datetime.datetime.utcnow()

    for (id, item) in acme_account_providers.items():
        dbObject = model_objects.AcmeAccountProvider()
        dbObject.id = item["id"]
        dbObject.timestamp_created = timestamp_now
        dbObject.name = item["name"]
        dbObject.endpoint = item["endpoint"]
        dbObject.directory = item["directory"]
        dbObject.is_default = item["is_default"]
        dbObject.is_enabled = item["is_enabled"]
        dbObject.protocol = item["protocol"]
        dbObject.server = item["server"]
        ctx.dbSession.add(dbObject)
        ctx.dbSession.flush(
            objects=[
                dbObject,
            ]
        )

    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("_DatabaseInitialization"),
        event_payload_dict,
    )

    dbObject = model_objects.PrivateKey()
    dbObject.id = 0
    dbObject.timestamp_created = timestamp_now
    _placeholder_text = "*placeholder-key*"
    dbObject.key_pem = _placeholder_text
    dbObject.key_pem_md5 = utils.md5_text(_placeholder_text)
    dbObject.spki_sha256 = _placeholder_text
    dbObject.is_active = True
    dbObject.operations_event_id__created = dbOperationsEvent.id
    dbObject.private_key_source_id = model_utils.PrivateKeySource.from_string(
        "placeholder"
    )
    dbObject.private_key_type_id = model_utils.PrivateKeyType.from_string("placeholder")
    # SYSTEM_DEFAULT
    dbObject.key_technology_id = model_utils.KeyTechnology.from_string(
        "RSA"
    )  # default to RSA
    ctx.dbSession.add(dbObject)
    ctx.dbSession.flush(
        objects=[
            dbObject,
        ]
    )
    return True


def initialize_CertificateCAs(ctx):

    # create a bookkeeping object
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("_DatabaseInitialization"),
        event_payload_dict,
    )

    certs = letsencrypt_info.CERT_CAS_DATA
    certs_discovered = []
    certs_modified = []
    certs_lookup = {}  # stash the ones we create for a moment
    for cert_id, cert_data in letsencrypt_info.CERT_CAS_DATA.items():
        _is_created = False
        dbCertificateCA = db_get.get__CertificateCA__by_pem_text(
            ctx, cert_data["cert_pem"]
        )
        if not dbCertificateCA:
            (
                dbCertificateCA,
                _is_created,
            ) = db_getcreate.getcreate__CertificateCA__by_pem_text(
                ctx, cert_data["cert_pem"], display_name=cert_data["display_name"]
            )
            if _is_created:
                certs_discovered.append(dbCertificateCA)
        if "is_trusted_root" in cert_data:
            if dbCertificateCA.is_trusted_root != cert_data["is_trusted_root"]:
                dbCertificateCA.is_trusted_root = cert_data["is_trusted_root"]
                if dbCertificateCA not in certs_discovered:
                    certs_modified.append(dbCertificateCA)
        else:
            attrs = ("display_name",)
            for _k in attrs:
                if getattr(dbCertificateCA, _k) is None:
                    setattr(dbCertificateCA, _k, cert_data[_k])
                    if dbCertificateCA not in certs_discovered:
                        certs_modified.append(dbCertificateCA)
        certs_lookup[cert_id] = dbCertificateCA

    # bookkeeping update
    event_payload_dict["is_certificates_discovered"] = (
        True if certs_discovered else False
    )
    event_payload_dict["is_certificates_updated"] = True if certs_modified else False
    event_payload_dict["ids_discovered"] = [c.id for c in certs_discovered]
    event_payload_dict["ids_modified"] = [c.id for c in certs_modified]

    dbOperationsEvent.set_event_payload(event_payload_dict)
    ctx.dbSession.flush(objects=[dbOperationsEvent])

    # now install the default preference chain
    _now = datetime.datetime.utcnow()
    _buffer = datetime.timedelta(90)
    date_cutoff = _now + _buffer

    slot_id = 1
    for cert_id in letsencrypt_info.DEFAULT_CA_PREFERENCES:
        cert_payload = letsencrypt_info.CERT_CAS_DATA[cert_id]
        cert_enddate = datetime.datetime(*cert_payload[".enddate"])
        if cert_enddate < date_cutoff:
            continue
        if cert_id not in certs_lookup:
            raise ValueError("Certificate `%s` is unknown" % cert_id)
        dbCertificateCA = certs_lookup[cert_id]
        dbPref = db_create.create__CertificateCAPreference(
            ctx, slot_id=slot_id, dbCertificateCA=dbCertificateCA
        )
        slot_id += 1  # increment the slot

    return True


def initialize_DomainBlocklisted(ctx):

    dbDomainBlocklisted = model_objects.DomainBlocklisted()
    dbDomainBlocklisted.domain_name = "always-fail.example.com"
    ctx.dbSession.add(dbDomainBlocklisted)
    ctx.dbSession.flush(
        objects=[
            dbDomainBlocklisted,
        ]
    )
    return True


def startup_AcmeAccountProviders(ctx, app_settings):

    # first handle the Default CertificateAuthority

    dbAcmeAccountProvider = db_get.get__AcmeAccountProvider__by_name(
        ctx, app_settings["certificate_authority"]
    )
    if not dbAcmeAccountProvider:
        print("Attempting to enroll new `AcmeAccountProvider` from config >>>")
        dbAcmeAccountProvider = db_create.create__AcmeAccountProvider(
            ctx,
            name=app_settings["certificate_authority"],
            directory=app_settings["certificate_authority_directory"],
            protocol=app_settings["certificate_authority_protocol"],
        )
        print("<<< Enrolled new `AcmeAccountProvider` from config")

    if (
        dbAcmeAccountProvider.directory
        != app_settings["certificate_authority_directory"]
    ):
        raise ValueError(
            "`dbAcmeAccountProvider.directory` ('%s') does not match `certificate_authority_directory` ('%s')"
            % (
                dbAcmeAccountProvider.directory,
                app_settings["certificate_authority_directory"],
            )
        )

    if dbAcmeAccountProvider.protocol != "acme-v2":
        raise ValueError("`AcmeAccountProvider.protocol` is not `acme-v2`")

    if not dbAcmeAccountProvider.is_default or not dbAcmeAccountProvider.is_enabled:
        _event_status = db_update.update_AcmeAccountProvider__activate_default(
            ctx, dbAcmeAccountProvider
        )

    dbAcmeAccount = db_get.get__AcmeAccount__GlobalDefault(ctx)
    if dbAcmeAccount and not dbAcmeAccount.acme_account_provider.is_default:
        dbAcmeAccount.is_global_default = False
        ctx.dbSession.flush()

    # fun times.
    # now enable any other options
    if app_settings["certificate_authorities_enable"]:
        for ca_name in app_settings["certificate_authorities_enable"]:
            dbAcmeAccountProvider = db_get.get__AcmeAccountProvider__by_name(
                ctx, ca_name
            )
            if not dbAcmeAccountProvider:
                raise ValueError(
                    "could not load the requested CertificateAuthority via `certificate_authorities_enable`: '%s'"
                    % ca_name
                )
            if not dbAcmeAccountProvider.is_enabled:
                _event_status = db_update.update_AcmeAccountProvider__set_is_enabled(
                    ctx, dbAcmeAccountProvider
                )

    return True
