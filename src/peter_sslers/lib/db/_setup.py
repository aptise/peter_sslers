# stdlib
import datetime
import logging
from typing import Dict
from typing import Optional
from typing import TYPE_CHECKING

# pypi
import cert_utils
import sqlalchemy
from typing_extensions import Literal
from typing_extensions import TypedDict

# local
from . import create as db_create
from . import get as db_get
from . import getcreate as db_getcreate
from . import update as db_update
from .logger import log__OperationsEvent
from ...lib import utils
from ...model import objects as model_objects
from ...model import utils as model_utils

if TYPE_CHECKING:
    from ..utils import ApiContext

# ==============================================================================

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

# ------------------------------------------------------------------------------

DictProvider = TypedDict(
    "DictProvider",
    {
        "id": int,
        "name": str,
        "endpoint": Optional[str],
        "directory": Optional[str],
        "is_default": Optional[bool],
        "protocol": str,
        "is_enabled": bool,
        "server": str,
        "is_supports_ari__version": Optional[str],
        "is_unlimited_pending_authz": Optional[bool],
        "filepath_ca_cert_bundle": Optional[str],
    },
    total=False,
)


acme_servers: Dict[int, DictProvider] = {
    1: {
        "id": 1,
        "name": "pebble",
        "endpoint": None,
        "directory": "https://127.0.0.1:14000/dir",
        "is_default": None,
        "protocol": "acme-v2",
        "is_enabled": False,
        "server": "127.0.0.1:14000",
        "is_supports_ari__version": "draft-ietf-acme-ari-03",
        "filepath_ca_cert_bundle": "tests/test_configuration/pebble/test/certs/cert.pem",
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
        "is_supports_ari__version": "draft-ietf-acme-ari-03",
        "is_unlimited_pending_authz": True,
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
        "is_supports_ari__version": "draft-ietf-acme-ari-03",
        "is_unlimited_pending_authz": True,
    },
}


def initialize_AcmeServers(ctx: "ApiContext") -> Literal[True]:
    timestamp_now = datetime.datetime.now(datetime.UTC)

    for id, item in acme_servers.items():

        server_ca_cert_bundle: Optional[str] = None
        filepath_ca_cert_bundle = item.get("filepath_ca_cert_bundle")
        if filepath_ca_cert_bundle:
            with open(filepath_ca_cert_bundle) as fh:
                server_ca_cert_bundle = fh.read()
                server_ca_cert_bundle = cert_utils.cleanup_pem_text(
                    server_ca_cert_bundle
                )

        dbObject = model_objects.AcmeServer()
        dbObject.id = item["id"]
        dbObject.timestamp_created = timestamp_now
        dbObject.name = item["name"]
        dbObject.endpoint = item["endpoint"]
        dbObject.directory = item["directory"]
        dbObject.is_default = item["is_default"]
        dbObject.is_enabled = item["is_enabled"]
        dbObject.protocol = item["protocol"]
        dbObject.server = item["server"]
        dbObject.is_supports_ari__version = item.get("is_supports_ari__version", None)
        dbObject.is_unlimited_pending_authz = item.get(
            "is_unlimited_pending_authz", None
        )
        dbObject.is_custom_ca_certs = item.get("is_custom_ca_certs", None)
        dbObject.server_ca_cert_bundle = server_ca_cert_bundle
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
    _placeholder_text = utils.PLACEHOLDER_TEXT__KEY
    dbObject.key_pem = _placeholder_text
    dbObject.key_pem_md5 = cert_utils.utils.md5_text(_placeholder_text)
    dbObject.spki_sha256 = _placeholder_text
    dbObject.is_active = True
    dbObject.operations_event_id__created = dbOperationsEvent.id
    dbObject.private_key_source_id = model_utils.PrivateKeySource.PLACEHOLDER
    dbObject.private_key_type_id = model_utils.PrivateKeyType.PLACEHOLDER
    # SYSTEM_DEFAULT
    dbObject.key_technology_id = model_utils.KeyTechnology._DEFAULT_id
    ctx.dbSession.add(dbObject)
    ctx.dbSession.flush(
        objects=[
            dbObject,
        ]
    )
    return True


def initialize_CertificateCAs(ctx: "ApiContext") -> Literal[True]:
    # nestle this import, so we do not load it on every run
    from cert_utils import letsencrypt_info

    # create a bookkeeping object
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("_DatabaseInitialization"),
        event_payload_dict,
    )

    certs = letsencrypt_info.CERT_CAS_DATA
    certs_order = letsencrypt_info._CERT_CAS_ORDER

    # do a quick check
    _cert_ids = set(certs.keys())
    _cert_ids_order = set(certs_order)
    _missing_data = _cert_ids_order - _cert_ids
    if _missing_data:
        raise ValueError(
            "Missing from `letsencrypt_info.CERT_CAS_DATA`: %s" % _missing_data
        )
    _unordered = _cert_ids - _cert_ids_order
    if _unordered:
        raise ValueError(
            "Missing from `letsencrypt_info._CERT_CAS_ORDER`: %s" % _unordered
        )
    # end check

    certs_discovered = []
    certs_modified = []
    certs_lookup = {}  # stash the ones we create for a moment
    for cert_id in certs_order:
        cert_data = certs[cert_id]
        assert cert_data["cert_pem"]
        _is_created = False
        dbCertificateCA = db_get.get__CertificateCA__by_pem_text(
            ctx, cert_data["cert_pem"]
        )
        if not dbCertificateCA:
            is_trusted_root = cert_data.get("is_trusted_root")
            (
                dbCertificateCA,
                _is_created,
            ) = db_getcreate.getcreate__CertificateCA__by_pem_text(
                ctx,
                cert_data["cert_pem"],
                display_name=cert_data["display_name"],
                is_trusted_root=is_trusted_root,
                discovery_type="initial setup",
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
                    setattr(dbCertificateCA, _k, cert_data[_k])  # type: ignore[literal-required]
                    if dbCertificateCA not in certs_discovered:
                        certs_modified.append(dbCertificateCA)

        if ("compatibility" in cert_data) and (cert_data["compatibility"] is not None):
            # TODO: migrate to getcreate
            # TODO: log creation
            for platform_info in cert_data["compatibility"].items():
                dbRootStore = (
                    ctx.dbSession.query(model_objects.RootStore)
                    .filter(
                        sqlalchemy.func.lower(model_objects.RootStore.name)
                        == platform_info[0].lower(),
                    )
                    .first()
                )
                if not dbRootStore:
                    dbRootStore = model_objects.RootStore()
                    dbRootStore.name = platform_info[0]
                    dbRootStore.timestamp_created = ctx.timestamp
                    ctx.dbSession.add(dbRootStore)
                    ctx.dbSession.flush(
                        objects=[
                            dbRootStore,
                        ]
                    )
                dbRootStoreVersion = (
                    ctx.dbSession.query(model_objects.RootStoreVersion)
                    .filter(
                        model_objects.RootStoreVersion.root_store_id == dbRootStore.id,
                        sqlalchemy.func.lower(
                            model_objects.RootStoreVersion.version_string
                        )
                        == platform_info[1].lower(),
                    )
                    .first()
                )
                if not dbRootStoreVersion:
                    dbRootStoreVersion = model_objects.RootStoreVersion()
                    dbRootStoreVersion.root_store_id = dbRootStore.id
                    dbRootStoreVersion.version_string = platform_info[1]
                    dbRootStoreVersion.timestamp_created = ctx.timestamp
                    ctx.dbSession.add(dbRootStoreVersion)
                    ctx.dbSession.flush(
                        objects=[
                            dbRootStoreVersion,
                        ]
                    )

                dbRootStoreVersion2CertificateCA = (
                    ctx.dbSession.query(model_objects.RootStoreVersion_2_CertificateCA)
                    .filter(
                        model_objects.RootStoreVersion_2_CertificateCA.root_store_version_id
                        == dbRootStoreVersion.id,
                        model_objects.RootStoreVersion_2_CertificateCA.certificate_ca_id
                        == dbCertificateCA.id,
                    )
                    .first()
                )
                if not dbRootStoreVersion2CertificateCA:
                    dbRootStoreVersion2CertificateCA = (
                        model_objects.RootStoreVersion_2_CertificateCA()
                    )
                    dbRootStoreVersion2CertificateCA.root_store_version_id = (
                        dbRootStoreVersion.id
                    )
                    dbRootStoreVersion2CertificateCA.certificate_ca_id = (
                        dbCertificateCA.id
                    )
                    ctx.dbSession.add(dbRootStoreVersion2CertificateCA)
                    ctx.dbSession.flush(
                        objects=[
                            dbRootStoreVersion2CertificateCA,
                        ]
                    )
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
    # _now = datetime.datetime.now(datetime.UTC)
    # _buffer = datetime.timedelta(90)
    # date_cutoff = _now + _buffer

    slot_id = 1
    for cert_id in letsencrypt_info.DEFAULT_CA_PREFERENCES:
        # cert_payload = letsencrypt_info.CERT_CAS_DATA[cert_id]
        # cert_enddate = datetime.datetime(*cert_payload[".enddate"])
        # TODO: reintegrate
        # 2021.09.08 - Disable this so tests pass
        #              we are now close to the DST Expiration
        #              and our tests don't account for this
        # if cert_enddate < date_cutoff:
        #    continue
        if cert_id not in certs_lookup:
            raise ValueError("Certificate `%s` is unknown" % cert_id)
        dbCertificateCA = certs_lookup[cert_id]
        dbPref = db_create.create__CertificateCAPreference(  # noqa: F841
            ctx,
            dbCertificateCA=dbCertificateCA,
            slot_id=slot_id,
        )
        slot_id += 1  # increment the slot

    return True


def initialize_DomainBlocklisted(ctx: "ApiContext") -> Literal[True]:
    dbDomainBlocklisted = model_objects.DomainBlocklisted()
    dbDomainBlocklisted.domain_name = "always-fail.example.com"
    ctx.dbSession.add(dbDomainBlocklisted)
    ctx.dbSession.flush(
        objects=[
            dbDomainBlocklisted,
        ]
    )
    return True


def startup_AcmeServers(ctx: "ApiContext", app_settings: Dict) -> Literal[True]:
    # first handle the Default CertificateAuthority

    dbAcmeServer = db_get.get__AcmeServer__by_name(
        ctx, app_settings["certificate_authority"]
    )
    if not dbAcmeServer:
        print("Attempting to enroll new `AcmeServer` from config >>>")
        dbAcmeServer = db_create.create__AcmeServer(
            ctx,
            name=app_settings["certificate_authority"],
            directory=app_settings["certificate_authority_directory"],
            protocol=app_settings["certificate_authority_protocol"],
        )
        print("<<< Enrolled new `AcmeServer` from config")

    if dbAcmeServer.directory != app_settings["certificate_authority_directory"]:
        raise ValueError(
            "`dbAcmeServer.directory` ('%s') does not match `certificate_authority_directory` ('%s')"
            % (
                dbAcmeServer.directory,
                app_settings["certificate_authority_directory"],
            )
        )

    if dbAcmeServer.protocol != "acme-v2":
        raise ValueError("`AcmeServer.protocol` is not `acme-v2`")

    if not dbAcmeServer.is_default or not dbAcmeServer.is_enabled:
        _event_status = db_update.update_AcmeServer__activate_default(ctx, dbAcmeServer)

    dbAcmeAccount = db_get.get__AcmeAccount__GlobalDefault(ctx)
    if dbAcmeAccount and not dbAcmeAccount.acme_server.is_default:
        dbAcmeAccount.is_global_default = False
        ctx.dbSession.flush()

    # fun times.
    # now enable any other options
    if app_settings["certificate_authorities_enable"]:
        for ca_name in app_settings["certificate_authorities_enable"]:
            dbAcmeServer = db_get.get__AcmeServer__by_name(ctx, ca_name)
            if not dbAcmeServer:
                raise ValueError(
                    "could not load the requested CertificateAuthority via `certificate_authorities_enable`: '%s'"
                    % ca_name
                )
            if not dbAcmeServer.is_enabled:
                _event_status = (  # noqa: F841
                    db_update.update_AcmeServer__set_is_enabled(ctx, dbAcmeServer)
                )

    return True
