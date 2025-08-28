# stdlib
import logging
from typing import Dict
from typing import List
from typing import TYPE_CHECKING

# pypi
import cert_utils
import sqlalchemy
from typing_extensions import Literal

# local
from . import actions as db_actions
from . import create as db_create
from . import get as db_get
from . import getcreate as db_getcreate
from .logger import log__OperationsEvent
from ...lib import utils
from ...model import objects as model_objects
from ...model import utils as model_utils

if TYPE_CHECKING:
    from ..context import ApiContext

# ==============================================================================

log = logging.getLogger("peter_sslers.lib.db")

# ------------------------------------------------------------------------------

acme_servers: List[model_utils.AcmeServerInput] = [
    {
        "name": "pebble",
        "directory_url": "https://127.0.0.1:14000/dir",
        "protocol": "acme-v2",
        "is_supports_ari__version": "draft-ietf-acme-ari-03",
        "filepath_ca_cert_bundle": "tests/test_configuration/pebble/test/certs/pebble.minica.pem",
        "is_retry_challenges": False,
    },
    {
        "name": "pebble-alt",
        "directory_url": "https://127.0.0.1:14001/dir",
        "protocol": "acme-v2",
        "is_supports_ari__version": "draft-ietf-acme-ari-03",
        "filepath_ca_cert_bundle": "tests/test_configuration/pebble/test-alt/certs/pebble.minica.pem",
        "is_retry_challenges": False,
    },
    {
        "name": "letsencrypt-v2",
        "directory_url": "https://acme-v02.api.letsencrypt.org/directory",
        "protocol": "acme-v2",
        "is_supports_ari__version": "draft-ietf-acme-ari-03",
        "is_unlimited_pending_authz": True,
        "is_retry_challenges": False,
    },
    {
        "name": "letsencrypt-v2-staging",
        "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
        "protocol": "acme-v2",
        "is_supports_ari__version": "draft-ietf-acme-ari-03",
        "is_unlimited_pending_authz": True,
        "is_retry_challenges": False,
    },
    {
        "name": "buypass",
        "directory_url": "https://api.buypass.com/acme/directory",
        "protocol": "acme-v2",
        "is_supports_ari__version": "unknown",
        "is_unlimited_pending_authz": False,
        "is_retry_challenges": True,
    },
    {
        "name": "buypass-testing",
        "directory_url": "https://api.test4.buypass.no/acme/directory",
        "protocol": "acme-v2",
        "is_supports_ari__version": "unknown",
        "is_unlimited_pending_authz": False,
        "is_retry_challenges": True,
    },
]


def initialize_database(ctx: "ApiContext") -> Literal[True]:

    # !!!: Create an Event
    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = log__OperationsEvent(
        ctx,
        model_utils.OperationsEventType.from_string("_DatabaseInitialization"),
        event_payload_dict,
    )

    # !!!: AcmeServers
    db_actions.register_acme_servers(ctx, acme_servers, "initial")

    # !!!: Placeholders

    # Run the PrivateKey placeholder as well
    dbObject = model_objects.PrivateKey()
    dbObject.id = 0
    dbObject.timestamp_created = ctx.timestamp
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

    # !!!: CertificateAuthorities

    # nestle this import, so we do not load it on every run
    from cert_utils import letsencrypt_info

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
    # _now = datetime.datetime.now(datetime.timezone.utc)
    # _buffer = datetime.timedelta(90)
    # date_cutoff = _now + _buffer

    dbX509CertificateTrustPreferencePolicy = (
        db_create.create__X509CertificateTrustPreferencePolicy(ctx, "global")
    )

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
        dbPref = db_create.create__X509CertificatePreferencePolicyItem(  # noqa: F841
            ctx,
            dbX509CertificateTrustPreferencePolicy=dbX509CertificateTrustPreferencePolicy,
            dbCertificateCA=dbCertificateCA,
        )

    # !!!: DomainBlocklisted
    dbDomainBlocklisted = (  # noqa: F841
        db_getcreate.getcreate__DomainBlocklisted__by_domainName(
            ctx, "always-fail.example.com"
        )
    )

    # !!!: SystemConfigurations
    for _name in (
        "global",
        "autocert",
        "certificate-if-needed",
    ):
        if not utils.validate_websafe_slug(_name):
            raise ValueError("invalid name")
        _name = utils.normalize_unique_text(_name)
        dbSystemConfiguration = model_objects.SystemConfiguration()
        dbSystemConfiguration.name = _name
        dbSystemConfiguration.is_configured = False
        dbSystemConfiguration.acme_account_id__primary = 0
        dbSystemConfiguration.acme_account_id__backup = 0
        dbSystemConfiguration.private_key_technology_id__primary = (
            model_utils.KeyTechnology.ACCOUNT_DEFAULT
        )
        dbSystemConfiguration.private_key_technology_id__backup = (
            model_utils.KeyTechnology.ACCOUNT_DEFAULT
        )
        dbSystemConfiguration.private_key_cycle_id__primary = (
            model_utils.PrivateKeyCycle.ACCOUNT_DEFAULT
        )
        dbSystemConfiguration.private_key_cycle_id__backup = (
            model_utils.PrivateKeyCycle.ACCOUNT_DEFAULT
        )
        dbSystemConfiguration.acme_profile__primary = "@"
        dbSystemConfiguration.acme_profile__backup = "@"
        ctx.dbSession.add(dbSystemConfiguration)
        ctx.dbSession.flush(
            objects=[
                dbSystemConfiguration,
            ]
        )

    return True


def application_started(ctx: "ApiContext", application_settings: Dict) -> Literal[True]:
    """
    initially this hook was used to:

    1- ensure a server listed in the conf file is in the db and active
    2- ensure the default account is on the default server

    Then:
        The conf-file based endpoint idea was removed;
        tests would fail if the global default acme-account got unset

    Right now this remains as a hook, but no code is worth running here.

    """

    return True
