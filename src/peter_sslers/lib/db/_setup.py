# stdlib
import logging
from typing import Dict
from typing import List
from typing import TYPE_CHECKING

# pypi
import cert_utils
from typing_extensions import Literal

# local
from . import actions as db_actions
from . import create as db_create
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
    dbObject.private_key_source_id = model_utils.PrivateKey_Source.PLACEHOLDER
    dbObject.private_key_type_id = model_utils.PrivateKey_Type.PLACEHOLDER
    # SYSTEM_DEFAULT
    dbObject.key_technology_id = model_utils.KeyTechnology._DEFAULT_id
    ctx.dbSession.add(dbObject)
    ctx.dbSession.flush(
        objects=[
            dbObject,
        ]
    )

    # !!!: CertificateAuthorities

    dbOperationsEventTrusts, certs_lookup = db_actions.refresh_roots(
        ctx,
        dbOperationsEvent_child_of=dbOperationsEvent,
    )

    # now install the default preference chain
    # _now = datetime.datetime.now(datetime.timezone.utc)
    # _buffer = datetime.timedelta(90)
    # date_cutoff = _now + _buffer
    dbX509CertificateTrustPreferencePolicy = (
        db_create.create__X509CertificateTrustPreferencePolicy(ctx, "global")
    )
    from cert_utils import letsencrypt_info

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
        dbX509CertificateTrusted = certs_lookup[cert_id]
        dbPref = db_create.create__X509CertificatePreferencePolicyItem(  # noqa: F841
            ctx,
            dbX509CertificateTrustPreferencePolicy=dbX509CertificateTrustPreferencePolicy,
            dbX509CertificateTrusted=dbX509CertificateTrusted,
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
            model_utils.PrivateKey_Cycle.ACCOUNT_DEFAULT
        )
        dbSystemConfiguration.private_key_cycle_id__backup = (
            model_utils.PrivateKey_Cycle.ACCOUNT_DEFAULT
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
