# stdlib
import datetime
from enum import Enum
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING

# pypi
# import cert_utils
from cert_utils.model import KeyTechnologyEnum
from cert_utils.model import NewKeyArgs
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Mapped
from sqlalchemy.sql import expression
import sqlalchemy.types
from typing_extensions import TypedDict

from ..lib.errors import UnsupportedKeyTechnology


if TYPE_CHECKING:
    from .objects.objects import Domain

# ==============================================================================


class TZDateTime(sqlalchemy.types.TypeDecorator):
    impl = sqlalchemy.types.DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            if not value.tzinfo or value.tzinfo.utcoffset(value) is None:
                raise TypeError("tzinfo is required")
            value = value.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        return value


class year_week(expression.FunctionElement):
    inherit_cache = False
    type = sqlalchemy.types.String()
    name = "year_week"


@compiles(year_week)
def year_week__default(element, compiler, **kw) -> str:
    # return compiler.visit_function(element)
    """
    ## select extract(week from timestamp_event) from table_a;
    week_num = sqlalchemy.sql.expression.extract('WEEK', CertificateSigned.timestamp_not_before)
    """
    args = list(element.clauses)
    return "concat(extract(year from %s), '.', extract(week from %s)) " % (
        compiler.process(args[0]),
        compiler.process(args[0]),
    )


@compiles(year_week, "postgresql")
def year_week__postgresql(element, compiler, **kw) -> str:
    """
    # select to_char(timestamp_event, 'YYYY.WW')  from table_a;
    week_num = sqlalchemy.func.to_char(CertificateSigned.timestamp_not_before, 'YYYY.WW')
    """
    args = list(element.clauses)
    return "to_char(%s, 'YYYY.WW')" % (compiler.process(args[0]),)


@compiles(year_week, "sqlite")
def year_week__sqlite(element, compiler, **kw) -> str:
    """
    # strftime('%Y.%W', cast(CertificateSigned.timestamp_not_before) as text)
    week_num = sqlalchemy.func.strftime('%Y.%W',
                                        sqlalchemy.cast(TABLE.COLUMN,
                                                        sqlalchemy.Unicode
                                                        )
                                        )
    """
    args = list(element.clauses)
    return "strftime('%%Y.%%W', %s)" % (compiler.process(args[0]),)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class year_day(expression.FunctionElement):
    inherit_cache = False
    type = sqlalchemy.types.String()
    name = "year_day"


@compiles(year_day)
def year_day__default(element, compiler, **kw) -> str:
    # return compiler.visit_function(element)
    # TODO: lpad with 0s, as sqlite doesn't
    """
    ## select extract(doy from timestamp_event) from table_a;
    ## 94
    week_num = sqlalchemy.sql.expression.extract('WEEK', CertificateSigned.timestamp_not_before)
    ## select concat(extract(year from current_timestamp), '.', extract(doy from current_timestamp))
    """
    args = list(element.clauses)
    return "concat(extract(year from %s), '.', extract(doy from %s)) " % (
        compiler.process(args[0]),
        compiler.process(args[0]),
    )


@compiles(year_day, "postgresql")
def year_day__postgresql(element, compiler, **kw) -> str:
    """
    # select to_char(timestamp_event, 'YYYY.DDD')  from table_a;
    week_num = sqlalchemy.func.to_char(CertificateSigned.timestamp_not_before, 'YYYY.WW')
    # select to_char(current_timestamp, 'YYYY.DDD');
    # 2020.094
    """
    args = list(element.clauses)
    return "to_char(%s, 'YYYY.DDD')" % (compiler.process(args[0]),)


@compiles(year_day, "sqlite")
def year_day__sqlite(element, compiler, **kw) -> str:
    """
    # strftime('%Y.%j', cast(CertificateSigned.timestamp_not_before) as text)
    # 2020.094
    year_day = sqlalchemy.func.strftime('%Y.%j',
                                        sqlalchemy.cast(TABLE.COLUMN,
                                                        sqlalchemy.Unicode
                                                        )
                                        )
    """
    args = list(element.clauses)
    return "strftime('%%Y.%%j', %s)" % (compiler.process(args[0]),)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class min_date(expression.FunctionElement):
    inherit_cache = False
    type = sqlalchemy.types.DateTime()
    name = "min_date"


@compiles(min_date)
def min_date__default(element, compiler, **kw):
    # return compiler.visit_function(element)
    """
    # just return the first date
    """
    args = list(element.clauses)
    return compiler.process(args[0])


@compiles(min_date, "postgresql")
def min_date__postgresql(element, compiler, **kw) -> str:
    """
    # select least(col_a, col_b);
    """
    args = list(element.clauses)
    return "LEAST(%s, %s)" % (compiler.process(args[0]), compiler.process(args[1]))


@compiles(min_date, "sqlite")
def min_date__sqlite(element, compiler, **kw) -> str:
    """
    # select min(col_a, col_b);
    """
    args = list(element.clauses)
    return "min(%s, %s)" % (compiler.process(args[0]), compiler.process(args[1]))


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class utcnow(expression.FunctionElement):
    inherit_cache = True
    type = sqlalchemy.types.DateTime()
    name = "utcnow"


@compiles(utcnow)
def utcnow__default(element, compiler, **kw) -> str:
    # sqlite uses UTC by default
    return "CURRENT_TIMESTAMP"


@compiles(utcnow, "postgresql")
def utcnow__postgresql(element, compiler, **kw) -> str:
    return "TIMEZONE('utc', CURRENT_TIMESTAMP)"


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class indexable_lower(expression.FunctionElement):
    inherit_cache = False
    type = sqlalchemy.types.String()
    name = "indexable_lower"


@compiles(indexable_lower)
def indexable_lower__default(element, compiler, **kw) -> str:
    args = list(element.clauses)
    return "LOWER(%s)" % (compiler.process(args[0], **kw))


@compiles(indexable_lower, "sqlite")
def indexable_lower__sqlite(element, compiler, **kw) -> str:
    args = list(element.clauses)
    if compiler.dialect.dbapi.sqlite_version_info < (3, 9, 0):
        return compiler.process(args[0], **kw)
    else:
        return "LOWER(%s)" % (compiler.process(args[0], **kw))


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class _mixin_mapping(object):
    """handles a mapping of db codes/constants"""

    _mapping: Dict[int, str]
    _mapping_reverse: Dict[str, int]

    @classmethod
    def as_string(cls, mapping_id: int) -> str:
        if mapping_id in cls._mapping:
            return cls._mapping[mapping_id]
        return "***unknown***"

    @classmethod
    def from_string(cls, mapping_text: str) -> int:
        if not hasattr(cls, "_mapping_reverse"):
            cls._mapping_reverse = {v: k for k, v in cls._mapping.items()}
        return cls._mapping_reverse[mapping_text]


class _mixin_OperationsEventType(object):
    operations_event_type_id: Mapped[int]

    @property
    def event_type_text(self) -> str:
        return OperationsEventType.as_string(self.operations_event_type_id)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class _OperationsUnified(_mixin_mapping):
    """
    unified constants
    """

    _mapping = {
        1: "_DatabaseInitialization",
        110: "AcmeAccount__insert",
        111: "AcmeAccount__create",
        112: "AcmeAccount__deactivate",
        113: "AcmeAccount__key_change",
        114: "AcmeAccount__tos_change",
        120: "AcmeAccount__authenticate",
        121: "AcmeAccount__check",
        130: "AcmeAccount__mark",
        131: "AcmeAccount__mark__active",
        132: "AcmeAccount__mark__inactive",
        133: "AcmeAccount__mark__default",
        134: "AcmeAccount__mark__notdefault",
        135: "AcmeAccount__edit",
        136: "AcmeAccount__edit__order_defaults",
        137: "AcmeAccount__edit_AcmeAccountKey",
        138: "AcmeAccount__edit__private_key_technology",
        139: "AcmeAccount__mark__deactivated",
        140: "AcmeAccount__mark__backup",
        141: "AcmeAccount__mark__notbackup",
        142: "AcmeAccount__edit__name",
        143: "AcmeAccount__mark__is_render_in_selects",
        144: "AcmeAccount__mark__no_render_in_selects",
        150: "AcmeAccountKey__insert",
        151: "AcmeAccountKey__create",
        152: "AcmeAccountKey__mark__inactive",
        640: "AcmeOrder_New_Automated",
        650: "AcmeOrder_New_Retry",
        651: "AcmeOrder_Renew_Custom",
        652: "AcmeOrder_Renew_Quick",
        653: "AcmeOrder_New_RenewalConfiguration",
        # 661: "AcmeOrder__mark__renew_auto",
        # 662: "AcmeOrder__mark__renew_manual",
        1100: "AcmeServer__activate_default",
        1101: "AcmeServer__mark",
        1102: "AcmeServer__mark__is_enabled",
        1103: "AcmeServer__mark__is_unlimited_authz_true",
        1104: "AcmeServer__mark__is_unlimited_authz_false",
        1300: "AcmeDnsServer__insert",
        1301: "AcmeDnsServer__mark",
        1302: "AcmeDnsServer__mark__active",
        1303: "AcmeDnsServer__mark__inactive",
        1304: "AcmeDnsServer__mark__default",
        1305: "AcmeDnsServer__mark__notdefault",
        1306: "AcmeDnsServer__edit",
        1400: "AcmeDnsServerAccount__insert",
        2001: "ApiDomains__enable",
        2002: "ApiDomains__disable",
        2010: "ApiDomains__certificate_if_needed",
        2011: "ApiDomains__certificate_if_needed__domain_exists",
        2012: "ApiDomains__certificate_if_needed__domain_activate",
        2013: "ApiDomains__certificate_if_needed__domain_new",
        2015: "ApiDomains__certificate_if_needed__certificate_exists",
        2016: "ApiDomains__certificate_if_needed__certificate_new_success",
        2017: "ApiDomains__certificate_if_needed__certificate_new_fail",
        200: "CertificateCA__letsencrypt_sync",  # DEPRECATED
        210: "CertificateCA__insert",
        230: "CertificateCAChain__insert",
        610: "CertificateRequest__insert",
        620: "CertificateRequest__new",
        621: "CertificateRequest__new__imported",
        630: "CertificateRequest__new__acme_order",
        1200: "CoverageAssuranceEvent__mark_resolution",
        410: "Domain__insert",
        420: "Domain__mark",
        # 421: "Domain__mark__active",
        # 422: "Domain__mark__inactive",
        310: "PrivateKey__insert",
        311: "PrivateKey__generate",
        320: "PrivateKey__mark",
        321: "PrivateKey__mark__active",
        322: "PrivateKey__mark__inactive",
        323: "PrivateKey__mark__compromised",
        324: "PrivateKey__mark__default",
        325: "PrivateKey__mark__notdefault",
        330: "PrivateKey__revoke",
        340: "PrivateKey__insert_autogenerated_calendar",
        # 810: "QueueDomain__add",
        # 811: "QueueDomain__add__success",
        # 812: "QueueDomain__add__already_queued",
        # 813: "QueueDomain__add__already_exists",
        # 814: "QueueDomain__add__already_exists_activate",
        # 815: "QueueDomain__add__domain_blocklisted",
        # 820: "QueueDomain__process",
        # 821: "QueueDomain__process__success",
        # 822: "QueueDomain__process__fail",
        # 830: "QueueDomain__mark",
        # 831: "QueueDomain__mark__cancelled",
        # 832: "QueueDomain__mark__already_processed",
        # 910: "QueueCertificate__insert",
        # 920: "QueueCertificate__update",
        # 921: "QueueCertificate__batch",
        # 930: "QueueCertificate__mark",
        # 931: "QueueCertificate__mark__cancelled",
        # 940: "QueueCertificate__process",
        # 941: "QueueCertificate__process__success",
        # 942: "QueueCertificate__process__fail",
        710: "CertificateSigned__insert",
        720: "CertificateSigned__mark",
        721: "CertificateSigned__mark__active",
        722: "CertificateSigned__mark__inactive",
        723: "CertificateSigned__mark__revoked",
        724: "CertificateSigned__mark__compromised",  # the PrivateKey has been compromised
        726: "CertificateSigned__mark__unrevoked",
        # 727: "CertificateSigned__mark__renew_auto",
        # 728: "CertificateSigned__mark__renew_manual",
        740: "CertificateSigned__revoke",
        751: "CertificateSigned__deactivate_expired",
        752: "CertificateSigned__deactivate_duplicate",
        1600: "EnrollmentFactory__insert",
        1500: "RenewalConfiguration__insert",
        1530: "RenewalConfiguration__mark",
        1531: "RenewalConfiguration__mark__active",
        1532: "RenewalConfiguration__mark__inactive",
        1533: "RenewalConfiguration__mark__is_export_filesystem__on",
        1534: "RenewalConfiguration__mark__is_export_filesystem__off",
        510: "UniqueFQDNSet__insert",
        511: "UniquelyChallengedFQDNSet__insert",
        1002: "operations__update_recents__global",
        1003: "operations__update_recents__domains",
        1005: "operations__redis_prime",
        1006: "operations__nginx_cache_expire",
        1007: "operations__nginx_cache_flush",
        1008: "operations__reconcile_cas",
    }


class OperationsEventType(_OperationsUnified):
    """
    This object used to store constants
    """

    pass


class OperationsObjectEventStatus(_OperationsUnified):
    """
    This object is used to store constants
    """

    pass


class _Acme_Status_All(_mixin_mapping):
    """
    This is a base class to track and standardize the Acme Status Codes used
    in the following contexts:
        ACME Authorization
        ACME Challenge
        ACME Status

    Each context/object has a different set of valid codes and status transitions,
    however they share some core similarities.

    There are 3 custom codes used by this package, which are not ACME status but
    used as internal markers.

    * 0: "*discovered*"
        This internal marker is used to state a resource URL has been discovered by
        the system, but has not yet been queried.
        For example, upon creation an "Authorization" object contains several
        "Challenge" URLs. The Challenges are created in a "pending" state on the
        ACME server, but the system has not queried them yet and can not confirm
        they are "pending".

    * 404: "*404*"
        Inspired by the HTTP 404 Code "Not Found".
        This internal marker is used to state a resource URL does not exist on the
        ACME server. This usually only occurs in testing environments, as the objects
        do not persist.

    * 406: "*406*"
        Inspired by the HTTP 406 Code "Not Acceptable".
        This internal marker is used to state a resource URL is in a status that is
        not acceptable or tracked. This usually only occurs in testing environments, as
        the test ACME server may not implement the ACME Specification fully.
        For example, certain versions of the Pebble test server are known to mark
        an ACME Order as "deactivated" when the specification states is should be "invalid".

    * 410: "*410*"
        Inspired by the HTTP 410 Code "Gone".
        This should only occur in testing environments
    """

    ID_DEFAULT = 0
    ID_DISCOVERED = 0
    _mapping = {
        0: "*discovered*",
        1: "pending",
        2: "valid",
        3: "invalid",
        4: "deactivated",
        5: "expired",
        6: "revoked",
        7: "processing",
        8: "ready",
        404: "*404*",  # "Not Found"; resource is not on the server
        406: "*406*",  # "Not Acceptable"; the server returned a status we don't track
        410: "*410*",  # "Gone"; usually used by testing for something that was disabled
    }

    INVALID = 3
    DEACTIVATED = 4
    X_404_X = 404
    X_406_X = 406
    X_410_X = 410


class Acme_Status_Authorization(_Acme_Status_All):
    """The status of an authorization"""

    OPTIONS_DEACTIVATE = (
        "pending",
        "valid",  # a valid auth can be deactivated to uncache it
        "*discovered*",
    )
    OPTIONS_DEACTIVATE_TESTING = (  # tests don't care about valid
        "pending",
        "*discovered*",
    )
    OPTIONS_POSSIBLY_PENDING = (
        "pending",
        "*discovered*",
    )
    IDS_POSSIBLY_PENDING: List[int]  # define after declaring the class
    OPTIONS_X_UPDATE = ("*404*",)
    OPTIONS_TRIGGER = ("pending",)

    _mapping = {
        0: "*discovered*",
        1: "pending",
        2: "valid",
        3: "invalid",
        4: "deactivated",
        5: "expired",
        6: "revoked",
        404: "*404*",  # "Not Found"; resource is not on the server
        406: "*406*",  # "Not Acceptable"; the server returned a status we don't track
    }


Acme_Status_Authorization.IDS_POSSIBLY_PENDING = [
    Acme_Status_Authorization.from_string(i)
    for i in Acme_Status_Authorization.OPTIONS_POSSIBLY_PENDING
]


class Acme_Status_Challenge(_Acme_Status_All):
    """The status of a challenge"""

    OPTIONS_DEACTIVATE = (
        "pending",
        "*discovered*",
    )
    OPTIONS_POSSIBLY_ACTIVE = (
        "*discovered*",
        "pending",
        "processing",
    )
    OPTIONS_RESOLVED = (
        "valid",
        "invalid",
    )
    OPTIONS_PROCESSING = ("processing",)
    OPTIONS_INACTIVE = ("valid", "invalid", "*404*", "*410*")
    OPTIONS_TRIGGER = ("pending",)
    _mapping = {
        0: "*discovered*",
        1: "pending",
        2: "valid",
        3: "invalid",
        7: "processing",
        404: "*404*",  # "Not Found"; resource is not on the server
        406: "*406*",  # "Not Acceptable"; the server returned a status we don't track
        410: "*410*",  # "Gone"; use when the Authorization Payload no longer tracks this challenge
    }

    IDS_POSSIBLY_ACTIVE: List[int]  # define after declaring the class
    IDS_INACTIVE: List[int]  # define after declaring the class
    IDS_RESOLVED: List[int]  # define after declaring the class
    IDS_PROCESSING: List[int]  # define after declaring the class


Acme_Status_Challenge.IDS_INACTIVE = [
    Acme_Status_Challenge.from_string(i) for i in Acme_Status_Challenge.OPTIONS_INACTIVE
]
Acme_Status_Challenge.IDS_POSSIBLY_ACTIVE = [
    Acme_Status_Challenge.from_string(i)
    for i in Acme_Status_Challenge.OPTIONS_POSSIBLY_ACTIVE
]
Acme_Status_Challenge.IDS_RESOLVED = [
    Acme_Status_Challenge.from_string(i) for i in Acme_Status_Challenge.OPTIONS_RESOLVED
]
Acme_Status_Challenge.IDS_PROCESSING = [
    Acme_Status_Challenge.from_string(i)
    for i in Acme_Status_Challenge.OPTIONS_PROCESSING
]


class Acme_Status_Order(_Acme_Status_All):
    """
    The status of an order

    -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

    About the ACME order object Status

    # https://tools.ietf.org/html/rfc8555#section-7.1.3

    status (required, string):
        The status of this order.
        Possible values are" "pending", "ready", "processing", "valid", and "invalid".  See Section 7.1.6.

    # https://tools.ietf.org/html/rfc8555#page-48

       o  "invalid": The certificate will not be issued.  Consider this
          order process abandoned.

       o  "pending": The server does not believe that the client has
          fulfilled the requirements.  Check the "authorizations" array for
          entries that are still pending.

       o  "ready": The server agrees that the requirements have been
          fulfilled, and is awaiting finalization.  Submit a finalization
          request.

       o  "processing": The certificate is being issued.  Send a POST-as-GET
          request after the time given in the Retry-After header field of
          the response, if any.

       o  "valid": The server has issued the certificate and provisioned its
          URL to the "certificate" field of the order.  Download the
          certificate.

    PeterSSLers Extensions
        see _Acme_Status_All
        404 - not on the server (anymore? ever)
        406 - the status does not seem to be a valid transition
        410 - "Gone"; usually from testing
    """

    OPTIONS_FINALIZE = ("ready",)
    OPTIONS_PROCESS = (
        "pending",
        "ready",
    )
    OPTIONS_RENEW = (
        "valid",
        "ready",
        "*404*",
    )
    OPTIONS_RETRY: Tuple[str, ...] = (
        "invalid",
        "*404*",
        "*406*",
    )
    OPTIONS_UPDATE_DEACTIVATE: Tuple[str, ...] = (
        "valid",  # valid means we're done!
        "invalid",
        "*404*",
        "*406*",
        "*410*",
    )
    OPTIONS_X_ACME_SYNC = ("*404",)
    OPTIONS_X_DEACTIVATE_AUTHORIZATIONS = (
        # "valid",  # valid means we're done!
        "*404*",
    )
    OPTIONS_X_MARK_INVALID: Tuple[str, ...] = (
        "invalid",
        "valid",
        "*404*",
    )
    OPTIONS_BLOCKING = ("pending",)

    OPTIONS_active = (
        "pending",
        "ready",
        "processing",
    )
    OPTIONS_finished = (
        "invalid",
        "valid",
    )

    # orders with these status can not be processed any further
    OPTIONS_inactive = (
        "valid",
        "invalid",
        "*404*",
        "*406*",
        "*410*",
    )

    OPTIONS_potential_finalize = (
        "pending",
        "ready",
    )
    # do not include "valid", even though that can download
    OPTIONS_potential_certificate_download = (
        "pending",
        "ready",
        "processing",
    )

    _mapping = {
        0: "*discovered*",  # not an ACME status, but our internal marker
        1: "pending",
        2: "valid",
        3: "invalid",
        7: "processing",
        8: "ready",
        404: "*404*",  # "Not Found"; resource is not on the server
        406: "*406*",  # "Not Acceptable"; the server returned a status we don't track
        410: "*410*",  # "Gone"; use when turning off Orders during testing
    }

    IDS_BLOCKING: List[int]  # define after declaring the class
    IDS_RENEW: List[int]  # define after declaring the class
    IDS_active: List[int]  # define after declaring the class
    IDS_finished: List[int]  # define after declaring the class


if True:
    # pebble/boulder have a bug
    # orders are 'deactivated' when they should be 'invalid'
    # see https://github.com/letsencrypt/pebble/issues/300
    # see https://github.com/letsencrypt/boulder/issues/4887
    Acme_Status_Order._mapping[999] = "deactivated"
    Acme_Status_Order.OPTIONS_UPDATE_DEACTIVATE = (
        Acme_Status_Order.OPTIONS_UPDATE_DEACTIVATE + ("deactivated",)
    )
    Acme_Status_Order.OPTIONS_RETRY = Acme_Status_Order.OPTIONS_RETRY + ("deactivated",)
    Acme_Status_Order.OPTIONS_X_MARK_INVALID = (
        Acme_Status_Order.OPTIONS_X_MARK_INVALID + ("deactivated",)
    )

Acme_Status_Order.IDS_BLOCKING = [
    Acme_Status_Order.from_string(i) for i in Acme_Status_Order.OPTIONS_BLOCKING
]
Acme_Status_Order.IDS_RENEW = [
    Acme_Status_Order.from_string(i) for i in Acme_Status_Order.OPTIONS_RENEW
]
Acme_Status_Order.IDS_active = [
    Acme_Status_Order.from_string(i) for i in Acme_Status_Order.OPTIONS_active
]
Acme_Status_Order.IDS_finished = [
    Acme_Status_Order.from_string(i) for i in Acme_Status_Order.OPTIONS_finished
]


class AcmeAccountKeyOption(object):

    # legacy options
    options_all = (
        "account_key_global_default",
        "account_key_existing",
        "account_key_reuse",
        "account_key_file",
    )

    options_basic = (
        "account_key_global_default",
        "account_key_existing",
    )

    options_basic_backup = (
        "none",
        "account_key_global_backup",
        "account_key_existing",
    )

    options_streamlined = (
        "system_configuration_default",
        "account_key_existing",
    )
    options_streamlined_backup = (
        "none",
        "system_configuration_default",
        "account_key_existing",
    )

    options_basic_reuse = (
        "account_key_global_default",
        "account_key_existing",
        "account_key_reuse",
    )

    options_basic_backup_reuse = (
        "none",
        "account_key_global_backup",
        "account_key_existing",
        "account_key_reuse",
    )


class AcmeAccountKeySource(_mixin_mapping):
    """
    How was the AcmeAccountKey generated?
    """

    _mapping = {
        1: "generated",
        2: "imported",
    }

    GENERATED = 1
    IMPORTED = 2


class AcmeChallengeType(_mixin_mapping):
    """
    ACME supports multiple Challenge types
    """

    http_01 = 1
    dns_01 = 2
    tls_alpn_01 = 3
    _mapping = {
        1: "http-01",
        2: "dns-01",
        3: "tls-alpn-01",
    }

    DEFAULT = "http-01"


class AcmeChallengeFailType(_mixin_mapping):
    """
    Used for Acme Logging
    """

    _mapping = {
        1: "setup-prevalidation",
        2: "upstream-validation",
    }


class AcmeEvent(_mixin_mapping):
    """
    Used for Acme Logging
    """

    _mapping = {
        # 1: "v1|/acme/new-reg",  # account create
        # 2: "v1|/acme/new-authz",  # cert-request
        # 3: "v1|/acme/new-cert",  # cert-issue
        4: "v2|newAccount",  # account create
        5: "v2|newOrder",
        6: "v2|-authorization-request",  # hitting the LE authorization url
        7: "v2|-challenge-trigger",  # not an endpoint name, but element of an order
        8: "v2|Order-finalize",
        9: "v2|-order-location",
        10: "v2|-challenge-pass",
        11: "v2|-challenge-fail",
        12: "v2|Certificate-procured",  # we downloaded and enrolled the certificate
        13: "v2|-challenge-PostAsGet",
        14: "v2|-authorization-deactivate",
        15: "v2|Account-deactivate",
        16: "v2|keyChange",
    }


class AcmeOrder_ProcessingStrategy(_mixin_mapping):
    create_order = 1
    process_single = 2
    process_multi = 3
    _mapping = {
        1: "create_order",  # just create the order
        2: "process_single",  # create the order, and process in a single request
        3: "process_multi",  # create the order, but process piecemeal
    }
    OPTIONS_DEACTIVATE_AUTHS = ("process_single",)
    OPTIONS_ALL = (
        "create_order",
        "process_single",
        "process_multi",
    )
    OPTIONS_IMMEDIATE = ("process_single",)
    OPTIONS_REQUIRE_PYRAMID = (
        "process_single",
        "process_multi",
    )


class AcmeOrder_ProcessingStatus(_mixin_mapping):
    created_local = 1
    created_acme = 2
    processing_started = 3
    processing_completed_success = 4
    processing_completed_failure = 5
    order_finalized = 6
    certificate_downloaded = 7
    processing_deactivated = 8
    _mapping = {
        1: "created_local",
        2: "created_acme",
        3: "processing_started",
        4: "processing_completed_success",
        5: "processing_completed_failure",
        6: "order_finalized",
        7: "certificate_downloaded",
        8: "processing_deactivated",
    }
    IDS_CAN_PROCESS_CHALLENGES = (2, 3)


class AcmeOrderType(_mixin_mapping):
    """
    How was the AcmeOrder created?
    """

    ACME_ORDER_NEW_FREEFORM = 1
    RETRY = 2
    # ACME_AUTOMATED_RENEW_QUICK = 3
    # ACME_AUTOMATED_RENEW_CUSTOM = 4
    CERTIFICATE_IF_NEEDED = 5  # CIN=Certificate-If-Needed
    AUTOCERT = 6
    # ENROLLMENT_FACTORY = 7
    # QUEUE_CERTIFICATE = 11
    # QUEUE_DOMAINS = 12
    RENEWAL_CONFIGURATION_REQUEST = 21
    RENEWAL_CONFIGURATION_AUTOMATED = 22
    _mapping = {
        1: "ACME (New Freeform Order)",
        2: "ACME (Retry)",
        # 3: "ACME Automated (Renew Quick)",
        # 4: "ACME Automated (Renew Custom)",
        5: "ACME (New - Certificate if Needed)",
        6: "ACME (New - Autocert)",
        # 7: "ACME (New - EnrollmentFactory)",
        # 11: "Queue - Certificate Renewal",
        # 12: "Queue - Domains",
        21: "RenewalConfiguration - Request",
        22: "RenewalConfiguration - Automated",
    }


# note: AcmeServerInput
AcmeServerInput = TypedDict(
    "AcmeServerInput",
    {
        "name": str,
        "directory": str,
        "protocol": str,
        # "is_default": Optional[bool],
        "is_supports_ari__version": Optional[str],
        "is_unlimited_pending_authz": Optional[bool],
        "filepath_ca_cert_bundle": Optional[str],
        "ca_cert_bundle": Optional[str],
    },
    total=False,
)


class CertificateRequestSource(_mixin_mapping):
    """
    How was the CertificateRequest generated?
    - imported - just records the CSR; uploaded into our system
    - acme_order - part of an acme order
    """

    IMPORTED = 1
    ACME_ORDER = 2

    _mapping = {
        1: "imported",
        2: "acme_order",
    }


class CertificateType(_mixin_mapping):
    """
    What role is the certificate
    """

    RAW_IMPORTED = 1
    MANAGED_PRIMARY = 2
    MANAGED_BACKUP = 3

    _mapping = {
        1: "RawImported",
        2: "ManagedPrimary",
        3: "ManagedBackup",
    }

    _options_AcmeOrder_id = [2, 3]

    @classmethod
    def to_CertificateType_Enum(cls, id_) -> Optional["CertificateType_Enum"]:
        if id_ == CertificateType.RAW_IMPORTED:
            return None
        elif id_ == CertificateType.MANAGED_PRIMARY:
            return CertificateType_Enum.MANAGED_PRIMARY
        elif id_ == CertificateType.MANAGED_BACKUP:
            return CertificateType_Enum.MANAGED_BACKUP
        raise ValueError("invalid id_")


class CertificateType_Enum(Enum):
    MANAGED_PRIMARY = CertificateType.MANAGED_PRIMARY
    MANAGED_BACKUP = CertificateType.MANAGED_BACKUP


class CoverageAssuranceEventType(_mixin_mapping):
    _mapping = {
        1: "PrivateKey_compromised_mark",  # we mark it as compromised
        2: "PrivateKey_compromised_acme",  # the ACME server is confirmed to have it as compromised
        3: "CertificateSigned_revoked_mark",  # we mark it as revoked
        4: "CertificateSigned_revoked_acme",  # ACME confirms it as revoked
        5: "AccountKey_revoked_mark",  # we mark it as revoked
        6: "AccountKey_revoked_acme",  # ACME confirms it as revoked
        # 7: "QueueCertificate_no_account_key",  # the Queue item has no key, and the fallback global is unavailable
    }


class CoverageAssuranceEventStatus(_mixin_mapping):
    _mapping = {
        1: "reported",
        2: "reported+deactivated",
        3: "resolved-ignored",
        4: "resolved-replaced",
    }
    OPTIONS_ALL: List[str]


CoverageAssuranceEventStatus.OPTIONS_ALL = list(
    CoverageAssuranceEventStatus._mapping.values()
)


class CoverageAssuranceResolution(_mixin_mapping):
    _mapping = {
        1: "unresolved",
        2: "abandoned",
        3: "PrivateKey_replaced",
        4: "CertificateSigned_replaced",
    }
    OPTIONS_ALL: List[str]

    UNRESOLVED = 1


CoverageAssuranceResolution.OPTIONS_ALL = list(
    CoverageAssuranceResolution._mapping.values()
)


class DomainsChallenged(dict):
    """
    standardized mapping for `domains_challenged` items

    keep in sync with `AcmeChallengeType._mapping`
    """

    DEFAULT = AcmeChallengeType.DEFAULT
    _challenge_types = [
        "http-01",
        "dns-01",
        "tls-alpn-01",
    ]

    def __init__(self, *args, **kwargs):
        if args or kwargs:
            raise ValueError("no args or kwargs")
        for _ct in self._challenge_types:
            self[_ct] = None

    @property
    def domains_as_list(self) -> List[str]:
        _domains = []
        for v in self.values():
            if v is not None:
                _domains.extend(v)
        return sorted(_domains)

    def ensure_parity(self, domains_to_test: List[str]) -> None:
        """raise a ValueError if we do not have the exact set of domains"""
        if not isinstance(domains_to_test, list):
            raise ValueError("`domains_to_test` must be a list")
        domains_to_test = sorted(domains_to_test)
        domain_names = self.domains_as_list
        if domain_names != domains_to_test:
            raise ValueError("`%s` != `%s`" % (domain_names, domains_to_test))

    @classmethod
    def new_http01(cls, domains_list: List[str]) -> "DomainsChallenged":
        _domains_challenged = DomainsChallenged()
        _domains_challenged["http-01"] = domains_list
        return _domains_challenged

    def ENSURE_DEFAULT_HTTP01(self):
        # default challenge type is http-01
        if self.DEFAULT != "http-01":
            raise ValueError("`DomainsChallenged.DEFAULT` must be `http-01`")

    def domain_to_challenge_type_id(self, domain_name: str) -> int:
        for _acme_challenge_type in self.keys():
            if self[_acme_challenge_type]:
                for _domain_name in self[_acme_challenge_type]:
                    if _domain_name == domain_name:
                        return AcmeChallengeType.from_string(_acme_challenge_type)
        raise ValueError("domain is not challenged")

    def serialize_names(self) -> str:
        lines = []
        for _ct in sorted(self._challenge_types):
            if not self[_ct]:
                continue
            vals = sorted(self[_ct])
            lines.append("%s:%s" % (_ct, ",".join(vals)))
        return ";".join(lines)

    def serialize_ids(self, mapping: Dict[str, "Domain"]) -> str:
        lines = []
        for _ct in sorted(self._challenge_types):
            if not self[_ct]:
                continue
            vals = sorted([mapping[name].id for name in self[_ct]])
            lines.append("%s:%s" % (_ct, ",".join([str(i) for i in vals])))
        return ";".join(lines)


class KeyDeactivationType(_mixin_mapping):
    ACCOUNT_KEY_ROLLOVER = 1

    _mapping = {
        1: "ACCOUNT_KEY_ROLLOVER",
    }


class KeyTechnology(_mixin_mapping):
    """
    What kind of Certificate/Key is this?
    """

    ACCOUNT_DEFAULT = 0  # PlaceHolder
    SYSTEM_CONFIGURATION_DEFAULT = 99
    RSA_2048 = 1
    RSA_3072 = 2
    RSA_4096 = 3
    EC_P256 = 4  # ECDSA
    EC_P384 = 5  # ECDSA

    _mapping = {
        0: "account_default",
        1: "RSA_2048",
        2: "RSA_3072",
        3: "RSA_4096",
        4: "EC_P256",
        5: "EC_P384",
        99: "system_configuration_default",
    }

    _options_all_id = (0, 1, 2, 3, 4, 5)
    _options_AcmeAccount_private_key_technology_id = (1, 2, 3, 4, 5)
    _options_AcmeAccount_order_default_id = (1, 2, 3, 4, 5)
    _options_CertificateIfNeeded_id = (0, 1, 2, 3, 4, 5, 99)
    _options_RenewalConfiguration_private_key_technology_id = (0, 1, 2, 3, 4, 5)
    _options_RenewalConfiguration_private_key_technology_id__alt = (
        0,
        1,
        2,
        3,
        4,
        5,
        99,
    )
    _options_Generate_id = (1, 2, 3, 4, 5)
    _options_RSA_id = (1, 2, 3)
    _options_EC_id = (4, 5)

    _DEFAULT = "EC_P256"
    _DEFAULT_id: int
    _DEFAULT_AcmeAccount = "EC_P256"
    _DEFAULT_AcmeAccount_id: int
    _DEFAULT_AcmeAccount_order_default = "EC_P256"
    _DEFAULT_AcmeAccount_order_default_id: int
    _DEFAULT_AcmeOrder = "EC_P256"
    _DEFAULT_Generate = "EC_P256"
    _DEFAULT_Generate_id: int
    _DEFAULT_GlobalKey = "EC_P256"
    _DEFAULT_GlobalKey_id: int
    _DEFAULT_PrivateKey = "EC_P256"
    _DEFAULT_PrivateKey_id: int
    _DEFAULT_RenewalConfiguration = "account_default"
    _DEFAULT_RenewalConfiguration_id: int
    _options_all: List[str]
    _options_AcmeAccount_private_key_technology: List[str]
    _options_AcmeAccount_order_default: List[str]
    _options_Generate: List[str]
    _options_RenewalConfiguration_private_key_technology: List[str]
    _options_RenewalConfiguration_private_key_technology__alt: List[str]
    _options_CertificateIfNeeded: List[str]

    @classmethod
    def to_new_args(cls, id_) -> NewKeyArgs:
        kwargs: NewKeyArgs = {}
        if id_ in (cls.RSA_2048, cls.RSA_3072, cls.RSA_4096):
            kwargs["key_technology_id"] = KeyTechnologyEnum.RSA
            if id_ == cls.RSA_2048:
                kwargs["rsa_bits"] = 2048
            elif id_ == cls.RSA_3072:
                kwargs["rsa_bits"] = 3072
            elif id_ == cls.RSA_4096:
                kwargs["rsa_bits"] = 4096
        elif id_ in (cls.EC_P256, cls.EC_P384):
            kwargs["key_technology_id"] = KeyTechnologyEnum.EC
            if id_ == cls.EC_P256:
                kwargs["ec_curve"] = "P-256"
            elif id_ == cls.EC_P384:
                kwargs["ec_curve"] = "P-384"
        return kwargs

    @classmethod
    def from_cert_utils_tuple(cls, cu_args: Tuple) -> int:
        if cu_args[0] == "EC":
            if cu_args[1][0] == "P-256":
                return cls.EC_P256
            elif cu_args[1][0] == "P-384":
                return cls.EC_P384
            raise UnsupportedKeyTechnology("EC Recognized; unknown: %s" % cu_args[1][0])
        elif cu_args[0] == "RSA":
            if cu_args[1][0] == 2048:
                return cls.RSA_2048
            elif cu_args[1][0] == 3072:
                return cls.RSA_3072
            elif cu_args[1][0] == 4096:
                return cls.RSA_4096
            raise UnsupportedKeyTechnology(
                "RSA Recognized; unknown: %s" % cu_args[1][0]
            )
        raise ValueError("unknown cu_args: %s", cu_args)


KeyTechnology._options_all = [
    KeyTechnology._mapping[_id] for _id in KeyTechnology._options_all_id
]
KeyTechnology._options_AcmeAccount_private_key_technology = [
    KeyTechnology._mapping[_id]
    for _id in KeyTechnology._options_AcmeAccount_private_key_technology_id
]
KeyTechnology._options_AcmeAccount_order_default = [
    KeyTechnology._mapping[_id]
    for _id in KeyTechnology._options_AcmeAccount_order_default_id
]
KeyTechnology._options_CertificateIfNeeded = [
    KeyTechnology._mapping[_id] for _id in KeyTechnology._options_CertificateIfNeeded_id
]
KeyTechnology._options_Generate = [
    KeyTechnology._mapping[_id] for _id in KeyTechnology._options_Generate_id
]
KeyTechnology._options_RenewalConfiguration_private_key_technology = [
    KeyTechnology._mapping[_id]
    for _id in KeyTechnology._options_RenewalConfiguration_private_key_technology_id
]
KeyTechnology._options_RenewalConfiguration_private_key_technology__alt = [
    KeyTechnology._mapping[_id]
    for _id in KeyTechnology._options_RenewalConfiguration_private_key_technology_id__alt
]

KeyTechnology._DEFAULT_id = KeyTechnology.from_string(KeyTechnology._DEFAULT)
KeyTechnology._DEFAULT_AcmeAccount_id = KeyTechnology.from_string(
    KeyTechnology._DEFAULT_AcmeAccount
)
KeyTechnology._DEFAULT_AcmeAccount_order_default_id = KeyTechnology.from_string(
    KeyTechnology._DEFAULT_AcmeAccount_order_default
)
KeyTechnology._DEFAULT_Generate_id = KeyTechnology.from_string(
    KeyTechnology._DEFAULT_Generate
)
KeyTechnology._DEFAULT_GlobalKey_id = KeyTechnology.from_string(
    KeyTechnology._DEFAULT_GlobalKey
)
KeyTechnology._DEFAULT_PrivateKey_id = KeyTechnology.from_string(
    KeyTechnology._DEFAULT_PrivateKey
)
KeyTechnology._DEFAULT_RenewalConfiguration_id = KeyTechnology.from_string(
    KeyTechnology._DEFAULT_RenewalConfiguration
)


class NotificationType(_mixin_mapping):
    ACME_SERVER_CHANGED = 1

    _mapping = {
        1: "acme_server_changed",
    }


class OptionsOnOff(_mixin_mapping):
    OFF = 0
    ON = 1
    ENROLLMENT_FACTORY_DEFAULT = 2

    _mapping = {
        0: "off",
        1: "on",
        2: "enrollment_factory_default",
    }
    _options_EnrollmentFactory_isExportFilesystem_id = (0, 1)
    _options_EnrollmentFactory_isExportFilesystem: List[str]
    _options_RenewalConfiguration_isExportFilesystem_id = (0, 1)
    _options_RenewalConfiguration_isExportFilesystem: List[str]
    _options_RenewalConfigurationFactory_isExportFilesystem_id = (2,)
    _options_RenewalConfigurationFactory_isExportFilesystem: List[str]


# compute this for ease of `curl` options
OptionsOnOff._options_EnrollmentFactory_isExportFilesystem = [
    OptionsOnOff._mapping[_id]
    for _id in OptionsOnOff._options_EnrollmentFactory_isExportFilesystem_id
]
OptionsOnOff._options_RenewalConfiguration_isExportFilesystem = [
    OptionsOnOff._mapping[_id]
    for _id in OptionsOnOff._options_RenewalConfiguration_isExportFilesystem_id
]
OptionsOnOff._options_RenewalConfigurationFactory_isExportFilesystem = [
    OptionsOnOff._mapping[_id]
    for _id in OptionsOnOff._options_RenewalConfigurationFactory_isExportFilesystem_id
]


class PrivateKeyCycle(_mixin_mapping):
    """
    How should a PrivateKey be cycled on renewal?
    """

    ACCOUNT_DEFAULT = 1  # Placeholder
    SINGLE_USE = 2
    ACCOUNT_DAILY = 3
    GLOBAL_DAILY = 4
    ACCOUNT_WEEKLY = 5
    GLOBAL_WEEKLY = 6
    SINGLE_USE__REUSE_1_YEAR = 7
    SYSTEM_CONFIGURATION_DEFAULT = 8

    _mapping = {
        1: "account_default",  # use the Account Default
        2: "single_use",
        3: "account_daily",  # use the account's daily key
        4: "global_daily",  # use a global daily key
        5: "account_weekly",  # use the account's weekly key
        6: "global_weekly",  # use the global weekly key
        7: "single_use__reuse_1_year",  # reuse the single certificate for up to one year
        8: "system_configuration_default",  # use the SystemConfiguration Default
    }
    _options_AcmeAccount_order_default_id = (
        # 1, #  this IS the Account Default
        2,
        3,
        4,
        5,
        6,
        7,
    )
    _options_RenewalConfiguration_private_key_cycle_id = (
        1,
        2,
        3,
        4,
        5,
        6,
        7,
    )
    _options_RenewalConfiguration_private_key_cycle_id__alt = (  # testing sysconfig
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
    )
    _options_CertificateIfNeeded_private_key_cycle_id = (
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
    )
    _DEFAULT_order_logic = "single_use"
    _DEFAULT_AcmeOrder = "account_default"
    _DEFAULT_AcmeAccount_order_default = "single_use__reuse_1_year"
    _DEFAULT_system_renewal = "single_use"

    _options_AcmeAccount_order_default: List[str]
    _options_RenewalConfiguration_private_key_cycle: List[str]
    _options_CertificateIfNeeded_private_key_cycle: List[str]
    _options_RenewalConfiguration_private_key_cycle__alt: List[str]


# compute this for ease of `curl` options
PrivateKeyCycle._options_AcmeAccount_order_default = [
    PrivateKeyCycle._mapping[_id]
    for _id in PrivateKeyCycle._options_AcmeAccount_order_default_id
]
PrivateKeyCycle._options_RenewalConfiguration_private_key_cycle = [
    PrivateKeyCycle._mapping[_id]
    for _id in PrivateKeyCycle._options_RenewalConfiguration_private_key_cycle_id
]
PrivateKeyCycle._options_CertificateIfNeeded_private_key_cycle = [
    PrivateKeyCycle._mapping[_id]
    for _id in PrivateKeyCycle._options_CertificateIfNeeded_private_key_cycle_id
]
PrivateKeyCycle._options_RenewalConfiguration_private_key_cycle__alt = [
    PrivateKeyCycle._mapping[_id]
    for _id in PrivateKeyCycle._options_RenewalConfiguration_private_key_cycle_id__alt
]


class PrivateKeyDeferred(_mixin_mapping):
    """
    What kind of PrivateKeyDeferred is this?

    When creating an order, we have a few ways to specify the key

    1- Specify an Actual Key for the order
    2- Defer the key
        1. use the AcmeAccount.order_default [account_default]
        2. use a weekly/daily key [account_associate]
        3. make a new key with a specific algorithm [generate__*]
    """

    NOT_DEFERRED = 0
    ACCOUNT_DEFAULT = 1  # Placeholder
    ACCOUNT_ASSOCIATE = 2
    SYSTEM_CONFIGURATION_DEFAULT = 3  # Placeholder

    # Specifically Requested Keys
    GENERATE__RSA_2048 = 11
    GENERATE__RSA_3072 = 12
    GENERATE__RSA_4096 = 13
    GENERATE__EC_P256 = 14
    GENERATE__EC_P384 = 15

    _mapping = {
        0: "not_deferred",
        1: "account_default",
        2: "account_associate",
        3: "system_configuration_default",
        # Specifically Requested Keys
        11: "generate__rsa_2048",
        12: "generate__rsa_3072",
        13: "generate__rsa_4096",
        14: "generate__ec_p256",
        15: "generate__ec_p384",
    }

    _options_generate = (
        "generate__rsa_2048",
        "generate__rsa_3072",
        "generate__rsa_4096",
        "generate__ec_p256",
        "generate__ec_p384",
    )

    @classmethod
    def generate_from_key_technology_str(
        cls, key_technology_str: str
    ) -> Tuple[int, str]:
        as_str = "generate__%s" % key_technology_str.lower()
        as_id = getattr(cls, as_str.upper())
        return (as_id, as_str)

    @classmethod
    def str_to_KeyTechnology_id(cls, str_) -> int:
        if str_ == "generate__rsa_2048":
            return KeyTechnology.RSA_2048
        elif str_ == "generate__rsa_3072":
            return KeyTechnology.RSA_3072
        elif str_ == "generate__rsa_4096":
            return KeyTechnology.RSA_4096
        elif str_ == "generate__ec_p256":
            return KeyTechnology.EC_P256
        elif str_ == "generate__ec_p384":
            return KeyTechnology.EC_P384
        raise ValueError("unsupported: `%s`" % str_)

    @classmethod
    def id_from_KeyTechnology_id(cls, key_technology_id) -> int:
        key_technology = KeyTechnology.as_string(key_technology_id)
        if key_technology == "RSA_2048":
            return cls.GENERATE__RSA_2048
        elif key_technology == "RSA_3072":
            return cls.GENERATE__RSA_3072
        elif key_technology == "RSA_4096":
            return cls.GENERATE__RSA_4096
        elif key_technology == "EC_P256":
            return cls.GENERATE__EC_P256
        elif key_technology == "EC_P384":
            return cls.GENERATE__EC_P384
        raise ValueError("unsupported: `%s`" % key_technology_id)


class PrivateKeyOption(object):

    options_all = (
        "account_default",
        "private_key_existing",
        "private_key_file",
        "private_key_generate",
        "private_key_reuse",
    )

    options_basic = (
        "account_default",
        "private_key_existing",
        "private_key_generate",
    )

    options_streamlined = (
        "private_key_generate",
        "private_key_existing",
    )

    options_streamlined_backup = (
        "none",
        "private_key_generate",
        "private_key_existing",
    )


class PrivateKeySource(_mixin_mapping):
    """
    How was the PrivateKey generated?
    """

    _mapping = {
        0: "placeholder",  # application setup only
        1: "generated",
        2: "imported",
    }

    PLACEHOLDER = 0
    GENERATED = 1
    IMPORTED = 2


class PrivateKeyStrategy(_mixin_mapping):
    """
    What is the strategy for associating the PrivateKey to the order?
    """

    _mapping = {
        1: "specified",
        2: "deferred-generate",  # generate a new PrivateKey when the order is made
        3: "deferred-associate",  # use the daily/weekly/account/per-certificate when the order is made
        4: "backup",  # if there is an issue using the intended PrivateKey, backup to a new one
        5: "reused",  # only used for single_use__reuse_1_year
    }
    _DEFAULT_system_renewal = "deferred-generate"

    SPECIFIED = 1
    DEFERRED_GENERATE = 2
    DEFERRED_ASSOCIATE = 3
    BACKUP = 4
    REUSED = 5

    @classmethod
    def from_private_key_cycle(cls, private_key_cycle: str) -> str:
        _PrivateKeyCycle_2_PrivateKeyStrategy = {
            "single_use": "deferred-generate",
            "single_use__reuse_1_year": "deferred-associate",
            "account_daily": "deferred-associate",
            "global_daily": "deferred-associate",
            "account_weekly": "deferred-associate",
            "global_weekly": "deferred-associate",
            "account_default": "*lookup*",
        }
        return _PrivateKeyCycle_2_PrivateKeyStrategy[private_key_cycle]


class PrivateKeyType(_mixin_mapping):
    """
    What kind of PrivateKey is this?
    """

    _mapping = {
        0: "placeholder",
        1: "standard",
        2: "single_use",
        3: "global_daily",
        4: "global_weekly",
        5: "account_daily",
        6: "account_weekly",
        7: "single_use__reuse_1_year",
    }

    PLACEHOLDER = 0
    STANDARD = 1
    SINGLE_USE = 2
    GLOBAL_DAILY = 3
    GLOBAL_WEEKLY = 4
    ACCOUNT_DAILY = 5
    ACCOUNT_WEEKLY = 6
    SINGLE_USE__REUSE_1_YEAR = 7

    @classmethod
    def from_private_key_cycle(cls, private_key_cycle: str) -> str:
        if private_key_cycle == "account_default":
            raise ValueError("`account_default` invalid")
        elif private_key_cycle in (
            "single_use",
            "global_daily",
            "global_weekly",
            "account_daily",
            "account_weekly",
            "single_use__reuse_1_year",
        ):
            return private_key_cycle
        else:
            raise ValueError("unsupported type: %s" % private_key_cycle)

    _options_calendar = (
        "global_daily",
        "global_weekly",
        "account_daily",
        "account_weekly",
    )
    _options_calendar_weekly = (
        "global_weekly",
        "account_weekly",
    )
    _options_calendar_daily = ("global_daily" "account_daily",)


class ReplacesType(_mixin_mapping):
    """
    What kind of `replaces` is this?
    """

    _mapping = {
        1: "AUTOMATIC",
        2: "MANUAL",
        3: "RETRY",
    }

    AUTOMATIC = 1
    MANUAL = 2
    RETRY = 3


class ReplacesType_Enum(Enum):
    AUTOMATIC = ReplacesType.AUTOMATIC
    MANUAL = ReplacesType.MANUAL
    RETRY = ReplacesType.RETRY


class Routine(_mixin_mapping):
    # these need to be tracked for performance
    _mapping = {
        1: "periodic",
        2: "routine__run_ari_checks",
        3: "routine__clear_old_ari_checks",
        4: "routine__order_missing",
        5: "routine__renew_expiring",
        6: "routine__reconcile_blocks",
    }

    periodic = 1
    routine__run_ari_checks = 2
    routine__clear_old_ari_checks = 3
    routine__order_missing = 4
    routine__renew_expiring = 5
    routine__reconcile_blocks = 6
