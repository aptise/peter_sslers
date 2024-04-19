# stdlib
from typing import Dict
from typing import List
from typing import Tuple

# pypi
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Mapped
from sqlalchemy.sql import expression
import sqlalchemy.types


# ==============================================================================


class year_week(expression.FunctionElement):
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
        return "unknown"

    @classmethod
    def from_string(cls, mapping_text: str) -> int:
        if not hasattr(cls, "_mapping_reverse"):
            cls._mapping_reverse = {v: k for k, v in cls._mapping.items()}
        return cls._mapping_reverse[mapping_text]


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
        120: "AcmeAccount__authenticate",
        121: "AcmeAccount__check",
        130: "AcmeAccount__mark",
        131: "AcmeAccount__mark__active",
        132: "AcmeAccount__mark__inactive",
        133: "AcmeAccount__mark__default",
        134: "AcmeAccount__mark__notdefault",
        135: "AcmeAccount__edit",
        136: "AcmeAccount__edit__private_key_cycle",
        137: "AcmeAccount__edit_AcmeAccountKey",
        138: "AcmeAccount__edit__private_key_technology",
        139: "AcmeAccount__mark__deactivated",
        150: "AcmeAccountKey__insert",
        151: "AcmeAccountKey__create",
        152: "AcmeAccountKey__mark__inactive",
        640: "AcmeOrder_New_Automated",
        650: "AcmeOrder_New_Retry",
        651: "AcmeOrder_Renew_Custom",
        652: "AcmeOrder_Renew_Quick",
        661: "AcmeOrder__mark__renew_auto",
        662: "AcmeOrder__mark__renew_manual",
        1100: "AcmeAccountProvider__activate_default",
        1101: "AcmeAccountProvider__mark__is_enabled",
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
        421: "Domain__mark__active",
        422: "Domain__mark__inactive",
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
        810: "QueueDomain__add",
        811: "QueueDomain__add__success",
        812: "QueueDomain__add__already_queued",
        813: "QueueDomain__add__already_exists",
        814: "QueueDomain__add__already_exists_activate",
        815: "QueueDomain__add__domain_blocklisted",
        820: "QueueDomain__process",
        821: "QueueDomain__process__success",
        822: "QueueDomain__process__fail",
        830: "QueueDomain__mark",
        831: "QueueDomain__mark__cancelled",
        832: "QueueDomain__mark__already_processed",
        910: "QueueCertificate__insert",
        920: "QueueCertificate__update",
        921: "QueueCertificate__batch",
        930: "QueueCertificate__mark",
        931: "QueueCertificate__mark__cancelled",
        940: "QueueCertificate__process",
        941: "QueueCertificate__process__success",
        942: "QueueCertificate__process__fail",
        710: "CertificateSigned__insert",
        720: "CertificateSigned__mark",
        721: "CertificateSigned__mark__active",
        722: "CertificateSigned__mark__inactive",
        723: "CertificateSigned__mark__revoked",
        724: "CertificateSigned__mark__compromised",  # the PrivateKey has been compromised
        726: "CertificateSigned__mark__unrevoked",
        727: "CertificateSigned__mark__renew_auto",
        728: "CertificateSigned__mark__renew_manual",
        740: "CertificateSigned__revoke",
        751: "CertificateSigned__deactivate_expired",
        752: "CertificateSigned__deactivate_duplicate",
        510: "UniqueFQDNSet__insert",
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
    }


class Acme_Status_Authorization(_Acme_Status_All):
    """The status of an authorization"""

    OPTIONS_DEACTIVATE = (
        "pending",
        "valid",  # a valid auth can be deactivated to uncache it
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
    Acme_Status_Order.OPTIONS_UPDATE_DEACTIVATE = Acme_Status_Order.OPTIONS_RETRY + (
        "deactivated",
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


class AcmeAccountKeySource(_mixin_mapping):
    """
    How was the AcmeAccountKey generated?
    """

    _mapping = {
        1: "generated",
        2: "imported",
    }


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
    _OPTIONS_AcmeOrderless_AddChallenge = ("http-01",)


class AcmeChallengeFailType(_mixin_mapping):
    """
    Used for Acme Logging
    """

    _mapping = {1: "setup-prevalidation", 2: "upstream-validation"}


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

    ACME_AUTOMATED_NEW = 1
    ACME_AUTOMATED_RETRY = 2
    ACME_AUTOMATED_RENEW_QUICK = 3
    ACME_AUTOMATED_RENEW_CUSTOM = 4
    ACME_AUTOMATED_NEW__CIN = 5  # CIN=Certificate-If-Needed
    QUEUE_CERTIFICATE = 11
    QUEUE_DOMAINS = 12
    _mapping = {
        1: "ACME Automated (New)",
        2: "ACME Automated (Retry)",
        3: "ACME Automated (Renew Quick)",
        4: "ACME Automated (Renew Custom)",
        5: "ACME Automated (New - Certificate if Needed)",
        11: "Queue - Certificate Renewal",
        12: "Queue - Domains",
    }


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


class CoverageAssuranceEventType(_mixin_mapping):
    _mapping = {
        1: "PrivateKey_compromised_mark",  # we mark it as compromised
        2: "PrivateKey_compromised_acme",  # the ACME server is confirmed to have it as compromised
        3: "CertificateSigned_revoked_mark",  # we mark it as revoked
        4: "CertificateSigned_revoked_acme",  # ACME confirms it as revoked
        5: "AccountKey_revoked_mark",  # we mark it as revoked
        6: "AccountKey_revoked_acme",  # ACME confirms it as revoked
        7: "QueueCertificate_no_account_key",  # the Queue item has no key, and the fallback global is unavailable
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


CoverageAssuranceResolution.OPTIONS_ALL = list(
    CoverageAssuranceResolution._mapping.values()
)


class DomainsChallenged(dict):
    """
    standardized mapping for `domains_challenged` items

    keep in sync with `AcmeChallengeType._mapping`
    """

    DEFAULT = AcmeChallengeType.DEFAULT

    def __init__(self, *args, **kwargs):
        if args or kwargs:
            raise ValueError("no args or kwargs")
        self["http-01"] = None
        self["dns-01"] = None
        self["tls-alpn-01"] = None

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


class KeyTechnology(_mixin_mapping):
    """
    What kind of Certificate/Key is this?
    """

    RSA = 1
    EC = 2  # ECDSA
    # DSA = 3

    _mapping = {
        1: "RSA",
        2: "EC",
        # 3: "DSA",
    }

    _options_AcmeAccount_private_key_technology_id = (
        1,
        2,
    )
    _DEFAULT_AcmeAccount = "RSA"
    _DEFAULT_AcmeAccount_id: int
    _DEFAULT_GlobalKey = "RSA"
    _DEFAULT_GlobalKey_id: int
    _options_AcmeAccount_private_key_technology: List[str]


KeyTechnology._options_AcmeAccount_private_key_technology = [
    KeyTechnology._mapping[_id]
    for _id in KeyTechnology._options_AcmeAccount_private_key_technology_id
]
KeyTechnology._DEFAULT_AcmeAccount_id = KeyTechnology.from_string(
    KeyTechnology._DEFAULT_AcmeAccount
)
KeyTechnology._DEFAULT_GlobalKey_id = KeyTechnology.from_string(
    KeyTechnology._DEFAULT_GlobalKey
)


class PrivateKeyCycle(_mixin_mapping):
    """
    How should a PrivateKey be cycled on renewal/queues?
    """

    _mapping = {
        1: "single_certificate",
        2: "account_daily",
        3: "global_daily",
        4: "account_weekly",
        5: "global_weekly",
        6: "account_key_default",  # use the options for the AcmeAcountKey
    }
    _options_AcmeAccount_private_key_cycle_id = (
        1,
        2,
        3,
        4,
        5,
    )
    _options_AcmeOrder_private_key_cycle_id = (
        1,
        2,
        3,
        4,
        5,
        6,
    )
    _DEFAULT_AcmeAccount = "single_certificate"
    _DEFAULT_AcmeOrder = "account_key_default"
    _DEFAULT_system_renewal = "single_certificate"

    _options_AcmeAccount_private_key_cycle: List[str]
    _options_AcmeOrder_private_key_cycle: List[str]


# compute this for ease of `curl` options
PrivateKeyCycle._options_AcmeAccount_private_key_cycle = [
    PrivateKeyCycle._mapping[_id]
    for _id in PrivateKeyCycle._options_AcmeAccount_private_key_cycle_id
]
PrivateKeyCycle._options_AcmeOrder_private_key_cycle = [
    PrivateKeyCycle._mapping[_id]
    for _id in PrivateKeyCycle._options_AcmeOrder_private_key_cycle_id
]


class PrivateKeySource(_mixin_mapping):
    """
    How was the PrivateKey generated?
    """

    _mapping = {
        0: "placeholder",  # application setup only
        2: "imported",
        1: "generated",
    }


class PrivateKeyStrategy(_mixin_mapping):
    """
    What is the strategy for associating the PrivateKey to the order?
    """

    _mapping = {
        1: "specified",
        2: "deferred-generate",  # generate a new PrivateKey when the order is made
        3: "deferred-associate",  # use the daily/weekly/account/per-certificate when the order is made
        4: "backup",  # if there is an issue using the intended PrivateKey, backup to a new one
    }
    _DEFAULT_system_renewal = "deferred-generate"


class PrivateKeyType(_mixin_mapping):
    """
    What kind of PrivateKey is this?
    """

    _mapping = {
        0: "placeholder",
        1: "standard",
        2: "single_certificate",
        3: "global_daily",
        4: "global_weekly",
        5: "account_daily",
        6: "account_weekly",
    }

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


class _mixin_OperationsEventType(object):
    operations_event_type_id: Mapped[int]

    @property
    def event_type_text(self) -> str:
        return OperationsEventType.as_string(self.operations_event_type_id)


#
# Consolidate the options for forms here, as they are often printed out for JSON endpoints
#


AcmeAccontKey_options_a = (
    "account_key_global_default",
    "account_key_existing",
    "account_key_file",
)


AcmeAccontKey_options_b = (
    "account_key_reuse",
    "account_key_global_default",
    "account_key_existing",
    "account_key_file",
)

AcmeAccontKey_options_c = (
    "account_key_reuse",
    "account_key_global_default",
    "account_key_existing",
    "account_key_file",
    "none",  # not the Python `None`
)


PrivateKey_options_a = (
    "private_key_existing",
    "private_key_file",
    "private_key_generate",
    "private_key_for_account_key",
)


PrivateKey_options_b = (
    "private_key_reuse",
    "private_key_existing",
    "private_key_file",
    "private_key_generate",
    "private_key_for_account_key",
)


PrivateKeySelection_2_PrivateKeyStrategy = {
    "upload": "specified",
    "existing": "specified",
    "reuse": "specified",
    "generate": "deferred-generate",
    "private_key_for_account_key": "deferred-associate",
}


PrivateKeyCycle_2_PrivateKeyStrategy = {
    "single_certificate": "deferred-generate",
    "account_daily": "deferred-associate",
    "global_daily": "deferred-associate",
    "account_weekly": "deferred-associate",
    "global_weekly": "deferred-associate",
    "account_key_default": "*lookup*",
}
