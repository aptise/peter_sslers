import sqlalchemy.types
from sqlalchemy.sql import expression
from sqlalchemy.ext.compiler import compiles


# ==============================================================================


class year_week(expression.FunctionElement):
    type = sqlalchemy.types.String()
    name = "year_week"


@compiles(year_week)
def year_week__default(element, compiler, **kw):
    # return compiler.visit_function(element)
    """
    ## select extract(week from timestamp_event) from table_a;
    week_num = sqlalchemy.sql.expression.extract('WEEK', ServerCertificate.timestamp_signed)
    """
    args = list(element.clauses)
    return "concat(extract(year from %s), '.', extract(week from %s)) " % (
        compiler.process(args[0]),
        compiler.process(args[0]),
    )


@compiles(year_week, "postgresql")
def year_week__postgresql(element, compiler, **kw):
    """
    # select to_char(timestamp_event, 'YYYY.WW')  from table_a;
    week_num = sqlalchemy.func.to_char(ServerCertificate.timestamp_signed, 'YYYY.WW')
    """
    args = list(element.clauses)
    return "to_char(%s, 'YYYY.WW')" % (compiler.process(args[0]),)


@compiles(year_week, "sqlite")
def year_week__sqlite(element, compiler, **kw):
    """
    # strftime('%Y.%W', cast(ServerCertificate.timestamp_signed) as text)
    week_num = sqlalchemy.func.strftime('%Y.%W',
                                        sqlalchemy.cast(TABLE.COLUMN,
                                                        sqlalchemy.Unicode
                                                        )
                                        )
    """
    args = list(element.clauses)
    return "strftime('%%Y.%%W', %s)" % (compiler.process(args[0]),)


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
def min_date__postgresql(element, compiler, **kw):
    """
    # select least(col_a, col_b);
    """
    args = list(element.clauses)
    return "LEAST(%s, %s)" % (compiler.process(args[0]), compiler.process(args[1]))


@compiles(min_date, "sqlite")
def min_date__sqlite(element, compiler, **kw):
    """
    # select min(col_a, col_b);
    """
    args = list(element.clauses)
    return "min(%s, %s)" % (compiler.process(args[0]), compiler.process(args[1]))


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class utcnow(expression.FunctionElement):
    type = sqlalchemy.types.DateTime()


@compiles(utcnow)
def utcnow__default(element, compiler, **kw):
    # sqlite uses UTC by default
    return "CURRENT_TIMESTAMP"


@compiles(utcnow, "postgresql")
def utcnow__postgresql(element, compiler, **kw):
    return "TIMEZONE('utc', CURRENT_TIMESTAMP)"


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class _mixin_mapping(object):
    """handles a mapping of db codes/constants
    """

    _mapping = None
    _mapping_reverse = None

    @classmethod
    def as_string(cls, mapping_id):
        if mapping_id in cls._mapping:
            return cls._mapping[mapping_id]
        return "unknown"

    @classmethod
    def from_string(cls, mapping_text):
        if cls._mapping_reverse is None:
            cls._mapping_reverse = {v: k for k, v in cls._mapping.items()}
        return cls._mapping_reverse[mapping_text]


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class _OperationsUnified(_mixin_mapping):
    """
    unified constants
    """

    _mapping = {
        110: "acme_account_key__insert",
        120: "acme_account_key__authenticate",
        130: "acme_account_key__mark",
        131: "acme_account_key__mark__active",
        132: "acme_account_key__mark__inactive",
        133: "acme_account_key__mark__default",
        134: "acme_account_key__mark__notdefault",
        200: "ca_certificate__probe",
        210: "ca_certificate__insert",
        220: "ca_certificate__upload_bundle",
        310: "private_key__insert",
        320: "private_key__mark",
        321: "private_key__mark__active",
        322: "private_key__mark__inactive",
        323: "private_key__mark__compromised",
        324: "private_key__mark__default",
        325: "private_key__mark__notdefault",
        330: "private_key__revoke",
        340: "private_key__insert_autogenerated",
        410: "domain__insert",
        420: "domain__mark",
        421: "domain__mark__active",
        422: "domain__mark__inactive",
        510: "unqiue_fqdn__insert",
        610: "certificate_request__insert",
        620: "certificate_request__new",
        630: "certificate_request__new__flow",
        640: "certificate_request__new__automated",
        650: "certificate_request__do__automated",
        710: "certificate__insert",
        720: "certificate__mark",
        721: "certificate__mark__active",
        722: "certificate__mark__inactive",
        723: "certificate__mark__revoked",
        724: "certificate__mark__renew_auto",
        725: "certificate__mark__renew_manual",
        726: "certificate__mark__unrevoked",
        730: "certificate__renew",
        740: "certificate__revoke",
        751: "certificate__deactivate_expired",
        752: "certificate__deactivate_duplicate",
        810: "queue_domain__add",
        811: "queue_domain__add__success",
        812: "queue_domain__add__already_queued",
        813: "queue_domain__add__already_exists",
        814: "queue_domain__add__already_exists_activate",
        820: "queue_domain__process",
        821: "queue_domain__process__success",
        822: "queue_domain__process__fail",
        830: "queue_domain__mark",
        831: "queue_domain__mark__cancelled",
        832: "queue_domain__mark__already_processed",
        910: "queue_renewal__insert",
        920: "queue_renewal__update",
        930: "queue_renewal__mark",
        931: "queue_renewal__mark__cancelled",
        940: "queue_renewal__process",
        941: "queue_renewal__process__success",
        942: "queue_renewal__process__fail",
        1002: "operations__update_recents",
        1005: "operations__redis_prime",
        1006: "operations__nginx_cache_expire",
        1007: "operations__nginx_cache_flush",
        2001: "api_domains__enable",
        2002: "api_domains__disable",
        2010: "api_domains__certificate_if_needed",
        2011: "api_domains__certificate_if_needed__domain_exists",
        2012: "api_domains__certificate_if_needed__domain_activate",
        2013: "api_domains__certificate_if_needed__domain_new",
        2015: "api_domains__certificate_if_needed__certificate_exists",
        2016: "api_domains__certificate_if_needed__certificate_new_success",
        2017: "api_domains__certificate_if_needed__certificate_new_fail",
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


class AcmeAccountProvider:
    """
    Used for Acme Logging, API setup, etc
    """

    registry = {
        0: {
            "id": 0,
            "name": "custom",
            "endpoint": None,
            "is_default": None,
            "protocol": None,
            "directory": None,
        },
        #  1: {
        #     "id": 1,
        #     "name": "letsencrypt-v1",
        #     "endpoint": "https://acme-v01.api.letsencrypt.org",
        #     "directory": None,
        #     "is_default": None,
        #     "protocol": "acme-v1",
        # },
        # 2: {
        #     "id": 2,
        #     "name": "letsencrypt-v1-staging",
        #     "endpoint": "https://acme-staging.api.letsencrypt.org",
        #     "directory": None,
        #     "is_default": None,
        #     "protocol": "acme-v1",
        # },
        3: {
            "id": 3,
            "name": "letsencrypt-v2",
            "endpoint": "https://acme-v02.api.letsencrypt.org",
            "directory": "https://acme-v02.api.letsencrypt.org/directory",
            "is_default": None,
            "protocol": "acme-v2",
        },
        4: {
            "id": 4,
            "name": "letsencrypt-v2-staging",
            "endpoint": "https://acme-staging-v02.api.letsencrypt.org",
            "directory": "https://acme-staging-v02.api.letsencrypt.org/directory",
            "is_default": None,
            "protocol": "acme-v2",
        },
    }


class Acme_Status_Authorization(_mixin_mapping):
    """The status of an authorization"""

    DEFAULT_ID = 0
    OPTIONS_DEACTIVATE = ("pending", "valid", "*discovered*")

    _mapping = {
        0: "*discovered*",  # not an ACME status, but our internal marker
        1: "pending",
        2: "valid",
        3: "invalid",
        4: "deactivated",
        5: "expired",
        6: "revoked",
        404: "*404*",  # not found on server
    }


class Acme_Status_Challenge(_mixin_mapping):
    """The status of a challenge"""

    DEFAULT_ID = 0

    _mapping = {
        0: "*discovered*",  # not an ACME status, but our internal marker
        1: "pending",
        2: "processing",
        3: "valid",
        4: "invalid",
        404: "*404*",  # not found on server
    }


class Acme_Status_Order(_mixin_mapping):
    """The status of an order"""

    DEFAULT_ID = 0
    OPTIONS_X_ACME_SYNC = ("valid",)
    OPTIONS_X_MARK_INVALID = (
        "invalid",
        "valid",
    )
    OPTIONS_X_DEACTIVATE_AUTHORIZATIONS = (
        "valid",
        "*404*",
    )

    _mapping = {
        0: "*discovered*",  # not an ACME status, but our internal marker
        1: "pending",
        2: "ready",
        3: "processing",
        4: "valid",
        5: "invalid",
        404: "*404*",  # not found on server
    }


class AcmeChallengeType(_mixin_mapping):
    """
    Used for Acme Logging
    """

    _mapping = {1: "http-01", 2: "dns-01"}


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
    }


class CertificateRequestSource(_mixin_mapping):
    """
    How was the CertificateRequest generated?
    - RECORDED - just records the CSR; uploaded into our system
    - ACME_FLOW - Creates a flow
    - ACME_AUTOMATED = acting as the full LE Client
    """

    RECORDED = 1
    ACME_FLOW = 2
    ACME_AUTOMATED = 3

    _mapping = {1: "RECORDED", 2: "ACME_FLOW", 3: "ACME_AUTOMATED"}


class _mixin_OperationsEventType(object):
    @property
    def event_type_text(self):
        return OperationsEventType.as_string(self.operations_event_type_id)
