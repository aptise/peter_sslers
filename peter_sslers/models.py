# stdlib
import datetime
import json


# sqlalchemy
import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import (scoped_session,
                            sessionmaker,
                            )
from zope.sqlalchemy import ZopeTransactionExtension


"""
Coding Style:

    class Foo():
        columns
        relationships
        constraints
        properties/functions
"""


# ==============================================================================


DBSession = scoped_session(sessionmaker(extension=ZopeTransactionExtension(keep_session=True),))
Base = declarative_base()


# ==============================================================================


from sqlalchemy.sql import expression
from sqlalchemy.ext.compiler import compiles
import sqlalchemy.types


class year_week(expression.FunctionElement):
    type = sqlalchemy.types.String()
    name = 'year_week'


@compiles(year_week)
def year_week__default(element, compiler, **kw):
    # return compiler.visit_function(element)
    """
    ## select extract(week from timestamp_event) from table_a;
    week_num = sqlalchemy.sql.expression.extract('WEEK', LetsencryptServerCertificate.timestamp_signed)
    """
    args = list(element.clauses)
    return "concat(extract(year from %s), '.', extract(week from %s)) " % (
        compiler.process(args[0]),
        compiler.process(args[0]),
    )


@compiles(year_week, 'postgresql')
def year_week__postgresql(element, compiler, **kw):
    """
    # select to_char(timestamp_event, 'YYYY.WW')  from table_a;
    week_num = sqlalchemy.func.to_char(LetsencryptServerCertificate.timestamp_signed, 'YYYY.WW')
    """
    args = list(element.clauses)
    return "to_char(%s, 'YYYY.WW')" % (
        compiler.process(args[0]),
    )


@compiles(year_week, 'sqlite')
def year_week__sqlite(element, compiler, **kw):
    """
    # strftime('%Y.%W', cast(LetsencryptServerCertificate.timestamp_signed) as text)
    week_num = sqlalchemy.func.strftime('%Y.%W',
                                        sqlalchemy.cast(TABLE.COLUMN,
                                                        sqlalchemy.Unicode
                                                        )
                                        )
    """
    args = list(element.clauses)
    return "strftime('%%Y.%%W', %s)" % (
        compiler.process(args[0]),
    )


class utcnow(expression.FunctionElement):
    type = sqlalchemy.types.DateTime()


@compiles(utcnow)
def utcnow__default(element, compiler, **kw):
    # sqlite uses UTC by default
    return 'CURRENT_TIMESTAMP'


@compiles(utcnow, 'postgresql')
def utcnow__postgresql(element, compiler, **kw):
    return "TIMEZONE('utc', CURRENT_TIMESTAMP)"


# ==============================================================================


class LetsencryptAccountKey(Base):
    """
    Represents a registered account with the LetsEncrypt Service.
    This is used for authentication to the LE API, it is not tied to any certificates.
    """
    __tablename__ = 'letsencrypt_account_key'
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_first_seen = sa.Column(sa.DateTime, nullable=False, )
    key_pem = sa.Column(sa.Text, nullable=True, )
    key_pem_md5 = sa.Column(sa.Unicode(32), nullable=False, )
    key_pem_modulus_md5 = sa.Column(sa.Unicode(32), nullable=False, )
    count_certificate_requests = sa.Column(sa.Integer, nullable=True, default=0, )
    count_certificates_issued = sa.Column(sa.Integer, nullable=True, default=0, )
    timestamp_last_certificate_request = sa.Column(sa.DateTime, nullable=True, )
    timestamp_last_certificate_issue = sa.Column(sa.DateTime, nullable=True, )
    timestamp_last_authenticated = sa.Column(sa.DateTime, nullable=True, )
    is_active = sa.Column(sa.Boolean, nullable=False, default=True)
    is_default = sa.Column(sa.Boolean, nullable=True, default=None)

    certificate_requests = sa.orm.relationship("LetsencryptCertificateRequest",
                                               primaryjoin="LetsencryptAccountKey.id==LetsencryptCertificateRequest.letsencrypt_account_key_id",
                                               back_populates='letsencrypt_account_key',
                                               order_by='LetsencryptCertificateRequest.id.desc()',
                                               )

    issued_certificates = sa.orm.relationship("LetsencryptServerCertificate",
                                              primaryjoin="LetsencryptAccountKey.id==LetsencryptServerCertificate.letsencrypt_account_key_id",
                                              back_populates='letsencrypt_account_key',
                                              order_by='LetsencryptServerCertificate.id.desc()',
                                              )

    @property
    def key_pem_modulus_search(self):
        return "type=modulus&modulus=%s&source=account_key&account_key.id=%s" % (self.key_pem_modulus_md5, self.id, )


class LetsencryptCACertificate(Base):
    """
    These are trusted "Certificate Authority" Certificates from LetsEncrypt that are used to sign server certificates.
    These are directly tied to a ServerCertificate and are needed to create a "fullchain" certificate for most deployments.
    """
    __tablename__ = 'letsencrypt_ca_certificate'
    id = sa.Column(sa.Integer, primary_key=True)
    name = sa.Column(sa.Unicode(255), nullable=False)
    le_authority_name = sa.Column(sa.Unicode(255), nullable=True)
    is_ca_certificate = sa.Column(sa.Boolean, nullable=True, default=None)
    is_authority_certificate = sa.Column(sa.Boolean, nullable=True, default=None)
    is_cross_signed_authority_certificate = sa.Column(sa.Boolean, nullable=True, default=None)
    id_cross_signed_of = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_ca_certificate.id"), nullable=True)
    timestamp_first_seen = sa.Column(sa.DateTime, nullable=False, )
    cert_pem = sa.Column(sa.Text, nullable=False, )
    cert_pem_md5 = sa.Column(sa.Unicode(32), nullable=True)
    cert_pem_modulus_md5 = sa.Column(sa.Unicode(32), nullable=True)
    timestamp_signed = sa.Column(sa.DateTime, nullable=False, )
    timestamp_expires = sa.Column(sa.DateTime, nullable=False, )
    cert_subject = sa.Column(sa.Text, nullable=True, )
    cert_issuer = sa.Column(sa.Text, nullable=True, )
    cert_subject_hash = sa.Column(sa.Unicode(8), nullable=True)
    cert_issuer_hash = sa.Column(sa.Unicode(8), nullable=True)
    count_active_certificates = sa.Column(sa.Integer, nullable=True)

    @property
    def cert_pem_modulus_search(self):
        return "type=modulus&modulus=%s&source=ca_certificate&ca_certificate.id=%s" % (self.cert_pem_modulus_md5, self.id, )

    @property
    def cert_subject_hash_search(self):
        return "type=cert_subject_hash&cert_subject_hash=%s&source=ca_certificate&ca_certificate.id=%s" % (self.cert_subject_hash, self.id, )

    @property
    def cert_issuer_hash_search(self):
        return "type=cert_issuer_hash&cert_issuer_hash=%s&source=ca_certificate&ca_certificate.id=%s" % (self.cert_issuer_hash, self.id, )


class LetsencryptCertificateRequestType(object):
    """
    This package tracks two types of CSRs
    - Flow = handling the challenges from another client
    - Full = acting as the full LE Client
    """
    FLOW = 1
    FULL = 2


class LetsencryptCertificateRequest(Base):
    """
    A CertificateRequest is submitted to the LE signing authority.
    In goes your hope, out comes your dreams.

    The domains will be stored in 2 places:
    * LetsencryptCertificateRequest2LetsencryptDomain - an association table to store validation data
    * LetsencryptUniqueFQDNSet - the signing authority has a ratelimit on 'unique' sets of fully qualified domain names.
    """
    __tablename__ = 'letsencrypt_certificate_request'
    id = sa.Column(sa.Integer, primary_key=True)
    is_active = sa.Column(sa.Boolean, nullable=False, default=True)
    is_error = sa.Column(sa.Boolean, nullable=True, default=None)
    certificate_request_type_id = sa.Column(sa.Integer, nullable=False)  # 1=FLOW, 2=FULL; see LetsencryptCertificateRequest
    timestamp_started = sa.Column(sa.DateTime, nullable=False, )
    timestamp_finished = sa.Column(sa.DateTime, nullable=True, )

    csr_pem = sa.Column(sa.Text, nullable=True, )
    csr_pem_md5 = sa.Column(sa.Unicode(32), nullable=True, )
    csr_pem_modulus_md5 = sa.Column(sa.Unicode(32), nullable=True, )

    letsencrypt_private_key_id__signed_by = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_private_key.id"), nullable=True)
    letsencrypt_account_key_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_account_key.id"), nullable=True)

    letsencrypt_server_certificate_id__renewal_of = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_server_certificate.id"), nullable=True)

    letsencrypt_unique_fqdn_set_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_unique_fqdn_set.id"), nullable=False)

    certificate_request_to_domains = sa.orm.relationship("LetsencryptCertificateRequest2LetsencryptDomain",
                                                         primaryjoin="LetsencryptCertificateRequest.id==LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_certificate_request_id",
                                                         back_populates='certificate_request',
                                                         )

    private_key__signed_by = sa.orm.relationship("LetsencryptPrivateKey",
                                                 primaryjoin="LetsencryptCertificateRequest.letsencrypt_private_key_id__signed_by==LetsencryptPrivateKey.id",
                                                 back_populates='certificate_requests',
                                                 uselist=False,
                                                 )

    letsencrypt_account_key = sa.orm.relationship("LetsencryptAccountKey",
                                                  primaryjoin="LetsencryptCertificateRequest.letsencrypt_account_key_id==LetsencryptAccountKey.id",
                                                  back_populates='certificate_requests',
                                                  uselist=False,
                                                  )

    signed_certificate = sa.orm.relationship("LetsencryptServerCertificate",
                                             primaryjoin="LetsencryptCertificateRequest.id==LetsencryptServerCertificate.letsencrypt_certificate_request_id",
                                             back_populates='certificate_request',
                                             uselist=False,
                                             )

    certificate_renewal_of = sa.orm.relationship("LetsencryptServerCertificate",
                                                 primaryjoin="LetsencryptCertificateRequest.letsencrypt_server_certificate_id__renewal_of==LetsencryptServerCertificate.id",
                                                 back_populates='renewal_requests',
                                                 uselist=False,
                                                 )

    unique_fqdn_set = sa.orm.relationship("LetsencryptUniqueFQDNSet",
                                          primaryjoin="LetsencryptCertificateRequest.letsencrypt_unique_fqdn_set_id==LetsencryptUniqueFQDNSet.id",
                                          uselist=False,
                                          back_populates='certificate_requests',
                                          )

    check1 = sa.CheckConstraint("""(certificate_request_type_id = 1
                                    and (csr_pem is NULL and csr_pem_md5 is NULL and csr_pem_modulus_md5 is NULL)
                                    )
                                   or
                                   (certificate_request_type_id = 2
                                    and (csr_pem is NOT NULL and csr_pem_md5 is NOT NULL and csr_pem_modulus_md5 is NOT NULL)
                                    )""", name='check1')

    @property
    def csr_pem_modulus_search(self):
        return "type=modulus&modulus=%s&source=certificate_request&certificate_request.id=%s" % (self.csr_pem_modulus_md5, self.id, )

    @property
    def certificate_request_type(self):
        if self.certificate_request_type_id == LetsencryptCertificateRequestType.FLOW:
            return "Flow"
        elif self.certificate_request_type_id == LetsencryptCertificateRequestType.FULL:
            return "Full"
        raise ValueError("invalid `self.certificate_request_type_id`")

    def certificate_request_type_is(self, check):
        if (check.lower() == 'flow') and (self.certificate_request_type_id == LetsencryptCertificateRequestType.FLOW):
            return True
        elif (check.lower() == 'full') and (self.certificate_request_type_id == LetsencryptCertificateRequestType.FULL):
            return True
        return False

    @property
    def domains_as_string(self):
        domains = sorted([to_d.domain.domain_name for to_d in self.certificate_request_to_domains])
        return ', '.join(domains)

    @property
    def domains_as_list(self):
        domain_names = [to_d.domain.domain_name.lower() for to_d in self.certificate_request_to_domains]
        domain_names = list(set(domain_names))
        domain_names = sorted(domain_names)
        return domain_names


class LetsencryptCertificateRequest2LetsencryptDomain(Base):
    """
    The Domains in a CSR are stored in an association table because there is associated verification data.
    """
    __tablename__ = 'letsencrypt_certificate_request_2_letsencrypt_domain'
    letsencrypt_certificate_request_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_certificate_request.id"), primary_key=True)
    letsencrypt_domain_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_domain.id"), primary_key=True)
    timestamp_verified = sa.Column(sa.DateTime, nullable=True, )
    ip_verified = sa.Column(sa.Unicode(255), nullable=True, )
    challenge_key = sa.Column(sa.Unicode(255), nullable=True, )
    challenge_text = sa.Column(sa.Unicode(255), nullable=True, )

    certificate_request = sa.orm.relationship("LetsencryptCertificateRequest",
                                              primaryjoin="LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_certificate_request_id==LetsencryptCertificateRequest.id",
                                              uselist=False,
                                              back_populates='certificate_request_to_domains',
                                              )
    domain = sa.orm.relationship("LetsencryptDomain",
                                 primaryjoin="LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_domain_id==LetsencryptDomain.id",
                                 uselist=False,
                                 back_populates='domain_to_certificate_requests',
                                 )

    @property
    def is_configured(self):
        return True if (self.challenge_key and self.challenge_text) else False


class LetsencryptDomain(Base):
    """Domains that are included in CertificateRequests or Certificates
    """
    __tablename__ = 'letsencrypt_domain'
    id = sa.Column(sa.Integer, primary_key=True)
    domain_name = sa.Column(sa.Unicode(255), nullable=False)
    is_active = sa.Column(sa.Boolean, nullable=False, default=True)
    is_from_domain_queue = sa.Column(sa.Boolean, nullable=False, default=None)
    timestamp_first_seen = sa.Column(sa.DateTime, nullable=False, )

    letsencrypt_server_certificate_id__latest_single = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_server_certificate.id"), nullable=True)
    letsencrypt_server_certificate_id__latest_multi = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_server_certificate.id"), nullable=True)

    domain_to_certificate_requests = sa.orm.relationship("LetsencryptCertificateRequest2LetsencryptDomain",
                                                         primaryjoin="LetsencryptDomain.id==LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_domain_id",
                                                         back_populates='domain',
                                                         order_by='LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_certificate_request_id.desc()',
                                                         )

    latest_certificate_single = sa.orm.relationship("LetsencryptServerCertificate",
                                                    primaryjoin="LetsencryptDomain.letsencrypt_server_certificate_id__latest_single==LetsencryptServerCertificate.id",
                                                    uselist=False,
                                                    )

    latest_certificate_multi = sa.orm.relationship("LetsencryptServerCertificate",
                                                   primaryjoin="LetsencryptDomain.letsencrypt_server_certificate_id__latest_multi==LetsencryptServerCertificate.id",
                                                   uselist=False,
                                                   )

    to_fqdns = sa.orm.relationship("LetsencryptUniqueFQDNSet2LetsencryptDomain",
                                   primaryjoin="LetsencryptDomain.id==LetsencryptUniqueFQDNSet2LetsencryptDomain.letsencrypt_domain_id",
                                   back_populates="domain"
                                   )


class LetsencryptOperationsEventType(object):
    """
    This client tracks different types of events:
    """
    ca_certificate_probe = 1
    update_recents = 2
    deactivate_expired = 3
    deactivate_duplicate = 4
    redis_prime = 5
    nginx_cache_expire = 6
    nginx_cache_flush = 7
    certificate_mark = 8
    domain_mark = 9
    account_key_mark = 10
    private_key_mark = 11
    batch_queued_domains = 12
    private_key_revoke = 13
    queue_renewals = 14


class LetsencryptOperationsEvent(Base):
    """
    Certain events are tracked for bookkeeping
    """
    __tablename__ = 'letsencrypt_operations_event'
    id = sa.Column(sa.Integer, primary_key=True)
    letsencrypt_operations_event_type_id = sa.Column(sa.Integer, nullable=False)
    timestamp_operation = sa.Column(sa.DateTime, nullable=True, )
    event_payload = sa.Column(sa.Text, nullable=False, )
    letsencrypt_operations_event_id__child_of = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_operations_event.id"), nullable=True)

    @property
    def event_payload_json(self):
        if self._event_payload_json is None:
            self._event_payload_json = json.loads(self.event_payload)
        return self._event_payload_json
    _event_payload_json = None
    
    def set_event_payload(self, payload_dict):
        self.event_payload = json.dumps(payload_dict)

    @property
    def event_type_text(self):
        if self.letsencrypt_operations_event_type_id == 1:
            return 'ca_certificate_probe'
        elif self.letsencrypt_operations_event_type_id == 2:
            return 'update_recents'
        elif self.letsencrypt_operations_event_type_id == 3:
            return 'deactivate_expired'
        elif self.letsencrypt_operations_event_type_id == 4:
            return 'deactivate_duplicate'
        elif self.letsencrypt_operations_event_type_id == 5:
            return 'redis_prime'
        elif self.letsencrypt_operations_event_type_id == 6:
            return 'nginx_cache_expire'
        elif self.letsencrypt_operations_event_type_id == 7:
            return 'nginx_cache_flush'
        elif self.letsencrypt_operations_event_type_id == 8:
            return 'certificate_mark'
        elif self.letsencrypt_operations_event_type_id == 9:
            return 'domain_mark'
        elif self.letsencrypt_operations_event_type_id == 10:
            return 'account_key_mark'
        elif self.letsencrypt_operations_event_type_id == 11:
            return 'private_key_mark'
        elif self.letsencrypt_operations_event_type_id == 12:
            return 'batch_queued_domains'
        elif self.letsencrypt_operations_event_type_id == 13:
            return 'private_key_revoke'
        elif self.letsencrypt_operations_event_type_id == 14:
            return 'queue_renewals'
        return 'unknown'


class LetsencryptPrivateKey(Base):
    """
    These keys are used to sign CertificateRequests and are the PrivateKey component to a ServerCertificate.
    """
    __tablename__ = 'letsencrypt_private_key'
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_first_seen = sa.Column(sa.DateTime, nullable=False, )
    key_pem = sa.Column(sa.Text, nullable=True, )
    key_pem_md5 = sa.Column(sa.Unicode(32), nullable=False, )
    key_pem_modulus_md5 = sa.Column(sa.Unicode(32), nullable=False, )
    count_active_certificates = sa.Column(sa.Integer, nullable=True, )
    is_autogenerated_key = sa.Column(sa.Boolean, nullable=True, default=None)
    is_active = sa.Column(sa.Boolean, nullable=False, default=True)
    is_compromised = sa.Column(sa.Boolean, nullable=True, default=None)

    count_certificate_requests = sa.Column(sa.Integer, nullable=True, default=0, )
    count_certificates_issued = sa.Column(sa.Integer, nullable=True, default=0, )
    timestamp_last_certificate_request = sa.Column(sa.DateTime, nullable=True, )
    timestamp_last_certificate_issue = sa.Column(sa.DateTime, nullable=True, )

    certificate_requests = sa.orm.relationship("LetsencryptCertificateRequest",
                                               primaryjoin="LetsencryptPrivateKey.id==LetsencryptCertificateRequest.letsencrypt_private_key_id__signed_by",
                                               back_populates='private_key__signed_by',
                                               order_by='LetsencryptCertificateRequest.id.desc()',
                                               )
    signed_certificates = sa.orm.relationship("LetsencryptServerCertificate",
                                              primaryjoin="LetsencryptPrivateKey.id==LetsencryptServerCertificate.letsencrypt_private_key_id__signed_by",
                                              back_populates='private_key',
                                              order_by='LetsencryptServerCertificate.id.desc()',
                                              )

    @property
    def key_pem_modulus_search(self):
        return "type=modulus&modulus=%s&source=private_key&private_key.id=%s" % (self.key_pem_modulus_md5, self.id, )

    @property
    def autogenerated_key_year_week(self):
        if not self.is_autogenerated_key:
            return ''
        return "%s.%s" % self.timestamp_first_seen.isocalendar()[0:2]


class LetsencryptQueueDomain(Base):
    """
    A list of domains to be queued into certificates.
    This is only used for batch processing consumer domains
    Domains that are included in CertificateRequests or Certificates
    The DomainQueue will allow you to queue-up domain names for management
    """
    __tablename__ = 'letsencrypt_queue_domain'
    id = sa.Column(sa.Integer, primary_key=True)
    domain_name = sa.Column(sa.Unicode(255), nullable=False)
    timestamp_entered = sa.Column(sa.DateTime, nullable=False, )
    timestamp_processed = sa.Column(sa.DateTime, nullable=True, )
    letsencrypt_domain_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_domain.id"), nullable=True)

    domain = sa.orm.relationship(
        "LetsencryptDomain",
        primaryjoin="LetsencryptQueueDomain.letsencrypt_domain_id==LetsencryptDomain.id",
        uselist=False,
    )


class LetsencryptQueueRenewal(Base):
    """
    An item to be renewed.
    If something is expired, it will be placed here for renewal
    """
    __tablename__ = 'letsencrypt_queue_renewal'
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_entered = sa.Column(sa.DateTime, nullable=False, )
    letsencrypt_server_certificate_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_server_certificate.id"), nullable=False)
    letsencrypt_operations_event_id__child_of = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_operations_event.id"), nullable=True)
    timestamp_processed = sa.Column(sa.DateTime, nullable=True, )
    process_result = sa.Column(sa.Boolean, nullable=True, default=None)
    letsencrypt_unique_fqdn_set_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_unique_fqdn_set.id"), nullable=False)

    certificate = sa.orm.relationship(
        "LetsencryptServerCertificate",
        primaryjoin="LetsencryptQueueRenewal.letsencrypt_server_certificate_id==LetsencryptServerCertificate.id",
        uselist=False,
    )
    operations_event = sa.orm.relationship(
        "LetsencryptOperationsEvent",
        primaryjoin="LetsencryptQueueRenewal.letsencrypt_operations_event_id__child_of==LetsencryptOperationsEvent.id",
        uselist=False,
    )
    unique_fqdn_set = sa.orm.relationship("LetsencryptUniqueFQDNSet",
                                          primaryjoin="LetsencryptQueueRenewal.letsencrypt_unique_fqdn_set_id==LetsencryptUniqueFQDNSet.id",
                                          uselist=False,
                                          back_populates='renewal_queue',
                                          )


class LetsencryptServerCertificate(Base):
    """
    A signed ServerCertificate.
    To install on a webserver, must be paired with the PrivateKey and Trusted CA Certificate.

    The domains will be stored in:
    * LetsencryptUniqueFQDNSet - the signing authority has a ratelimit on 'unique' sets of fully qualified domain names.
    """
    __tablename__ = 'letsencrypt_server_certificate'
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_signed = sa.Column(sa.DateTime, nullable=False, )
    timestamp_expires = sa.Column(sa.DateTime, nullable=False, )
    is_active = sa.Column(sa.Boolean, nullable=False, default=True)
    is_single_domain_cert = sa.Column(sa.Boolean, nullable=True, default=None)
    cert_pem = sa.Column(sa.Text, nullable=False, )
    cert_pem_md5 = sa.Column(sa.Unicode(32), nullable=False, )
    cert_pem_modulus_md5 = sa.Column(sa.Unicode(32), nullable=False, )

    cert_subject = sa.Column(sa.Text, nullable=True, )
    cert_issuer = sa.Column(sa.Text, nullable=True, )
    cert_subject_hash = sa.Column(sa.Unicode(8), nullable=True)
    cert_issuer_hash = sa.Column(sa.Unicode(8), nullable=True)
    is_deactivated = sa.Column(sa.Boolean, nullable=True, default=None)
    is_revoked = sa.Column(sa.Boolean, nullable=True, default=None)

    letsencrypt_unique_fqdn_set_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_unique_fqdn_set.id"), nullable=False)

    # this is the LetsEncrypt key
    letsencrypt_ca_certificate_id__upchain = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_ca_certificate.id"), nullable=False)

    # this is the private key
    letsencrypt_private_key_id__signed_by = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_private_key.id"), nullable=False)

    # this is the account key, if a LetsEncrypt issue.  this could be null
    letsencrypt_account_key_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_account_key.id"), nullable=True)

    # tracking
    letsencrypt_certificate_request_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_certificate_request.id"), nullable=True)
    letsencrypt_server_certificate_id__renewal_of = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_server_certificate.id"), nullable=True)

    private_key = sa.orm.relationship("LetsencryptPrivateKey",
                                      primaryjoin="LetsencryptServerCertificate.letsencrypt_private_key_id__signed_by==LetsencryptPrivateKey.id",
                                      back_populates='signed_certificates',
                                      uselist=False,
                                      )

    certificate_request = sa.orm.relationship("LetsencryptCertificateRequest",
                                              primaryjoin="LetsencryptServerCertificate.letsencrypt_certificate_request_id==LetsencryptCertificateRequest.id",
                                              back_populates='signed_certificate',
                                              uselist=False,
                                              )

    certificate_upchain = sa.orm.relationship("LetsencryptCACertificate",
                                              primaryjoin="LetsencryptServerCertificate.letsencrypt_ca_certificate_id__upchain==LetsencryptCACertificate.id",
                                              uselist=False,
                                              )

    letsencrypt_account_key = sa.orm.relationship("LetsencryptAccountKey",
                                                  primaryjoin="LetsencryptServerCertificate.letsencrypt_account_key_id==LetsencryptAccountKey.id",
                                                  back_populates='issued_certificates',
                                                  uselist=False,
                                                  )

    renewal_requests = sa.orm.relationship("LetsencryptCertificateRequest",
                                           primaryjoin="LetsencryptServerCertificate.id==LetsencryptCertificateRequest.letsencrypt_server_certificate_id__renewal_of",
                                           back_populates='certificate_renewal_of',
                                           )

    unique_fqdn_set = sa.orm.relationship("LetsencryptUniqueFQDNSet",
                                          primaryjoin="LetsencryptServerCertificate.letsencrypt_unique_fqdn_set_id==LetsencryptUniqueFQDNSet.id",
                                          uselist=False,
                                          back_populates='certificates',
                                          )

    renewal_queue = sa.orm.relationship("LetsencryptQueueRenewal",
                                         primaryjoin="LetsencryptServerCertificate.id==LetsencryptQueueRenewal.letsencrypt_server_certificate_id",
                                         back_populates='certificate',
                                         )

    @property
    def cert_pem_modulus_search(self):
        return "type=modulus&modulus=%s&source=certificate&certificate.id=%s" % (self.cert_pem_modulus_md5, self.id, )

    @property
    def cert_subject_hash_search(self):
        return "type=cert_subject_hash&cert_subject_hash=%s&source=certificate&certificate.id=%s" % (self.cert_subject_hash, self.id, )

    @property
    def cert_issuer_hash_search(self):
        return "type=cert_issuer_hash&cert_issuer_hash=%s&source=certificate&certificate.id=%s" % (self.cert_issuer_hash, self.id, )

    @property
    def cert_fullchain_pem(self):
        return '\n'.join((self.cert_pem, self.certificate_upchain.cert_pem))

    @property
    def expiring_days(self):
        if self._expiring_days is None:
            self._expiring_days = (self.timestamp_expires - datetime.datetime.utcnow()).days
        return self._expiring_days
    _expiring_days = None

    @property
    def expiring_days_label(self):
        if self.is_active:
            if self.expiring_days <= 0:
                return 'danger'
            elif self.expiring_days <= 30:
                return 'warning'
            elif self.expiring_days > 30:
                return 'success'
        return 'danger'

    @property
    def config_payload(self):
        # the ids are strings so that the fullchain id can be split by a client without further processing
        return {'id': str(self.id),
                'private_key': {'id': str(self.private_key.id),
                                'pem': self.private_key.key_pem,
                                },
                'certificate': {'id': str(self.id),
                                'pem': self.cert_pem,
                                },
                'chain': {'id': str(self.certificate_upchain.id),
                          'pem': self.certificate_upchain.cert_pem,
                          },
                'fullchain': {'id': '%s,%s' % (self.id, self.certificate_upchain.id),
                              'pem': "\n".join([self.cert_fullchain_pem]),
                              },
                }

    @property
    def config_payload_idonly(self):
        # the ids are strings so that the fullchain id can be split by a client without further processing
        return {'id': str(self.id),
                'private_key': {'id': str(self.private_key.id),
                                },
                'certificate': {'id': str(self.id),
                                },
                'chain': {'id': str(self.certificate_upchain.id),
                          },
                'fullchain': {'id': '%s,%s' % (self.id, self.certificate_upchain.id),
                              },
                }

    @property
    def can_quick_renew(self):
        """only allow renewable of LE certificates"""
        if self.letsencrypt_account_key_id:
            return True
        return False

    @property
    def domains_as_string(self):
        domains = sorted([to_d.domain.domain_name for to_d in self.unique_fqdn_set.to_domains])
        return ', '.join(domains)

    @property
    def domains_as_list(self):
        domain_names = [to_d.domain.domain_name.lower() for to_d in self.unique_fqdn_set.to_domains]
        domain_names = list(set(domain_names))
        domain_names = sorted(domain_names)
        return domain_names


class LetsencryptUniqueFQDNSet(Base):
    """
    There is a ratelimit in effect from LetsEncrypt for unique sets of fully-qualified domain names
    * `domain_ids_string` should be a unique list of ordered ids, separated by commas.
    * the association table is used to actually join domains to Certificates and CSRs
    #RATELIMIT.FQDN
    """
    __tablename__ = 'letsencrypt_unique_fqdn_set'
    id = sa.Column(sa.Integer, primary_key=True)
    domain_ids_string = sa.Column(sa.Text, nullable=False, )
    timestamp_first_seen = sa.Column(sa.DateTime, nullable=False, )

    to_domains = sa.orm.relationship("LetsencryptUniqueFQDNSet2LetsencryptDomain",
                                     primaryjoin="LetsencryptUniqueFQDNSet.id==LetsencryptUniqueFQDNSet2LetsencryptDomain.letsencrypt_unique_fqdn_set_id",
                                     back_populates='unique_fqdn_set',
                                     )

    certificates = sa.orm.relationship("LetsencryptServerCertificate",
                                       primaryjoin="LetsencryptUniqueFQDNSet.id==LetsencryptServerCertificate.letsencrypt_unique_fqdn_set_id",
                                       back_populates='unique_fqdn_set',
                                       )

    certificate_requests = sa.orm.relationship("LetsencryptCertificateRequest",
                                               primaryjoin="LetsencryptUniqueFQDNSet.id==LetsencryptCertificateRequest.letsencrypt_unique_fqdn_set_id",
                                               back_populates='unique_fqdn_set',
                                               )

    renewal_queue = sa.orm.relationship("LetsencryptQueueRenewal",
                                          primaryjoin="LetsencryptUniqueFQDNSet.id==LetsencryptQueueRenewal.letsencrypt_unique_fqdn_set_id",
                                          back_populates='unique_fqdn_set',
                                          )


class LetsencryptUniqueFQDNSet2LetsencryptDomain(Base):
    """
    #RATELIMIT.FQDN
    association table
    """
    __tablename__ = 'letsencrypt_unique_fqdn_set_2_letsencrypt_domain'
    letsencrypt_unique_fqdn_set_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_unique_fqdn_set.id"), primary_key=True)
    letsencrypt_domain_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_domain.id"), primary_key=True)

    unique_fqdn_set = sa.orm.relationship("LetsencryptUniqueFQDNSet",
                                          primaryjoin="LetsencryptUniqueFQDNSet2LetsencryptDomain.letsencrypt_unique_fqdn_set_id==LetsencryptUniqueFQDNSet.id",
                                          uselist=False,
                                          back_populates='to_domains',
                                          )

    domain = sa.orm.relationship("LetsencryptDomain",
                                 primaryjoin="LetsencryptUniqueFQDNSet2LetsencryptDomain.letsencrypt_domain_id==LetsencryptDomain.id",
                                 uselist=False,
                                 )


# ==============================================================================


# advanced relationships


LetsencryptAccountKey.certificate_requests_5 = sa.orm.relationship(
    LetsencryptCertificateRequest,
    primaryjoin=(
        sa.and_(LetsencryptAccountKey.id == LetsencryptCertificateRequest.letsencrypt_account_key_id,
                LetsencryptCertificateRequest.id.in_(sa.select([LetsencryptCertificateRequest.id])
                                                     .where(LetsencryptAccountKey.id == LetsencryptCertificateRequest.letsencrypt_account_key_id)
                                                     .order_by(LetsencryptCertificateRequest.id.desc())
                                                     .limit(5)
                                                     .correlate()
                                                     )
                )
    ),
    order_by=LetsencryptCertificateRequest.id.desc(),
    viewonly=True
)


LetsencryptAccountKey.issued_certificates_5 = sa.orm.relationship(
    LetsencryptServerCertificate,
    primaryjoin=(
        sa.and_(LetsencryptAccountKey.id == LetsencryptServerCertificate.letsencrypt_account_key_id,
                LetsencryptServerCertificate.id.in_(sa.select([LetsencryptServerCertificate.id])
                                                    .where(LetsencryptAccountKey.id == LetsencryptServerCertificate.letsencrypt_account_key_id)
                                                    .order_by(LetsencryptServerCertificate.id.desc())
                                                    .limit(5)
                                                    .correlate()
                                                    )
                )
    ),
    order_by=LetsencryptServerCertificate.id.desc(),
    viewonly=True
)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


LetsencryptPrivateKey.certificate_requests_5 = sa.orm.relationship(
    LetsencryptCertificateRequest,
    primaryjoin=(
        sa.and_(LetsencryptPrivateKey.id == LetsencryptCertificateRequest.letsencrypt_private_key_id__signed_by,
                LetsencryptCertificateRequest.id.in_(sa.select([LetsencryptCertificateRequest.id])
                                                     .where(LetsencryptPrivateKey.id == LetsencryptCertificateRequest.letsencrypt_private_key_id__signed_by)
                                                     .order_by(LetsencryptCertificateRequest.id.desc())
                                                     .limit(5)
                                                     .correlate()
                                                     )
                )
    ),
    order_by=LetsencryptCertificateRequest.id.desc(),
    viewonly=True
)


LetsencryptPrivateKey.signed_certificates_5 = sa.orm.relationship(
    LetsencryptServerCertificate,
    primaryjoin=(
        sa.and_(LetsencryptPrivateKey.id == LetsencryptServerCertificate.letsencrypt_private_key_id__signed_by,
                LetsencryptServerCertificate.id.in_(sa.select([LetsencryptServerCertificate.id])
                                                    .where(LetsencryptPrivateKey.id == LetsencryptServerCertificate.letsencrypt_private_key_id__signed_by)
                                                    .order_by(LetsencryptServerCertificate.id.desc())
                                                    .limit(5)
                                                    .correlate()
                                                    )
                )
    ),
    order_by=LetsencryptServerCertificate.id.desc(),
    viewonly=True
)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


LetsencryptDomain.domain_to_certificate_requests_5 = sa.orm.relationship(
    LetsencryptCertificateRequest2LetsencryptDomain,
    primaryjoin=(
        sa.and_(
            LetsencryptDomain.id == LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_domain_id,
                LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_certificate_request_id.in_(
                    sa.select([LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_certificate_request_id])
                    .where(LetsencryptDomain.id == LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_domain_id)
                    .order_by(LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_certificate_request_id.desc())
                    .limit(5)
                    .correlate()
                )
        )
    ),
    order_by=LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_certificate_request_id.desc(),
    viewonly=True
)


# returns an object with a `certificate` on it
LetsencryptDomain.certificates_5 = sa.orm.relationship(
    "LetsencryptServerCertificate",
    secondary=(  """join(LetsencryptUniqueFQDNSet2LetsencryptDomain,
                         LetsencryptServerCertificate,
                         LetsencryptUniqueFQDNSet2LetsencryptDomain.letsencrypt_unique_fqdn_set_id == LetsencryptServerCertificate.letsencrypt_unique_fqdn_set_id
                  )"""),
    primaryjoin="LetsencryptDomain.id == LetsencryptUniqueFQDNSet2LetsencryptDomain.letsencrypt_domain_id",
    secondaryjoin=(
        sa.and_(
            LetsencryptServerCertificate.letsencrypt_unique_fqdn_set_id == sa.orm.foreign(LetsencryptUniqueFQDNSet2LetsencryptDomain.letsencrypt_unique_fqdn_set_id),
            LetsencryptServerCertificate.id.in_(
                sa.select([LetsencryptServerCertificate.id])
                .where(LetsencryptServerCertificate.letsencrypt_unique_fqdn_set_id == LetsencryptUniqueFQDNSet2LetsencryptDomain.letsencrypt_unique_fqdn_set_id)
                .where(LetsencryptUniqueFQDNSet2LetsencryptDomain.letsencrypt_domain_id == LetsencryptDomain.id)
                .order_by(LetsencryptServerCertificate.id.desc())
                .limit(5)
                .correlate()
            )
        )
    ),
    order_by=LetsencryptServerCertificate.id.desc(),
    viewonly=True
)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


LetsencryptUniqueFQDNSet.certificate_requests_5 = sa.orm.relationship(
    LetsencryptCertificateRequest,
    primaryjoin=(
        sa.and_(LetsencryptUniqueFQDNSet.id == LetsencryptCertificateRequest.letsencrypt_unique_fqdn_set_id,
                LetsencryptCertificateRequest.id.in_(sa.select([LetsencryptCertificateRequest.id])
                                                     .where(LetsencryptUniqueFQDNSet.id == LetsencryptCertificateRequest.letsencrypt_unique_fqdn_set_id)
                                                     .order_by(LetsencryptCertificateRequest.id.desc())
                                                     .limit(5)
                                                     .correlate()
                                                     )
                )
    ),
    order_by=LetsencryptCertificateRequest.id.desc(),
    viewonly=True
)


LetsencryptUniqueFQDNSet.signed_certificates_5 = sa.orm.relationship(
    LetsencryptServerCertificate,
    primaryjoin=(
        sa.and_(LetsencryptUniqueFQDNSet.id == LetsencryptServerCertificate.letsencrypt_unique_fqdn_set_id,
                LetsencryptServerCertificate.id.in_(sa.select([LetsencryptServerCertificate.id])
                                                    .where(LetsencryptUniqueFQDNSet.id == LetsencryptServerCertificate.letsencrypt_unique_fqdn_set_id)
                                                    .order_by(LetsencryptServerCertificate.id.desc())
                                                    .limit(5)
                                                    .correlate()
                                                    )
                )
    ),
    order_by=LetsencryptServerCertificate.id.desc(),
    viewonly=True
)


LetsencryptUniqueFQDNSet.latest_certificate = sa.orm.relationship(
    LetsencryptServerCertificate,
    primaryjoin=(
        sa.and_(LetsencryptUniqueFQDNSet.id == LetsencryptServerCertificate.letsencrypt_unique_fqdn_set_id,
                LetsencryptServerCertificate.id.in_(sa.select([sa.func.max(LetsencryptServerCertificate.id)])
                                                    .where(LetsencryptUniqueFQDNSet.id == LetsencryptServerCertificate.letsencrypt_unique_fqdn_set_id)
                                                    .correlate()
                                                    )
                )
    ),
    viewonly=True,
    uselist=False,
)
LetsencryptUniqueFQDNSet.latest_active_certificate = sa.orm.relationship(
    LetsencryptServerCertificate,
    primaryjoin=(
        sa.and_(LetsencryptUniqueFQDNSet.id == LetsencryptServerCertificate.letsencrypt_unique_fqdn_set_id,
                LetsencryptServerCertificate.id.in_(sa.select([sa.func.max(LetsencryptServerCertificate.id)])
                                                    .where(LetsencryptUniqueFQDNSet.id == LetsencryptServerCertificate.letsencrypt_unique_fqdn_set_id)
                                                    .where(LetsencryptServerCertificate.is_active.op('IS')(True))
                                                    .correlate()
                                                    )
                )
    ),
    viewonly=True,
    uselist=False,
)

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
