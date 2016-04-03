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


DBSession = scoped_session(sessionmaker(extension=ZopeTransactionExtension()))
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


# ==============================================================================


class LetsencryptAccountKey(Base):
    """
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
    Tracking official LetsEncrypt certificates.
    These are tracked to a fullchain can be created
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
    FLOW = 1
    FULL = 2


class LetsencryptCertificateRequest(Base):
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

    certificate_request_to_domains = sa.orm.relationship("LetsencryptCertificateRequest2LetsencryptDomain",
                                                         primaryjoin="LetsencryptCertificateRequest.id==LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_certificate_request_id",
                                                         back_populates='certificate_request',
                                                         )

    letsencrypt_private_key__signed_by = sa.orm.relationship("LetsencryptPrivateKey",
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
    """
    """
    __tablename__ = 'letsencrypt_domain'
    id = sa.Column(sa.Integer, primary_key=True)
    domain_name = sa.Column(sa.Unicode(255), nullable=False)

    letsencrypt_server_certificate_id__latest_single = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_server_certificate.id"), nullable=True)
    letsencrypt_server_certificate_id__latest_multi = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_server_certificate.id"), nullable=True)

    domain_to_certificate_requests = sa.orm.relationship("LetsencryptCertificateRequest2LetsencryptDomain",
                                                         primaryjoin="LetsencryptDomain.id==LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_domain_id",
                                                         back_populates='domain',
                                                         order_by='LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_certificate_request_id.desc()',
                                                         )
    domain_to_certificates = sa.orm.relationship("LetsencryptServerCertificate2LetsencryptDomain",
                                                 primaryjoin="LetsencryptDomain.id==LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id",
                                                 back_populates='domain',
                                                 order_by='LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_server_certificate_id.desc()',
                                                 )

    latest_certificate_single = sa.orm.relationship("LetsencryptServerCertificate",
                                                    primaryjoin="LetsencryptDomain.letsencrypt_server_certificate_id__latest_single==LetsencryptServerCertificate.id",
                                                    uselist=False,
                                                    )
    latest_certificate_multi = sa.orm.relationship("LetsencryptServerCertificate",
                                                   primaryjoin="LetsencryptDomain.letsencrypt_server_certificate_id__latest_multi==LetsencryptServerCertificate.id",
                                                   uselist=False,
                                                   )


class LetsencryptOperationsEventType(object):
    ca_certificate_probe = 1
    update_recents = 2
    deactivate_expired = 3
    deactivate_duplicate = 4
    redis_prime = 5
    nginx_cache_expire = 6
    nginx_cache_flush = 7


class LetsencryptOperationsEvent(Base):
    """
    Tracking official LetsEncrypt certificates.
    These are tracked to a fullchain can be created
    """
    __tablename__ = 'letsencrypt_sync_event'
    id = sa.Column(sa.Integer, primary_key=True)
    letsencrypt_operations_event_type_id = sa.Column(sa.Integer, nullable=False)
    timestamp_operation = sa.Column(sa.DateTime, nullable=True, )
    event_payload = sa.Column(sa.Text, nullable=False, )
    letsencrypt_sync_event_id_child_of = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_sync_event.id"), nullable=True)

    @property
    def event_payload_json(self):
        if self._event_payload_json is None:
            self._event_payload_json = json.loads(self.event_payload)
        return self._event_payload_json
    _event_payload_json = None

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
        return 'unknown'


class LetsencryptPrivateKey(Base):
    """
    Tracking the certs we use to sign requests
    """
    __tablename__ = 'letsencrypt_private_key'
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_first_seen = sa.Column(sa.DateTime, nullable=False, )
    key_pem = sa.Column(sa.Text, nullable=True, )
    key_pem_md5 = sa.Column(sa.Unicode(32), nullable=False, )
    key_pem_modulus_md5 = sa.Column(sa.Unicode(32), nullable=False, )
    count_active_certificates = sa.Column(sa.Integer, nullable=True, )

    count_certificate_requests = sa.Column(sa.Integer, nullable=True, default=0, )
    count_certificates_issued = sa.Column(sa.Integer, nullable=True, default=0, )
    timestamp_last_certificate_request = sa.Column(sa.DateTime, nullable=True, )
    timestamp_last_certificate_issue = sa.Column(sa.DateTime, nullable=True, )

    certificate_requests = sa.orm.relationship("LetsencryptCertificateRequest",
                                               primaryjoin="LetsencryptPrivateKey.id==LetsencryptCertificateRequest.letsencrypt_private_key_id__signed_by",
                                               back_populates='letsencrypt_private_key__signed_by',
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


class LetsencryptServerCertificate(Base):
    """
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

    certificate_to_domains = sa.orm.relationship("LetsencryptServerCertificate2LetsencryptDomain",
                                                 primaryjoin="LetsencryptServerCertificate.id==LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_server_certificate_id",
                                                 back_populates='certificate',
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
        if self.expiring_days <= 0:
            return 'danger'
        elif self.expiring_days <= 30:
            return 'warning'
        elif self.expiring_days > 30:
            return 'success'

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
        domains = sorted([to_d.domain.domain_name for to_d in self.certificate_to_domains])
        return ', '.join(domains)

    @property
    def domains_as_list(self):
        domain_names = [to_d.domain.domain_name.lower() for to_d in self.certificate_to_domains]
        domain_names = list(set(domain_names))
        domain_names = sorted(domain_names)
        return domain_names


class LetsencryptServerCertificate2LetsencryptDomain(Base):
    """
    """
    __tablename__ = 'letsencrypt_server_certificate_2_letsencrypt_domain'
    letsencrypt_server_certificate_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_server_certificate.id"), primary_key=True)
    letsencrypt_domain_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_domain.id"), primary_key=True)

    certificate = sa.orm.relationship("LetsencryptServerCertificate",
                                      primaryjoin="LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_server_certificate_id==LetsencryptServerCertificate.id",
                                      uselist=False,
                                      back_populates='certificate_to_domains',
                                      )
    domain = sa.orm.relationship("LetsencryptDomain",
                                 primaryjoin="LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id==LetsencryptDomain.id",
                                 uselist=False,
                                 back_populates='domain_to_certificates',
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
        sa.and_(LetsencryptDomain.id == LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_domain_id,
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


LetsencryptDomain.domain_to_certificates_5 = sa.orm.relationship(
    LetsencryptServerCertificate2LetsencryptDomain,
    primaryjoin=(
        sa.and_(LetsencryptDomain.id == LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id,
                LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_server_certificate_id.in_(
                    sa.select([LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_server_certificate_id])
                    .where(LetsencryptDomain.id == LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id)
                    .order_by(LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_server_certificate_id.desc())
                    .limit(5)
                    .correlate()
                )
                )
    ),
    order_by=LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_server_certificate_id.desc(),
    viewonly=True
)


class LetsencryptRatelimitedAction(Base):
    """
    iso_week is used for quick lookups
    stores a float of datetime.datetime.utcnow().isocalendar()[:2]
    i.e. {YEAR}.{WEEKNUMBER}
    """
    __tablename__ = 'letsencrypt_ratelimited_action'
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp = sa.Column(sa.DateTime, nullable=False)
    iso_week = sa.Column(sa.Float, nullable=False, )
