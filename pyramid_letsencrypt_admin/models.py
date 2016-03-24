import sqlalchemy as sa

from sqlalchemy.ext.declarative import declarative_base

from sqlalchemy.orm import (scoped_session,
                            sessionmaker,
                            )

from zope.sqlalchemy import ZopeTransactionExtension

DBSession = scoped_session(sessionmaker(extension=ZopeTransactionExtension()))
Base = declarative_base()


class LetsencryptCACertificateProbe(Base):
    """
    Tracking official LetsEncrypt certificates.
    These are tracked to a fullchain can be created
    """
    __tablename__ = 'letsencrypt_ca_certificate_probe'
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_operation = sa.Column(sa.DateTime, nullable=True, )
    is_certificates_discovered = sa.Column(sa.Boolean, nullable=True, default=None)
    is_certificates_updated = sa.Column(sa.Boolean, nullable=True, default=None)


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


class LetsencryptAccountKey(Base):
    """
    """
    __tablename__ = 'letsencrypt_account_key'
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_first_seen = sa.Column(sa.DateTime, nullable=False, )
    key_pem = sa.Column(sa.Text, nullable=True, )
    key_pem_md5 = sa.Column(sa.Unicode(32), nullable=False, )
    key_pem_modulus_md5 = sa.Column(sa.Unicode(32), nullable=False, )

    certificate_requests = sa.orm.relationship("LetsencryptCertificateRequest",
                                               primaryjoin="LetsencryptAccountKey.id==LetsencryptCertificateRequest.letsencrypt_account_key_id",
                                               back_populates='letsencrypt_account_key',
                                               )


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

    certificate_requests = sa.orm.relationship("LetsencryptCertificateRequest",
                                               primaryjoin="LetsencryptPrivateKey.id==LetsencryptCertificateRequest.letsencrypt_private_key_id__signed_by",
                                               back_populates='letsencrypt_private_key__signed_by',
                                               )
    signed_certificates = sa.orm.relationship("LetsencryptHttpsCertificate",
                                              primaryjoin="LetsencryptPrivateKey.id==LetsencryptHttpsCertificate.letsencrypt_private_key_id__signed_by",
                                              back_populates='private_key',
                                              )


class LetsencryptHttpsCertificate(Base):
    """
    """
    __tablename__ = 'letsencrypt_https_certificate'
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_signed = sa.Column(sa.DateTime, nullable=False, )
    timestamp_expires = sa.Column(sa.DateTime, nullable=False, )
    is_active = sa.Column(sa.Boolean, nullable=False, default=True)
    cert_pem = sa.Column(sa.Text, nullable=False, )
    cert_pem_md5 = sa.Column(sa.Unicode(32), nullable=False, )
    cert_pem_modulus_md5 = sa.Column(sa.Unicode(32), nullable=False, )

    cert_subject = sa.Column(sa.Text, nullable=True, )
    cert_issuer = sa.Column(sa.Text, nullable=True, )
    cert_subject_hash = sa.Column(sa.Unicode(8), nullable=True)
    cert_issuer_hash = sa.Column(sa.Unicode(8), nullable=True)

    # this is the LetsEncrypt key
    letsencrypt_ca_certificate_id__signed_by = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_ca_certificate.id"), nullable=False)

    # this is the private key
    letsencrypt_private_key_id__signed_by = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_private_key.id"), nullable=False)

    # tracking
    letsencrypt_certificate_request_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_certificate_request.id"), nullable=True)

    private_key = sa.orm.relationship("LetsencryptPrivateKey",
                                      primaryjoin="LetsencryptHttpsCertificate.letsencrypt_private_key_id__signed_by==LetsencryptPrivateKey.id",
                                      back_populates='signed_certificates',
                                      uselist=False,
                                      )

    certificate_to_domains = sa.orm.relationship("LetsencryptHttpsCertificateToDomain",
                                                 primaryjoin="LetsencryptHttpsCertificate.id==LetsencryptHttpsCertificateToDomain.letsencrypt_https_certificate_id",
                                                 back_populates='certificate',
                                                 )

    certificate_request = sa.orm.relationship("LetsencryptCertificateRequest",
                                              primaryjoin="LetsencryptHttpsCertificate.letsencrypt_certificate_request_id==LetsencryptCertificateRequest.id",
                                              back_populates='signed_certificate',
                                              uselist=False,
                                              )


class LetsencryptHttpsCertificateToDomain(Base):
    """
    """
    __tablename__ = 'letsencrypt_https_certificate_to_domain'
    letsencrypt_https_certificate_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_https_certificate.id"), primary_key=True)
    letsencrypt_managed_domain_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_managed_domain.id"), primary_key=True)

    certificate = sa.orm.relationship("LetsencryptHttpsCertificate",
                                      primaryjoin="LetsencryptHttpsCertificateToDomain.letsencrypt_https_certificate_id==LetsencryptHttpsCertificate.id",
                                      uselist=False,
                                      back_populates='certificate_to_domains',
                                      )
    domain = sa.orm.relationship("LetsencryptManagedDomain",
                                 primaryjoin="LetsencryptHttpsCertificateToDomain.letsencrypt_managed_domain_id==LetsencryptManagedDomain.id",
                                 uselist=False,
                                 back_populates='domain_to_certificates',
                                 )


class LetsencryptManagedDomain(Base):
    """
    """
    __tablename__ = 'letsencrypt_managed_domain'
    id = sa.Column(sa.Integer, primary_key=True)
    domain_name = sa.Column(sa.Unicode(255), nullable=False)

    domain_to_certificate_requests = sa.orm.relationship("LetsencryptCertificateRequest_2_ManagedDomain",
                                                         primaryjoin="LetsencryptManagedDomain.id==LetsencryptCertificateRequest_2_ManagedDomain.letsencrypt_managed_domain_id",
                                                         back_populates='domain',
                                                         )
    domain_to_certificates = sa.orm.relationship("LetsencryptHttpsCertificateToDomain",
                                                 primaryjoin="LetsencryptManagedDomain.id==LetsencryptHttpsCertificateToDomain.letsencrypt_managed_domain_id",
                                                 back_populates='domain',
                                                 )


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

    check1 = sa.CheckConstraint("""(certificate_request_type_id = 1
                                    and (csr_pem is NULL and csr_pem_md5 is NULL and csr_pem_modulus_md5 is NULL)
                                    )
                                   or
                                   (certificate_request_type_id = 2
                                    and (csr_pem is NOT NULL and csr_pem_md5 is NOT NULL and csr_pem_modulus_md5 is NOT NULL)
                                    )""", name='check1')

    letsencrypt_private_key_id__signed_by = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_private_key.id"), nullable=True)
    letsencrypt_account_key_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_account_key.id"), nullable=True)

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

    certificate_request_to_domains = sa.orm.relationship("LetsencryptCertificateRequest_2_ManagedDomain",
                                                         primaryjoin="LetsencryptCertificateRequest.id==LetsencryptCertificateRequest_2_ManagedDomain.letsencrypt_certificate_request_id",
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

    signed_certificate = sa.orm.relationship("LetsencryptHttpsCertificate",
                                             primaryjoin="LetsencryptCertificateRequest.id==LetsencryptHttpsCertificate.letsencrypt_certificate_request_id",
                                             back_populates='certificate_request',
                                             uselist=False,
                                             )


class LetsencryptCertificateRequest_2_ManagedDomain(Base):
    __tablename__ = 'letsencrypt_certificate_request_2_managed_domain'
    letsencrypt_certificate_request_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_certificate_request.id"), primary_key=True)
    letsencrypt_managed_domain_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_managed_domain.id"), primary_key=True)
    timestamp_verified = sa.Column(sa.DateTime, nullable=True, )
    ip_verified = sa.Column(sa.Unicode(255), nullable=True, )
    challenge_key = sa.Column(sa.Unicode(255), nullable=True, )
    challenge_text = sa.Column(sa.Unicode(255), nullable=True, )

    @property
    def is_configured(self):
        return True if (self.challenge_key and self.challenge_text) else False

    certificate_request = sa.orm.relationship("LetsencryptCertificateRequest",
                                              primaryjoin="LetsencryptCertificateRequest_2_ManagedDomain.letsencrypt_certificate_request_id==LetsencryptCertificateRequest.id",
                                              uselist=False,
                                              back_populates='certificate_request_to_domains',
                                              )
    domain = sa.orm.relationship("LetsencryptManagedDomain",
                                 primaryjoin="LetsencryptCertificateRequest_2_ManagedDomain.letsencrypt_managed_domain_id==LetsencryptManagedDomain.id",
                                 uselist=False,
                                 back_populates='domain_to_certificate_requests',
                                 )
