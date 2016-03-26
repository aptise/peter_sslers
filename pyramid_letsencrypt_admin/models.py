import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import (scoped_session,
                            sessionmaker,
                            )
from zope.sqlalchemy import ZopeTransactionExtension


import json


# ==============================================================================


DBSession = scoped_session(sessionmaker(extension=ZopeTransactionExtension()))
Base = declarative_base()


# ==============================================================================


class LetsencryptOperationsEventType(object):
    ca_certificate_probe = 1
    update_recents = 2
    deactivate_expired = 3
    deactivate_duplicate = 4


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
        if self.letsencrypt_operations_event_type_id == 2:
            return 'update_recents'
        if self.letsencrypt_operations_event_type_id == 3:
            return 'deactivate_expired'
        if self.letsencrypt_operations_event_type_id == 4:
            return 'deactivate_duplicate'
        return 'unknown'


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
    signed_certificates = sa.orm.relationship("LetsencryptServerCertificate",
                                              primaryjoin="LetsencryptPrivateKey.id==LetsencryptServerCertificate.letsencrypt_private_key_id__signed_by",
                                              back_populates='private_key',
                                              )


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

    @property
    def cert_fullchain_pem(self):
        return '\n'.join((self.cert_pem, self.certificate_upchain.cert_pem))

    # this is the private key
    letsencrypt_private_key_id__signed_by = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_private_key.id"), nullable=False)

    # tracking
    letsencrypt_certificate_request_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_certificate_request.id"), nullable=True)

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
                                                         )
    domain_to_certificates = sa.orm.relationship("LetsencryptServerCertificate2LetsencryptDomain",
                                                 primaryjoin="LetsencryptDomain.id==LetsencryptServerCertificate2LetsencryptDomain.letsencrypt_domain_id",
                                                 back_populates='domain',
                                                 )

    latest_certificate_single = sa.orm.relationship("LetsencryptServerCertificate",
                                                    primaryjoin="LetsencryptDomain.letsencrypt_server_certificate_id__latest_single==LetsencryptServerCertificate.id",
                                                    uselist=False,
                                                    )
    latest_certificate_multi = sa.orm.relationship("LetsencryptServerCertificate",
                                                   primaryjoin="LetsencryptDomain.letsencrypt_server_certificate_id__latest_multi==LetsencryptServerCertificate.id",
                                                   uselist=False,
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


class LetsencryptCertificateRequest2LetsencryptDomain(Base):
    __tablename__ = 'letsencrypt_certificate_request_2_letsencrypt_domain'
    letsencrypt_certificate_request_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_certificate_request.id"), primary_key=True)
    letsencrypt_domain_id = sa.Column(sa.Integer, sa.ForeignKey("letsencrypt_domain.id"), primary_key=True)
    timestamp_verified = sa.Column(sa.DateTime, nullable=True, )
    ip_verified = sa.Column(sa.Unicode(255), nullable=True, )
    challenge_key = sa.Column(sa.Unicode(255), nullable=True, )
    challenge_text = sa.Column(sa.Unicode(255), nullable=True, )

    @property
    def is_configured(self):
        return True if (self.challenge_key and self.challenge_text) else False

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
