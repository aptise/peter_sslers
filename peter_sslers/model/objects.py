# stdlib
import datetime
import json

# pypi
import sqlalchemy as sa
from sqlalchemy.orm import relationship as sa_orm_relationship
from pyramid.decorator import reify

# localapp
from .meta import Base
from . import utils as model_utils


# ==============================================================================


"""
Coding Style:

    class Foo():
        columns
        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        relationships
        constraints
        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        properties/functions
"""
TESTING_ENVIRONMENT = False


# ==============================================================================


class AcmeEventLog(Base):
    """
    log acme requests
    """

    __tablename__ = "acme_event_log"
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_event = sa.Column(sa.DateTime, nullable=False)
    acme_event_id = sa.Column(sa.Integer, nullable=False)  # AcmeEvent
    acme_account_key_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_account_key.id"), nullable=True
    )
    acme_authorization_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_authorization.id"), nullable=True
    )
    acme_challenge_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_challenge.id"), nullable=True
    )
    acme_order_id = sa.Column(sa.Integer, sa.ForeignKey("acme_order.id"), nullable=True)
    certificate_request_id = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_request.id"), nullable=True
    )
    server_certificate_id = sa.Column(
        sa.Integer, sa.ForeignKey("server_certificate.id"), nullable=True
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    #     acme_challenges = sa_orm_relationship(
    #         "AcmeChallenge",
    #         primaryjoin="AcmeEventLog.id==AcmeChallenge.acme_event_log_id",
    #         order_by="AcmeChallenge.id.asc()",
    #         back_populates="acme_event_log",
    #     )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @reify
    def acme_event(self):
        if self.acme_event_id:
            return model_utils.AcmeEvent.as_string(self.acme_event_id)
        return None


class AcmeChallengePoll(Base):
    """
    log ACME Challenge polls
    """

    __tablename__ = "acme_challenge_poll"

    id = sa.Column(sa.Integer, primary_key=True)
    acme_challenge_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_challenge.id"), nullable=False
    )
    timestamp_polled = sa.Column(sa.DateTime, nullable=False)
    remote_ip_address = sa.Column(sa.Unicode(255), nullable=False)

    acme_challenge = sa_orm_relationship(
        "AcmeChallenge",
        primaryjoin="AcmeChallengePoll.acme_challenge_id==AcmeChallenge.id",
        uselist=False,
        back_populates="acme_challenge_polls",
    )


class AcmeChallengeUnknownPoll(Base):
    """
    log polls of non-existant ace challenges
    """

    __tablename__ = "acme_challenge_unknown_poll"

    id = sa.Column(sa.Integer, primary_key=True)
    domain = sa.Column(sa.Unicode(255), nullable=False)
    challenge = sa.Column(sa.Unicode(255), nullable=False)
    timestamp_polled = sa.Column(sa.DateTime, nullable=False)
    remote_ip_address = sa.Column(sa.Unicode(255), nullable=False)


# ==============================================================================


class AcmeAccountKey(Base):
    """
    Represents a registered account with the LetsEncrypt Service.
    This is used for authentication to the LE API, it is not tied to any certificates.
    """

    __tablename__ = "acme_account_key"
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_first_seen = sa.Column(sa.DateTime, nullable=False)
    key_pem = sa.Column(sa.Text, nullable=True)
    key_pem_md5 = sa.Column(sa.Unicode(32), nullable=False)
    key_pem_modulus_md5 = sa.Column(sa.Unicode(32), nullable=False)
    count_certificate_requests = sa.Column(sa.Integer, nullable=True, default=0)
    count_certificates_issued = sa.Column(sa.Integer, nullable=True, default=0)
    timestamp_last_certificate_request = sa.Column(sa.DateTime, nullable=True)
    timestamp_last_certificate_issue = sa.Column(sa.DateTime, nullable=True)
    timestamp_last_authenticated = sa.Column(sa.DateTime, nullable=True)
    is_active = sa.Column(sa.Boolean, nullable=False, default=True)
    is_default = sa.Column(sa.Boolean, nullable=True, default=None)
    acme_account_provider_id = sa.Column(sa.Integer, nullable=False)
    operations_event_id__created = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )
    letsencrypt_data = sa.Column(sa.Text, nullable=True)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_orders = sa_orm_relationship(
        "AcmeOrder",
        primaryjoin="AcmeAccountKey.id==AcmeOrder.acme_account_key_id",
        order_by="AcmeOrder.id.desc()",
        uselist=True,
        back_populates="acme_account_key",
    )

    server_certificates__issued = sa_orm_relationship(
        "ServerCertificate",
        primaryjoin="AcmeAccountKey.id==ServerCertificate.acme_account_key_id",
        order_by="ServerCertificate.id.desc()",
        back_populates="acme_account_key",
    )

    operations_object_events = sa_orm_relationship(
        "OperationsObjectEvent",
        primaryjoin="AcmeAccountKey.id==OperationsObjectEvent.acme_account_key_id",
        back_populates="acme_account_key",
    )

    operations_event__created = sa_orm_relationship(
        "OperationsEvent",
        primaryjoin="AcmeAccountKey.operations_event_id__created==OperationsEvent.id",
        uselist=False,
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @reify
    def key_pem_modulus_search(self):
        return "type=modulus&modulus=%s&source=account_key&account_key.id=%s" % (
            self.key_pem_modulus_md5,
            self.id,
        )

    @reify
    def key_pem_sample(self):
        # strip the pem, because the last line is whitespace after "-----END RSA PRIVATE KEY-----"
        pem_lines = self.key_pem.strip().split("\n")
        return "%s...%s" % (pem_lines[1][0:5], pem_lines[-2][-5:])

    @reify
    def acme_account_provider(self):
        if self.acme_account_provider_id is not None:
            for provider_info in model_utils.AcmeAccountProvider.registry.values():
                if provider_info["id"] == self.acme_account_provider_id:
                    return provider_info["name"]
        return None

    @reify
    def acme_account_provider_endpoint(self):
        if TESTING_ENVIRONMENT:
            return model_utils.AcmeAccountProvider.registry[0]["endpoint"]
        if self.acme_account_provider_id:
            for provider_info in model_utils.AcmeAccountProvider.registry.values():
                if provider_info["id"] == self.acme_account_provider_id:
                    return provider_info["endpoint"]
        return None

    @reify
    def acme_account_provider_directory(self):
        if TESTING_ENVIRONMENT:
            return model_utils.AcmeAccountProvider.registry[0]["directory"]
        if self.acme_account_provider_id:
            for provider_info in model_utils.AcmeAccountProvider.registry.values():
                if provider_info["id"] == self.acme_account_provider_id:
                    return provider_info["directory"]
        return None

    @property
    def as_json(self):
        return {
            "key_pem": self.key_pem,
            "key_pem_md5": self.key_pem_md5,
            "is_active": True if self.is_active else False,
            "is_default": True if self.is_active else False,
            "acme_account_provider_id": self.acme_account_provider_id,
            "acme_account_provider": self.acme_account_provider,
            "id": self.id,
        }


class AcmeOrder(Base):
    """
    ACME Order Object [https://tools.ietf.org/html/rfc8555#section-7.1.3]

    An ACME Order is essentially a Certificate Request
        
    It contains the following objects:
        Identifiers (Domains)
        Authorizations (Authorization Objects)
        Certificate (Signed Certificate)
    """

    __tablename__ = "acme_order"

    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    status = sa.Column(sa.Unicode(32), nullable=False)
    resource_url = sa.Column(sa.Unicode(255), nullable=True)
    finalize_url = sa.Column(sa.Unicode(255), nullable=True)
    timestamp_expires = sa.Column(sa.DateTime, nullable=True)
    timestamp_updated = sa.Column(sa.DateTime, nullable=True)

    acme_event_log_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_event_log.id"), nullable=False
    )  # When was this created?  AcmeEvent['v2|newOrder']

    timestamp_finalized = sa.Column(sa.DateTime, nullable=True)

    acme_account_key_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_account_key.id"), nullable=False
    )
    certificate_request_id = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_request.id"), nullable=True
    )
    server_certificate_id = sa.Column(
        sa.Integer, sa.ForeignKey("server_certificate.id"), nullable=True
    )
    unique_fqdn_set_id = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_request.id"), nullable=False
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_account_key = sa_orm_relationship(
        "AcmeAccountKey",
        primaryjoin="AcmeOrder.acme_account_key_id==AcmeAccountKey.id",
        uselist=False,
        back_populates="acme_orders",
    )

    certificate_request = sa_orm_relationship(
        "CertificateRequest",
        primaryjoin="AcmeOrder.certificate_request_id==CertificateRequest.id",
        uselist=False,
        back_populates="acme_orders",
    )

    server_certificate = sa_orm_relationship(
        "ServerCertificate",
        primaryjoin="AcmeOrder.server_certificate_id==ServerCertificate.id",
        uselist=False,
        back_populates="acme_orders",
    )

    # authorizations
    to_acme_authorizations = sa_orm_relationship(
        "AcmeOrder2AcmeAuthorization",
        primaryjoin="AcmeOrder.id==AcmeOrder2AcmeAuthorization.acme_order_id",
        uselist=True,
        back_populates="acme_order",
    )

    # identifiers
    to_domains = sa_orm_relationship(
        "AcmeOrder2Domain",
        primaryjoin="AcmeOrder.id==AcmeOrder2Domain.acme_order_id",
        uselist=False,
        back_populates="acme_order",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def is_can_retry(self):
        # TODO: this should be conditional
        return True


class AcmeOrder2Domain(Base):
    __tablename__ = "acme_order_2_domain"

    acme_order_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_order.id"), primary_key=True
    )
    domain_id = sa.Column(sa.Integer, sa.ForeignKey("domain.id"), primary_key=True)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_order = sa_orm_relationship(
        "AcmeOrder",
        primaryjoin="AcmeOrder2Domain.acme_order_id==AcmeOrder.id",
        uselist=False,
        back_populates="to_domains",
    )

    domain = sa_orm_relationship(
        "Domain",
        primaryjoin="AcmeOrder2Domain.domain_id==Domain.id",
        uselist=False,
        back_populates="to_acme_orders",
    )


class AcmeOrder2AcmeAuthorization(Base):
    __tablename__ = "acme_order_2_acme_authorization"

    acme_order_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_order.id"), primary_key=True
    )
    acme_authorization_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_authorization.id"), primary_key=True
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_order = sa_orm_relationship(
        "AcmeOrder",
        primaryjoin="AcmeOrder2AcmeAuthorization.acme_order_id==AcmeOrder.id",
        uselist=False,
        back_populates="to_acme_authorizations",
    )

    acme_authorization = sa_orm_relationship(
        "AcmeAuthorization",
        primaryjoin="AcmeOrder2AcmeAuthorization.acme_authorization_id==AcmeAuthorization.id",
        uselist=False,
        back_populates="to_acme_orders",
    )


class AcmeAuthorization(Base):
    """
    ACME Authorization Object [https://tools.ietf.org/html/rfc8555#section-7.1.4]

    RFC Fields:

        identifier (required, object):
            this is a domain
            
        expires (optional, string):
            REQUIRED for objects with "valid" in the "status" field.
    
        status (required, string):  The status of this authorization.
              Possible values are "pending", "valid", "invalid", "deactivated",
              "expired", and "revoked".    

        challenges (required, array of objects):
        
        wildcard (optional, boolean):  

    Additionally, these are our fields:
        authorization_url - our unique-ish way to track this
        timestamp_created
        domain_id - `identifer`
        timestamp_expires - `expires`
        status - `status`
        timestamp_updated - last time we updated this object
    """

    __tablename__ = "acme_authorization"
    id = sa.Column(sa.Integer, primary_key=True)
    authorization_url = sa.Column(sa.Unicode(255), nullable=True)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    domain_id = sa.Column(sa.Integer, sa.ForeignKey("domain.id"), nullable=False)
    timestamp_expires = sa.Column(sa.DateTime, nullable=True)
    status = sa.Column(sa.Unicode(32), nullable=False)
    timestamp_updated = sa.Column(sa.DateTime, nullable=True)
    wildcard = sa.Column(sa.Boolean, nullable=True, default=None)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    domain = sa_orm_relationship(
        "Domain",
        primaryjoin="AcmeAuthorization.domain_id==Domain.id",
        uselist=False,
        back_populates="acme_authorizations",
    )

    to_acme_orders = sa_orm_relationship(
        "AcmeOrder2AcmeAuthorization",
        primaryjoin="AcmeAuthorization.id==AcmeOrder2AcmeAuthorization.acme_authorization_id",
        uselist=False,
        back_populates="acme_authorization",
    )

    acme_challenge_http01 = sa_orm_relationship(
        "AcmeChallenge",
        primaryjoin="and_(AcmeAuthorization.id==AcmeChallenge.acme_authorization_id, AcmeChallenge.acme_challenge_type_id==%s)"
        % model_utils.AcmeChallengeType.from_string("http-01"),
        uselist=False,
        back_populates="acme_authorization",
    )


class AcmeChallenge(Base):
    """
    ACME Challenge Objects [https://tools.ietf.org/html/rfc8555#section-8]
    
    RFC Fields:
       type (required, string):  The type of challenge encoded in the
          object.

       url (required, string):  The URL to which a response can be posted.

       status (required, string):  The status of this challenge.  Possible
          values are "pending", "processing", "valid", and "invalid" (see
          Section 7.1.6).

       validated (optional, string):  The time at which the server validated
          this challenge, encoded in the format specified in [RFC3339].
          This field is REQUIRED if the "status" field is "valid".

       error (optional, object):  Error that occurred while the server was
          validating the challenge, if any, structured as a problem document
          [RFC7807].  Multiple errors can be indicated by using subproblems
          Section 6.7.1.  A challenge object with an error MUST have status
          equal to "invalid".


    HTTP Challenge https://tools.ietf.org/html/rfc8555#section-8.3

       type (required, string):  The string "http-01".

       token (required, string):  A random value that uniquely identifies
          the challenge.  This value MUST have at least 128 bits of entropy.
          It MUST NOT contain any characters outside the base64url alphabet
          and MUST NOT include base64 padding characters ("=").  See
          [RFC4086] for additional information on randomness requirements.

    Example Challenge:

       {
         "type": "http-01",
         "url": "https://example.com/acme/chall/prV_B7yEyA4",
         "status": "pending",
         "token": "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
       }

    """

    __tablename__ = "acme_challenge"
    id = sa.Column(sa.Integer, primary_key=True)
    acme_authorization_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_authorization.id"), nullable=False
    )
    challenge_url = sa.Column(sa.Unicode(255), nullable=True)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    acme_challenge_type_id = sa.Column(
        sa.Integer, nullable=True
    )  # this library only does http-01, `model_utils.AcmeChallengeType`
    status = sa.Column(sa.Unicode(32), nullable=False)
    token = sa.Column(sa.Unicode(255), nullable=False)
    timestamp_updated = sa.Column(sa.DateTime, nullable=True)

    #
    # token_clean = re.sub(r"[^A-Za-z0-9_\-]", "_", dbAcmeAuthorization.acme_challenge_http01.token)
    # keyauthorization = "{0}.{1}".format(token_clean, accountkey_thumbprint)
    keyauthorization = sa.Column(sa.Unicode(255), nullable=True)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    #     acme_event_log = sa_orm_relationship(
    #         "AcmeEventLog",
    #         primaryjoin="AcmeChallenge.acme_event_log_id==AcmeEventLog.id",
    #         uselist=False,
    #         back_populates="acme_challenges",
    #     )

    acme_challenge_polls = sa_orm_relationship(
        "AcmeChallengePoll",
        primaryjoin="AcmeChallenge.id==AcmeChallengePoll.acme_challenge_id",
        uselist=True,
        back_populates="acme_challenge",
    )

    acme_authorization = sa_orm_relationship(
        "AcmeAuthorization",
        primaryjoin="AcmeChallenge.acme_authorization_id==AcmeAuthorization.id",
        uselist=False,
        back_populates="acme_challenge_http01",
    )

    if False:
        # migrate to fqdns
        to_certificate_requests = sa_orm_relationship(
            "CertificateRequest2Domain",
            primaryjoin="AcmeChallenge.id==CertificateRequest2Domain.acme_challenge_id",
            uselist=False,
            back_populates="acme_challenge",
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def acme_challenge_type(self):
        if self.acme_challenge_type_id:
            return model_utils.AcmeChallengeType.as_string(self.acme_challenge_type_id)
        return None

    @property
    def domain_name(self):
        return self.acme_authorization.domain.domain_name

    @property
    def timestamp_created_isoformat(self):
        if self.timestamp_created:
            return self.timestamp_created.isoformat()
        return None

    @property
    def timestamp_updated_isoformat(self):
        if self.timestamp_updated:
            return self.timestamp_updated.isoformat()
        return None

    @property
    def as_json(self):
        return {
            "id": self.id,
            "acme_challenge_type": self.acme_challenge_type,
            "domain": self.domain_name,
            "status": self.status,
            "timestamp_created": self.timestamp_created_isoformat,
            "timestamp_updated": self.timestamp_updated_isoformat,
            # "acme_event_log_id": self.acme_event_log_id,
        }


# ==============================================================================


class CaCertificate(Base):
    """
    These are trusted "Certificate Authority" Certificates from LetsEncrypt that are used to sign server certificates.
    These are directly tied to a ServerCertificate and are needed to create a "fullchain" certificate for most deployments.
    """

    __tablename__ = "ca_certificate"
    id = sa.Column(sa.Integer, primary_key=True)
    name = sa.Column(sa.Unicode(255), nullable=False)
    le_authority_name = sa.Column(sa.Unicode(255), nullable=True)
    is_ca_certificate = sa.Column(sa.Boolean, nullable=True, default=None)
    is_authority_certificate = sa.Column(sa.Boolean, nullable=True, default=None)
    is_cross_signed_authority_certificate = sa.Column(
        sa.Boolean, nullable=True, default=None
    )
    id_cross_signed_of = sa.Column(
        sa.Integer, sa.ForeignKey("ca_certificate.id"), nullable=True
    )
    timestamp_first_seen = sa.Column(sa.DateTime, nullable=False)
    cert_pem = sa.Column(sa.Text, nullable=False)
    cert_pem_md5 = sa.Column(sa.Unicode(32), nullable=True)
    cert_pem_modulus_md5 = sa.Column(sa.Unicode(32), nullable=True)
    timestamp_signed = sa.Column(sa.DateTime, nullable=False)
    timestamp_expires = sa.Column(sa.DateTime, nullable=False)
    cert_subject = sa.Column(sa.Text, nullable=True)
    cert_issuer = sa.Column(sa.Text, nullable=True)
    cert_subject_hash = sa.Column(sa.Unicode(8), nullable=True)
    cert_issuer_hash = sa.Column(sa.Unicode(8), nullable=True)
    count_active_certificates = sa.Column(sa.Integer, nullable=True)
    operations_event_id__created = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    operations_event__created = sa_orm_relationship(
        "OperationsEvent",
        primaryjoin="CaCertificate.operations_event_id__created==OperationsEvent.id",
        uselist=False,
    )

    operations_object_events = sa_orm_relationship(
        "OperationsObjectEvent",
        primaryjoin="CaCertificate.id==OperationsObjectEvent.ca_certificate_id",
        back_populates="ca_certificate",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @reify
    def cert_pem_modulus_search(self):
        return "type=modulus&modulus=%s&source=ca_certificate&ca_certificate.id=%s" % (
            self.cert_pem_modulus_md5,
            self.id,
        )

    @reify
    def cert_subject_hash_search(self):
        return (
            "type=cert_subject_hash&cert_subject_hash=%s&source=ca_certificate&ca_certificate.id=%s"
            % (self.cert_subject_hash, self.id)
        )

    @reify
    def cert_issuer_hash_search(self):
        return (
            "type=cert_issuer_hash&cert_issuer_hash=%s&source=ca_certificate&ca_certificate.id=%s"
            % (self.cert_issuer_hash, self.id)
        )

    @property
    def timestamp_first_seen_isoformat(self):
        if self.timestamp_first_seen:
            return self.timestamp_first_seen.isoformat()
        return None

    @property
    def as_json(self):
        return {
            "id": self.id,
            "name": self.name,
            "cert_pem_md5": self.cert_pem_md5,
            "cert_pem": self.cert_pem,
            "timestamp_first_seen": self.timestamp_first_seen_isoformat,
        }


class CertificateRequest(Base):
    """
    A CertificateRequest is submitted to the LetsEncrypt signing authority.
    In goes your hope, out comes your dreams.

    The domains will be stored in the UniqueFQDNSet table
    * UniqueFQDNSet - the signing authority has a ratelimit on 'unique' sets of fully qualified domain names.
    """

    __tablename__ = "certificate_request"
    id = sa.Column(sa.Integer, primary_key=True)
    is_active = sa.Column(sa.Boolean, nullable=False, default=True)
    # ???: deprecation candidate: `is_error`
    # is_error = sa.Column(sa.Boolean, nullable=True, default=None)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    certificate_request_source_id = sa.Column(
        sa.Integer, nullable=False
    )  # see CertificateRequestSource

    csr_pem = sa.Column(sa.Text, nullable=True)
    csr_pem_md5 = sa.Column(sa.Unicode(32), nullable=True)
    csr_pem_modulus_md5 = sa.Column(sa.Unicode(32), nullable=True)

    operations_event_id__created = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )
    private_key_id__signed_by = sa.Column(
        sa.Integer, sa.ForeignKey("private_key.id"), nullable=True
    )
    server_certificate_id__renewal_of = sa.Column(
        sa.Integer,
        sa.ForeignKey("server_certificate.id", use_alter=True),
        nullable=True,
    )
    unique_fqdn_set_id = sa.Column(
        sa.Integer, sa.ForeignKey("unique_fqdn_set.id"), nullable=False
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_orders = sa_orm_relationship(
        "AcmeOrder",
        primaryjoin="CertificateRequest.id==AcmeOrder.certificate_request_id",
        uselist=True,
        back_populates="certificate_request",
    )

    operations_object_events = sa_orm_relationship(
        "OperationsObjectEvent",
        primaryjoin="CertificateRequest.id==OperationsObjectEvent.certificate_request_id",
        back_populates="certificate_request",
    )

    private_key__signed_by = sa_orm_relationship(
        "PrivateKey",
        primaryjoin="CertificateRequest.private_key_id__signed_by==PrivateKey.id",
        back_populates="certificate_requests",
        uselist=False,
    )

    server_certificate = sa_orm_relationship(
        "ServerCertificate",
        primaryjoin="CertificateRequest.id==ServerCertificate.certificate_request_id",
        back_populates="certificate_request",
        uselist=False,
    )

    server_certificate__renewal_of = sa_orm_relationship(
        "ServerCertificate",
        primaryjoin="CertificateRequest.server_certificate_id__renewal_of==ServerCertificate.id",
        back_populates="certificate_request__renewals",
        uselist=False,
    )

    if False:
        # TODO: migrate through the Unique FQDNS
        to_domains = sa_orm_relationship(
            "CertificateRequest2Domain",
            primaryjoin="CertificateRequest.id==CertificateRequest2Domain.certificate_request_id",
            back_populates="certificate_request",
        )

    unique_fqdn_set = sa_orm_relationship(
        "UniqueFQDNSet",
        primaryjoin="CertificateRequest.unique_fqdn_set_id==UniqueFQDNSet.id",
        uselist=False,
        back_populates="certificate_requests",
    )

    check1 = sa.CheckConstraint(
        """(certificate_request_source_id = 1
                                    and (csr_pem is NULL and csr_pem_md5 is NULL and csr_pem_modulus_md5 is NULL)
                                    )
                                   or
                                   (certificate_request_source_id = 2
                                    and (csr_pem is NOT NULL and csr_pem_md5 is NOT NULL and csr_pem_modulus_md5 is NOT NULL)
                                    )""",
        name="check1",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @reify
    def csr_pem_modulus_search(self):
        return (
            "type=modulus&modulus=%s&source=certificate_request&certificate_request.id=%s"
            % (self.csr_pem_modulus_md5, self.id)
        )

    @reify
    def certificate_request_source(self):
        if (
            self.certificate_request_source_id
            == model_utils.CertificateRequestSource.RECORDED
        ):
            return "Recorded"
        elif (
            self.certificate_request_source_id
            == model_utils.CertificateRequestSource.ACME_FLOW
        ):
            return "Acme Flow"
        elif (
            self.certificate_request_source_id
            == model_utils.CertificateRequestSource.ACME_AUTOMATED
        ):
            return "Acme Automated"
        raise ValueError("invalid `self.certificate_request_source_id`")

    def certificate_request_source_is(self, check):
        if (check.lower() == "recorded") and (
            self.certificate_request_source_id
            == model_utils.CertificateRequestSource.RECORDED
        ):
            return True
        elif (check.lower() == "acme flow") and (
            self.certificate_request_source_id
            == model_utils.CertificateRequestSource.ACME_FLOW
        ):
            return True
        elif (check.lower() == "acme automated") and (
            self.certificate_request_source_id
            == model_utils.CertificateRequestSource.ACME_AUTOMATED
        ):
            return True
        return False

    @property
    def domains_as_string(self):
        domains = sorted(
            [to_d.domain.domain_name for to_d in self.unique_fqdn_set.to_domains]
        )
        return ", ".join(domains)

    @property
    def domains_as_list(self):
        domain_names = [
            to_d.domain.domain_name.lower() for to_d in self.unique_fqdn_set.to_domains
        ]
        domain_names = list(set(domain_names))
        domain_names = sorted(domain_names)
        return domain_names

    @property
    def timestamp_started_isoformat(self):
        if self.timestamp_started:
            return self.timestamp_started.isoformat()
        return None

    @property
    def timestamp_finished_isoformat(self):
        if self.timestamp_finished:
            return self.timestamp_finished.isoformat()
        return None

    @property
    def server_certificate_id__issued(self):
        if self.server_certificate:
            return self.server_certificate.id
        return None

    @property
    def as_json(self):
        # ???: deprecation candidate: `is_error`
        return {
            "id": self.id,
            "is_active": True if self.is_active else False,
            # "is_error": True if self.is_error else False,
            "csr_pem_md5": self.csr_pem_md5,
            "certificate_request_source": self.certificate_request_source,
            "timestamp_started": self.timestamp_started_isoformat,
            "timestamp_finished": self.timestamp_finished_isoformat,
            "acme_account_key_id": self.acme_account_key_id,
            "private_key_id__signed_by": self.private_key_id__signed_by,
            "server_certificate_id__renewal_of": self.server_certificate_id__renewal_of,
            "unique_fqdn_set_id": self.unique_fqdn_set_id,
        }

    @property
    def as_json_extended(self):
        # ???: deprecation candidate: `is_error`
        return {
            "id": self.id,
            "is_active": True if self.is_active else False,
            # "is_error": True if self.is_error else False,
            "csr_pem_md5": self.csr_pem_md5,
            "certificate_request_source": self.certificate_request_source,
            "timestamp_started": self.timestamp_started_isoformat,
            "timestamp_finished": self.timestamp_finished_isoformat,
            "acme_account_key_id": self.acme_account_key_id,
            "private_key_id__signed_by": self.private_key_id__signed_by,
            "server_certificate_id__renewal_of": self.server_certificate_id__renewal_of,
            "unique_fqdn_set_id": self.unique_fqdn_set_id,
            "domains": self.domains_as_list,
            "csr_pem": self.csr_pem,
            "server_certificate_id__issued": self.server_certificate_id__issued,
        }


class Domain(Base):
    """
    A Fully Qualified Domain
    """

    __tablename__ = "domain"
    id = sa.Column(sa.Integer, primary_key=True)
    domain_name = sa.Column(sa.Unicode(255), nullable=False)
    is_active = sa.Column(sa.Boolean, nullable=False, default=True)
    timestamp_first_seen = sa.Column(sa.DateTime, nullable=False)

    is_from_queue_domain = sa.Column(
        sa.Boolean, nullable=True, default=None
    )  # ???: deprecation candidate

    operations_event_id__created = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )
    server_certificate_id__latest_single = sa.Column(
        sa.Integer, sa.ForeignKey("server_certificate.id"), nullable=True
    )
    server_certificate_id__latest_multi = sa.Column(
        sa.Integer, sa.ForeignKey("server_certificate.id"), nullable=True
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_authorizations = sa_orm_relationship(
        "AcmeAuthorization",
        primaryjoin="Domain.id==AcmeAuthorization.domain_id",
        order_by="AcmeAuthorization.id.desc()",
        uselist=True,
        back_populates="domain",
    )

    operations_object_events = sa_orm_relationship(
        "OperationsObjectEvent",
        primaryjoin="Domain.id==OperationsObjectEvent.domain_id",
        back_populates="domain",
    )

    server_certificate__latest_single = sa_orm_relationship(
        "ServerCertificate",
        primaryjoin="Domain.server_certificate_id__latest_single==ServerCertificate.id",
        uselist=False,
    )

    server_certificate__latest_multi = sa_orm_relationship(
        "ServerCertificate",
        primaryjoin="Domain.server_certificate_id__latest_multi==ServerCertificate.id",
        uselist=False,
    )

    to_acme_orders = sa_orm_relationship(
        "AcmeOrder2Domain",
        primaryjoin="Domain.id==AcmeOrder2Domain.domain_id",
        uselist=True,
        back_populates="domain",
    )

    if False:
        # TODO: migrate through the Unique FQDNS
        to_certificate_requests = sa_orm_relationship(
            "CertificateRequest2Domain",
            primaryjoin="Domain.id==CertificateRequest2Domain.domain_id",
            back_populates="domain",
            order_by="CertificateRequest2Domain.certificate_request_id.desc()",
        )

    to_fqdns = sa_orm_relationship(
        "UniqueFQDNSet2Domain",
        primaryjoin="Domain.id==UniqueFQDNSet2Domain.domain_id",
        back_populates="domain",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def as_json(self):
        payload = {
            "id": self.id,
            "is_active": True if self.is_active else False,
            "domain_name": self.domain_name,
            "certificate__latest_multi": {},
            "certificate__latest_single": {},
        }
        if self.server_certificate_id__latest_multi:
            payload["certificate__latest_multi"] = {
                "id": self.server_certificate_id__latest_multi,
                "timestamp_expires": self.server_certificate__latest_multi.timestamp_expires_isoformat,
                "expiring_days": self.server_certificate__latest_multi.expiring_days,
            }
        if self.server_certificate_id__latest_single:
            payload["certificate__latest_single"] = {
                "id": self.server_certificate_id__latest_single,
                "timestamp_expires": self.server_certificate__latest_single.timestamp_expires_isoformat,
                "expiring_days": self.server_certificate__latest_single.expiring_days,
            }
        return payload


class PrivateKey(Base):
    """
    These keys are used to sign CertificateRequests and are the PrivateKey component to a ServerCertificate.
    """

    __tablename__ = "private_key"
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_first_seen = sa.Column(sa.DateTime, nullable=False)
    key_pem = sa.Column(sa.Text, nullable=True)
    key_pem_md5 = sa.Column(sa.Unicode(32), nullable=False)
    key_pem_modulus_md5 = sa.Column(sa.Unicode(32), nullable=False)
    count_active_certificates = sa.Column(sa.Integer, nullable=True)
    is_autogenerated_key = sa.Column(sa.Boolean, nullable=True, default=None)
    is_active = sa.Column(sa.Boolean, nullable=False, default=True)
    is_compromised = sa.Column(sa.Boolean, nullable=True, default=None)
    count_certificate_requests = sa.Column(sa.Integer, nullable=True, default=0)
    count_certificates_issued = sa.Column(sa.Integer, nullable=True, default=0)
    timestamp_last_certificate_request = sa.Column(sa.DateTime, nullable=True)
    timestamp_last_certificate_issue = sa.Column(sa.DateTime, nullable=True)
    operations_event_id__created = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )
    is_default = sa.Column(sa.Boolean, nullable=True, default=None)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    certificate_requests = sa_orm_relationship(
        "CertificateRequest",
        primaryjoin="PrivateKey.id==CertificateRequest.private_key_id__signed_by",
        order_by="CertificateRequest.id.desc()",
        back_populates="private_key__signed_by",
    )

    server_certificates = sa_orm_relationship(
        "ServerCertificate",
        primaryjoin="PrivateKey.id==ServerCertificate.private_key_id__signed_by",
        order_by="ServerCertificate.id.desc()",
        back_populates="private_key",
    )

    operations_object_events = sa_orm_relationship(
        "OperationsObjectEvent",
        primaryjoin="PrivateKey.id==OperationsObjectEvent.private_key_id",
        back_populates="private_key",
    )

    operations_event__created = sa_orm_relationship(
        "OperationsEvent",
        primaryjoin="PrivateKey.operations_event_id__created==OperationsEvent.id",
        uselist=False,
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def key_pem_modulus_search(self):
        return "type=modulus&modulus=%s&source=private_key&private_key.id=%s" % (
            self.key_pem_modulus_md5,
            self.id,
        )

    @property
    def autogenerated_key_year_week(self):
        if not self.is_autogenerated_key:
            return ""
        return "%s.%s" % self.timestamp_first_seen.isocalendar()[0:2]

    @property
    def timestamp_first_seen_isoformat(self):
        if self.timestamp_first_seen:
            return self.timestamp_first_seen.isoformat()
        return None

    @property
    def key_pem_sample(self):
        # strip the pem, because the last line is whitespace after "-----END RSA PRIVATE KEY-----"
        pem_lines = self.key_pem.strip().split("\n")
        return "%s...%s" % (pem_lines[1][0:5], pem_lines[-2][-5:])

    @property
    def as_json(self):
        return {
            "id": self.id,
            "is_active": True if self.is_active else False,
            "is_default": True if self.is_default else False,
            "key_pem_md5": self.key_pem_md5,
            "key_pem": self.key_pem,
            "timestamp_first_seen": self.timestamp_first_seen_isoformat,
        }


class ServerCertificate(Base):
    """
    A signed Server Certificate.
    To install on a webserver, must be paired with the PrivateKey and Trusted CA Certificate.

    The domains will be stored in:
    * UniqueFQDNSet - the signing authority has a ratelimit on 'unique' sets of fully qualified domain names.
    """

    __tablename__ = "server_certificate"
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_signed = sa.Column(sa.DateTime, nullable=False)
    timestamp_expires = sa.Column(sa.DateTime, nullable=False)
    is_active = sa.Column(sa.Boolean, nullable=False, default=True)
    is_single_domain_cert = sa.Column(sa.Boolean, nullable=True, default=None)
    cert_pem = sa.Column(sa.Text, nullable=False)
    cert_pem_md5 = sa.Column(sa.Unicode(32), nullable=False)
    cert_pem_modulus_md5 = sa.Column(sa.Unicode(32), nullable=False)
    cert_subject = sa.Column(sa.Text, nullable=True)
    cert_issuer = sa.Column(sa.Text, nullable=True)
    cert_subject_hash = sa.Column(sa.Unicode(8), nullable=True)
    cert_issuer_hash = sa.Column(sa.Unicode(8), nullable=True)
    is_deactivated = sa.Column(
        sa.Boolean, nullable=True, default=None
    )  # used to determine is_active toggling.
    is_revoked = sa.Column(
        sa.Boolean, nullable=True, default=None
    )  # used to determine is_active toggling. this will set 'is_deactivated'
    is_auto_renew = sa.Column(sa.Boolean, nullable=False, default=True)
    unique_fqdn_set_id = sa.Column(
        sa.Integer, sa.ForeignKey("unique_fqdn_set.id"), nullable=False
    )
    is_renewed = sa.Column(sa.Boolean, nullable=True, default=None)
    timestamp_revoked_upstream = sa.Column(
        sa.DateTime, nullable=True
    )  # if set, the cert was reported revoked upstream and this is FINAL

    # this is the LetsEncrypt key
    ca_certificate_id__upchain = sa.Column(
        sa.Integer, sa.ForeignKey("ca_certificate.id"), nullable=False
    )

    # this is the private key
    private_key_id__signed_by = sa.Column(
        sa.Integer, sa.ForeignKey("private_key.id"), nullable=False
    )

    # this is the account key, if a LetsEncrypt issue.  this could be null
    acme_account_key_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_account_key.id"), nullable=True
    )

    # tracking
    # `use_alter=True` is needed for setup/drop
    certificate_request_id = sa.Column(
        sa.Integer,
        sa.ForeignKey("certificate_request.id", use_alter=True),
        nullable=True,
    )
    server_certificate_id__renewal_of = sa.Column(
        sa.Integer, sa.ForeignKey("server_certificate.id"), nullable=True
    )
    operations_event_id__created = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_account_key = sa_orm_relationship(
        "AcmeAccountKey",
        primaryjoin="ServerCertificate.acme_account_key_id==AcmeAccountKey.id",
        back_populates="server_certificates__issued",
        uselist=False,
    )

    acme_orders = sa_orm_relationship(
        "AcmeOrder",
        primaryjoin="ServerCertificate.id==AcmeOrder.server_certificate_id",
        uselist=True,
        back_populates="server_certificate",
    )

    certificate_request = sa_orm_relationship(
        "CertificateRequest",
        primaryjoin="ServerCertificate.certificate_request_id==CertificateRequest.id",
        back_populates="server_certificate",
        uselist=False,
    )

    certificate_request__renewals = sa_orm_relationship(
        "CertificateRequest",
        primaryjoin="ServerCertificate.id==CertificateRequest.server_certificate_id__renewal_of",
        back_populates="server_certificate__renewal_of",
    )

    certificate_upchain = sa_orm_relationship(
        "CaCertificate",
        primaryjoin="ServerCertificate.ca_certificate_id__upchain==CaCertificate.id",
        uselist=False,
    )

    operations_event__created = sa_orm_relationship(
        "OperationsEvent",
        primaryjoin="ServerCertificate.operations_event_id__created==OperationsEvent.id",
        uselist=False,
    )

    operations_object_events = sa_orm_relationship(
        "OperationsObjectEvent",
        primaryjoin="ServerCertificate.id==OperationsObjectEvent.server_certificate_id",
        back_populates="server_certificate",
    )

    private_key = sa_orm_relationship(
        "PrivateKey",
        primaryjoin="ServerCertificate.private_key_id__signed_by==PrivateKey.id",
        back_populates="server_certificates",
        uselist=False,
    )

    # TODO: queue
    if False:
        queue_renewal = sa_orm_relationship(
            "QueueRenewal",
            primaryjoin="ServerCertificate.id==QueueRenewal.server_certificate_id",
            back_populates="server_certificate",
        )

    unique_fqdn_set = sa_orm_relationship(
        "UniqueFQDNSet",
        primaryjoin="ServerCertificate.unique_fqdn_set_id==UniqueFQDNSet.id",
        uselist=False,
        back_populates="server_certificates",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def cert_pem_modulus_search(self):
        return "type=modulus&modulus=%s&source=certificate&certificate.id=%s" % (
            self.cert_pem_modulus_md5,
            self.id,
        )

    @property
    def cert_subject_hash_search(self):
        return (
            "type=cert_subject_hash&cert_subject_hash=%s&source=certificate&certificate.id=%s"
            % (self.cert_subject_hash, self.id)
        )

    @property
    def cert_issuer_hash_search(self):
        return (
            "type=cert_issuer_hash&cert_issuer_hash=%s&source=certificate&certificate.id=%s"
            % (self.cert_issuer_hash, self.id)
        )

    @property
    def cert_fullchain_pem(self):
        return "\n".join((self.cert_pem, self.certificate_upchain.cert_pem))

    @property
    def expiring_days(self):
        if self._expiring_days is None:
            self._expiring_days = (
                self.timestamp_expires - datetime.datetime.utcnow()
            ).days
        return self._expiring_days

    _expiring_days = None

    @property
    def expiring_days_label(self):
        if self.is_active:
            if self.expiring_days <= 0:
                return "danger"
            elif self.expiring_days <= 30:
                return "warning"
            elif self.expiring_days > 30:
                return "success"
        return "danger"

    @property
    def timestamp_expires_isoformat(self):
        if self.timestamp_expires:
            return self.timestamp_expires.isoformat()
        return None

    @property
    def timestamp_signed_isoformat(self):
        if self.timestamp_signed:
            return self.timestamp_signed.isoformat()
        return None

    @property
    def timestamp_revoked_upstream_isoformat(self):
        if self.timestamp_revoked_upstream:
            return self.timestamp_revoked_upstream.isoformat()
        return None

    @property
    def config_payload(self):
        # the ids are strings so that the fullchain id can be split by a client without further processing
        return {
            "id": str(self.id),
            "private_key": {
                "id": str(self.private_key.id),
                "pem": self.private_key.key_pem,
            },
            "certificate": {"id": str(self.id), "pem": self.cert_pem},
            "chain": {
                "id": str(self.certificate_upchain.id),
                "pem": self.certificate_upchain.cert_pem,
            },
            "fullchain": {
                "id": "%s,%s" % (self.id, self.certificate_upchain.id),
                "pem": "\n".join([self.cert_fullchain_pem]),
            },
        }

    @property
    def config_payload_idonly(self):
        # the ids are strings so that the fullchain id can be split by a client without further processing
        return {
            "id": str(self.id),
            "private_key": {"id": str(self.private_key.id)},
            "certificate": {"id": str(self.id)},
            "chain": {"id": str(self.certificate_upchain.id)},
            "fullchain": {"id": "%s,%s" % (self.id, self.certificate_upchain.id)},
        }

    @property
    def can_renew_letsencrypt(self):
        """only allow renew of LE certificates"""
        if self.acme_account_key_id:
            return True
        return False

    @property
    def domains_as_string(self):
        return self.unique_fqdn_set.domains_as_string

    @property
    def domains_as_list(self):
        return self.unique_fqdn_set.domains_as_list

    @property
    def as_json(self):
        return {
            "id": self.id,
            "is_active": True if self.is_active else False,
            "is_auto_renew": True if self.is_auto_renew else False,
            "is_deactivated": True if self.is_deactivated else False,
            "is_revoked": True if self.is_revoked else False,
            "is_renewed": True if self.is_renewed else False,
            "timestamp_expires": self.timestamp_expires_isoformat,
            "timestamp_signed": self.timestamp_signed_isoformat,
            "timestamp_revoked_upstream": self.timestamp_revoked_upstream_isoformat,
            "cert_pem": self.cert_pem,
            "cert_pem_md5": self.cert_pem_md5,
            "unique_fqdn_set_id": self.unique_fqdn_set_id,
            "ca_certificate_id__upchain": self.ca_certificate_id__upchain,
            "private_key_id__signed_by": self.private_key_id__signed_by,
            "acme_account_key_id": self.acme_account_key_id,
            "domains_as_list": self.domains_as_list,
        }


class UniqueFQDNSet(Base):
    """
    There is a ratelimit in effect from LetsEncrypt for unique sets of fully-qualified domain names

    * `domain_ids_string` should be a unique list of ordered ids, separated by commas.
    * the association table is used to actually join domains to Certificates and CSRs

    """

    # note: RATELIMIT.FQDN

    __tablename__ = "unique_fqdn_set"
    id = sa.Column(sa.Integer, primary_key=True)
    domain_ids_string = sa.Column(sa.Text, nullable=False)
    timestamp_first_seen = sa.Column(sa.DateTime, nullable=False)
    operations_event_id__created = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    to_domains = sa_orm_relationship(
        "UniqueFQDNSet2Domain",
        primaryjoin="UniqueFQDNSet.id==UniqueFQDNSet2Domain.unique_fqdn_set_id",
        back_populates="unique_fqdn_set",
    )

    server_certificates = sa_orm_relationship(
        "ServerCertificate",
        primaryjoin="UniqueFQDNSet.id==ServerCertificate.unique_fqdn_set_id",
        back_populates="unique_fqdn_set",
    )

    certificate_requests = sa_orm_relationship(
        "CertificateRequest",
        primaryjoin="UniqueFQDNSet.id==CertificateRequest.unique_fqdn_set_id",
        back_populates="unique_fqdn_set",
    )

    # TODO: queue
    if False:
        queue_renewal = sa_orm_relationship(
            "QueueRenewal",
            primaryjoin="UniqueFQDNSet.id==QueueRenewal.unique_fqdn_set_id",
            back_populates="unique_fqdn_set",
        )

        queue_renewal__active = sa_orm_relationship(
            "QueueRenewal",
            primaryjoin="and_(UniqueFQDNSet.id==QueueRenewal.unique_fqdn_set_id, QueueRenewal.is_active==True)",
            back_populates="unique_fqdn_set",
        )

    operations_object_events = sa_orm_relationship(
        "OperationsObjectEvent",
        primaryjoin="UniqueFQDNSet.id==OperationsObjectEvent.unique_fqdn_set_id",
        back_populates="unique_fqdn_set",
    )

    operations_event__created = sa_orm_relationship(
        "OperationsEvent",
        primaryjoin="UniqueFQDNSet.operations_event_id__created==OperationsEvent.id",
        uselist=False,
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def domains_as_string(self):
        domains = sorted([to_d.domain.domain_name for to_d in self.to_domains])
        return ", ".join(domains)

    @property
    def domains_as_list(self):
        domain_names = [to_d.domain.domain_name.lower() for to_d in self.to_domains]
        domain_names = list(set(domain_names))
        domain_names = sorted(domain_names)
        return domain_names

    @property
    def timestamp_first_seen_isoformat(self):
        if self.timestamp_first_seen:
            return self.timestamp_first_seen.isoformat()
        return None

    @property
    def as_json(self):
        return {
            "id": self.id,
            "timestamp_first_seen": self.timestamp_first_seen_isoformat,
            "domains_as_list": self.domains_as_list,
        }


class UniqueFQDNSet2Domain(Base):
    """
    association table
    """

    # note: RATELIMIT.FQDN

    __tablename__ = "unique_fqdn_set_2_domain"
    unique_fqdn_set_id = sa.Column(
        sa.Integer, sa.ForeignKey("unique_fqdn_set.id"), primary_key=True
    )
    domain_id = sa.Column(sa.Integer, sa.ForeignKey("domain.id"), primary_key=True)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    unique_fqdn_set = sa_orm_relationship(
        "UniqueFQDNSet",
        primaryjoin="UniqueFQDNSet2Domain.unique_fqdn_set_id==UniqueFQDNSet.id",
        uselist=False,
        back_populates="to_domains",
    )

    domain = sa_orm_relationship(
        "Domain",
        primaryjoin="UniqueFQDNSet2Domain.domain_id==Domain.id",
        uselist=False,
    )


# ==============================================================================


class OperationsEvent(Base, model_utils._mixin_OperationsEventType):
    """
    Certain events are tracked for bookkeeping
    """

    __tablename__ = "operations_event"
    id = sa.Column(sa.Integer, primary_key=True)
    operations_event_type_id = sa.Column(
        sa.Integer, nullable=False
    )  # references OperationsEventType
    timestamp_event = sa.Column(sa.DateTime, nullable=True)
    event_payload = sa.Column(sa.Text, nullable=False)
    operations_event_id__child_of = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=True
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    object_events = sa_orm_relationship(
        "OperationsObjectEvent",
        primaryjoin="OperationsEvent.id==OperationsObjectEvent.operations_event_id",
        back_populates="operations_event",
    )

    children = sa_orm_relationship(
        "OperationsEvent",
        primaryjoin="OperationsEvent.id==OperationsEvent.operations_event_id__child_of",
        remote_side="OperationsEvent.operations_event_id__child_of",
        back_populates="parent",
    )

    parent = sa_orm_relationship(
        "OperationsEvent",
        primaryjoin="OperationsEvent.operations_event_id__child_of==OperationsEvent.id",
        uselist=False,
        back_populates="children",
        remote_side="OperationsEvent.id",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def event_payload_json(self):
        if self._event_payload_json is None:
            self._event_payload_json = json.loads(self.event_payload)
        return self._event_payload_json

    _event_payload_json = None

    def set_event_payload(self, payload_dict):
        self.event_payload = json.dumps(payload_dict)


class OperationsObjectEvent(Base):
    """Domains updates are noted here
    """

    __tablename__ = "operations_object_event"
    id = sa.Column(sa.Integer, primary_key=True)
    operations_event_id = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=True
    )
    operations_object_event_status_id = sa.Column(
        sa.Integer, nullable=False
    )  # references OperationsObjectEventStatus

    ca_certificate_id = sa.Column(
        sa.Integer, sa.ForeignKey("ca_certificate.id"), nullable=True
    )
    certificate_request_id = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_request.id"), nullable=True
    )
    domain_id = sa.Column(sa.Integer, sa.ForeignKey("domain.id"), nullable=True)
    acme_account_key_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_account_key.id"), nullable=True
    )
    private_key_id = sa.Column(
        sa.Integer, sa.ForeignKey("private_key.id"), nullable=True
    )
    if False:
        # TODO: Queue
        queue_domain_id = sa.Column(
            sa.Integer, sa.ForeignKey("queue_domain.id"), nullable=True
        )
        queue_renewal_id = sa.Column(
            sa.Integer, sa.ForeignKey("queue_renewal.id"), nullable=True
        )
    server_certificate_id = sa.Column(
        sa.Integer, sa.ForeignKey("server_certificate.id"), nullable=True
    )
    unique_fqdn_set_id = sa.Column(
        sa.Integer, sa.ForeignKey("unique_fqdn_set.id"), nullable=True
    )

    # TODO: Queue
    """
        CASE WHEN queue_domain_id IS NOT NULL THEN 1 ELSE 0 END
        +
        CASE WHEN queue_renewal_id IS NOT NULL THEN 1 ELSE 0 END
        +
    """
    check1 = sa.CheckConstraint(
        """(
        CASE WHEN ca_certificate_id IS NOT NULL THEN 1 ELSE 0 END
        +
        CASE WHEN certificate_request_id IS NOT NULL THEN 1 ELSE 0 END
        +
        CASE WHEN domain_id IS NOT NULL THEN 1 ELSE 0 END
        +
        CASE WHEN acme_account_key_id IS NOT NULL THEN 1 ELSE 0 END
        +
        CASE WHEN private_key_id IS NOT NULL THEN 1 ELSE 0 END
        +
        CASE WHEN server_certificate_id IS NOT NULL THEN 1 ELSE 0 END
        +
        CASE WHEN unique_fqdn_set_id IS NOT NULL THEN 1 ELSE 0 END
    ) = 1""",
        name="check1",
    )

    operations_event = sa_orm_relationship(
        "OperationsEvent",
        primaryjoin="OperationsObjectEvent.operations_event_id==OperationsEvent.id",
        uselist=False,
        back_populates="object_events",
    )

    ca_certificate = sa_orm_relationship(
        "CaCertificate",
        primaryjoin="OperationsObjectEvent.ca_certificate_id==CaCertificate.id",
        uselist=False,
        back_populates="operations_object_events",
    )

    certificate_request = sa_orm_relationship(
        "CertificateRequest",
        primaryjoin="OperationsObjectEvent.certificate_request_id==CertificateRequest.id",
        uselist=False,
        back_populates="operations_object_events",
    )

    domain = sa_orm_relationship(
        "Domain",
        primaryjoin="OperationsObjectEvent.domain_id==Domain.id",
        uselist=False,
        back_populates="operations_object_events",
    )

    acme_account_key = sa_orm_relationship(
        "AcmeAccountKey",
        primaryjoin="OperationsObjectEvent.acme_account_key_id==AcmeAccountKey.id",
        uselist=False,
        back_populates="operations_object_events",
    )

    private_key = sa_orm_relationship(
        "PrivateKey",
        primaryjoin="OperationsObjectEvent.private_key_id==PrivateKey.id",
        uselist=False,
        back_populates="operations_object_events",
    )

    if False:
        # TODO: Queue
        queue_domain = sa_orm_relationship(
            "QueueDomain",
            primaryjoin="OperationsObjectEvent.queue_domain_id==QueueDomain.id",
            uselist=False,
            back_populates="operations_object_events",
        )
        queue_renewal = sa_orm_relationship(
            "QueueRenewal",
            primaryjoin="OperationsObjectEvent.queue_renewal_id==QueueRenewal.id",
            uselist=False,
            back_populates="operations_object_events",
        )

    server_certificate = sa_orm_relationship(
        "ServerCertificate",
        primaryjoin="OperationsObjectEvent.server_certificate_id==ServerCertificate.id",
        uselist=False,
        back_populates="operations_object_events",
    )

    unique_fqdn_set = sa_orm_relationship(
        "UniqueFQDNSet",
        primaryjoin="OperationsObjectEvent.unique_fqdn_set_id==UniqueFQDNSet.id",
        uselist=False,
        back_populates="operations_object_events",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def event_status_text(self):
        return model_utils.OperationsObjectEventStatus.as_string(
            self.operations_object_event_status_id
        )


# ==============================================================================


# !!!: Advanced Relationships Below

# note: AcmeAccountKey.acme_orders__5
AcmeAccountKey.acme_orders__5 = sa_orm_relationship(
    AcmeOrder,
    primaryjoin=(
        sa.and_(
            AcmeAccountKey.id == AcmeOrder.acme_account_key_id,
            AcmeOrder.id.in_(
                sa.select([AcmeOrder.id])
                .where(AcmeAccountKey.id == AcmeOrder.acme_account_key_id)
                .order_by(AcmeOrder.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=AcmeOrder.id.desc(),
    viewonly=True,
)

# note: AcmeAccountKey.certificate_requests__5
AcmeAccountKey.certificate_requests__5 = sa_orm_relationship(
    CertificateRequest,
    primaryjoin="AcmeAccountKey.id == AcmeOrder.acme_account_key_id",
    secondary=(
        """join(AcmeOrder,
                CertificateRequest,
                AcmeOrder.certificate_request_id == CertificateRequest.id
                )"""
    ),
    secondaryjoin=(
        sa.and_(
            CertificateRequest.id == sa.orm.foreign(AcmeOrder.certificate_request_id),
            CertificateRequest.id.in_(
                sa.select([CertificateRequest.id])
                .where(CertificateRequest.id == AcmeOrder.certificate_request_id)
                .where(AcmeOrder.acme_account_key_id == AcmeAccountKey.id)
                .order_by(CertificateRequest.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=CertificateRequest.id.desc(),
    viewonly=True,
)


# note: AcmeAccountKey.server_certificates__5
AcmeAccountKey.server_certificates__5 = sa_orm_relationship(
    ServerCertificate,
    primaryjoin=(
        sa.and_(
            AcmeAccountKey.id == ServerCertificate.acme_account_key_id,
            ServerCertificate.id.in_(
                sa.select([ServerCertificate.id])
                .where(AcmeAccountKey.id == ServerCertificate.acme_account_key_id)
                .order_by(ServerCertificate.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=ServerCertificate.id.desc(),
    viewonly=True,
)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# note: PrivateKey.certificate_requests__5
PrivateKey.certificate_requests__5 = sa_orm_relationship(
    CertificateRequest,
    primaryjoin=(
        sa.and_(
            PrivateKey.id == CertificateRequest.private_key_id__signed_by,
            CertificateRequest.id.in_(
                sa.select([CertificateRequest.id])
                .where(PrivateKey.id == CertificateRequest.private_key_id__signed_by)
                .order_by(CertificateRequest.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=CertificateRequest.id.desc(),
    viewonly=True,
)


# note: PrivateKey.server_certificates__5
PrivateKey.server_certificates__5 = sa_orm_relationship(
    ServerCertificate,
    primaryjoin=(
        sa.and_(
            PrivateKey.id == ServerCertificate.private_key_id__signed_by,
            ServerCertificate.id.in_(
                sa.select([ServerCertificate.id])
                .where(PrivateKey.id == ServerCertificate.private_key_id__signed_by)
                .order_by(ServerCertificate.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=ServerCertificate.id.desc(),
    viewonly=True,
)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# note: CertificateRequest.latest_acme_order
CertificateRequest.latest_acme_order = sa_orm_relationship(
    AcmeOrder,
    primaryjoin=(
        sa.and_(
            CertificateRequest.id == AcmeOrder.certificate_request_id,
            AcmeOrder.id.in_(
                sa.select([sa.func.max(AcmeOrder.id)])
                .where(AcmeOrder.certificate_request_id == CertificateRequest.id)
                .correlate()
            ),
        )
    ),
    uselist=False,
    viewonly=True,
)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# note: Domain.acme_orders__5
Domain.acme_orders__5 = sa_orm_relationship(
    AcmeOrder,
    primaryjoin="Domain.id == UniqueFQDNSet2Domain.domain_id",
    secondary=(
        """join(UniqueFQDNSet2Domain,
                AcmeOrder,
                UniqueFQDNSet2Domain.unique_fqdn_set_id == AcmeOrder.unique_fqdn_set_id
                )"""
    ),
    secondaryjoin=(
        sa.and_(
            AcmeOrder.unique_fqdn_set_id
            == sa.orm.foreign(UniqueFQDNSet2Domain.unique_fqdn_set_id),
            AcmeOrder.id.in_(
                sa.select([AcmeOrder.id])
                .where(
                    AcmeOrder.unique_fqdn_set_id
                    == UniqueFQDNSet2Domain.unique_fqdn_set_id
                )
                .where(UniqueFQDNSet2Domain.domain_id == Domain.id)
                .order_by(AcmeOrder.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=AcmeOrder.id.desc(),
    viewonly=True,
)

# note: Domain.certificate_requests__5
# returns an object with a `certificate` on it
Domain.certificate_requests__5 = sa_orm_relationship(
    CertificateRequest,
    primaryjoin="Domain.id == UniqueFQDNSet2Domain.domain_id",
    secondary=(
        """join(UniqueFQDNSet2Domain,
                CertificateRequest,
                UniqueFQDNSet2Domain.unique_fqdn_set_id == CertificateRequest.unique_fqdn_set_id
                )"""
    ),
    secondaryjoin=(
        sa.and_(
            CertificateRequest.unique_fqdn_set_id
            == sa.orm.foreign(UniqueFQDNSet2Domain.unique_fqdn_set_id),
            CertificateRequest.id.in_(
                sa.select([CertificateRequest.id])
                .where(
                    CertificateRequest.unique_fqdn_set_id
                    == UniqueFQDNSet2Domain.unique_fqdn_set_id
                )
                .where(UniqueFQDNSet2Domain.domain_id == Domain.id)
                .order_by(CertificateRequest.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=CertificateRequest.id.desc(),
    viewonly=True,
)


# note: Domain.server_certificates__5
# returns an object with a `certificate` on it
Domain.server_certificates__5 = sa_orm_relationship(
    ServerCertificate,
    primaryjoin="Domain.id == UniqueFQDNSet2Domain.domain_id",
    secondary=(
        """join(UniqueFQDNSet2Domain,
                ServerCertificate,
                UniqueFQDNSet2Domain.unique_fqdn_set_id == ServerCertificate.unique_fqdn_set_id
                )"""
    ),
    secondaryjoin=(
        sa.and_(
            ServerCertificate.unique_fqdn_set_id
            == sa.orm.foreign(UniqueFQDNSet2Domain.unique_fqdn_set_id),
            ServerCertificate.id.in_(
                sa.select([ServerCertificate.id])
                .where(
                    ServerCertificate.unique_fqdn_set_id
                    == UniqueFQDNSet2Domain.unique_fqdn_set_id
                )
                .where(UniqueFQDNSet2Domain.domain_id == Domain.id)
                .order_by(ServerCertificate.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=ServerCertificate.id.desc(),
    viewonly=True,
)


# note: Domain.to_unique_fqdn_sets__5
# returns an object with a `unique_fqdn_set` on it
Domain.to_unique_fqdn_sets__5 = sa_orm_relationship(
    UniqueFQDNSet2Domain,
    primaryjoin=(
        sa.and_(
            Domain.id == UniqueFQDNSet2Domain.domain_id,
            UniqueFQDNSet2Domain.unique_fqdn_set_id.in_(
                sa.select([UniqueFQDNSet2Domain.unique_fqdn_set_id])
                .where(Domain.id == UniqueFQDNSet2Domain.domain_id)
                .order_by(UniqueFQDNSet2Domain.unique_fqdn_set_id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=UniqueFQDNSet2Domain.unique_fqdn_set_id.desc(),
    viewonly=True,
)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# note: UniqueFQDNSet.certificate_requests__5
UniqueFQDNSet.certificate_requests__5 = sa_orm_relationship(
    CertificateRequest,
    primaryjoin=(
        sa.and_(
            UniqueFQDNSet.id == CertificateRequest.unique_fqdn_set_id,
            CertificateRequest.id.in_(
                sa.select([CertificateRequest.id])
                .where(UniqueFQDNSet.id == CertificateRequest.unique_fqdn_set_id)
                .order_by(CertificateRequest.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=CertificateRequest.id.desc(),
    viewonly=True,
)


# note: UniqueFQDNSet.server_certificates__5
UniqueFQDNSet.server_certificates__5 = sa_orm_relationship(
    ServerCertificate,
    primaryjoin=(
        sa.and_(
            UniqueFQDNSet.id == ServerCertificate.unique_fqdn_set_id,
            ServerCertificate.id.in_(
                sa.select([ServerCertificate.id])
                .where(UniqueFQDNSet.id == ServerCertificate.unique_fqdn_set_id)
                .order_by(ServerCertificate.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=ServerCertificate.id.desc(),
    viewonly=True,
)


# note: UniqueFQDNSet.latest_certificate
UniqueFQDNSet.latest_certificate = sa_orm_relationship(
    ServerCertificate,
    primaryjoin=(
        sa.and_(
            UniqueFQDNSet.id == ServerCertificate.unique_fqdn_set_id,
            ServerCertificate.id.in_(
                sa.select([sa.func.max(ServerCertificate.id)])
                .where(UniqueFQDNSet.id == ServerCertificate.unique_fqdn_set_id)
                .correlate()
            ),
        )
    ),
    uselist=False,
    viewonly=True,
)

# note: UniqueFQDNSet.latest_active_certificate
UniqueFQDNSet.latest_active_certificate = sa_orm_relationship(
    ServerCertificate,
    primaryjoin=(
        sa.and_(
            UniqueFQDNSet.id == ServerCertificate.unique_fqdn_set_id,
            ServerCertificate.id.in_(
                sa.select([sa.func.max(ServerCertificate.id)])
                .where(UniqueFQDNSet.id == ServerCertificate.unique_fqdn_set_id)
                .where(ServerCertificate.is_active.op("IS")(True))
                .correlate()
            ),
        )
    ),
    uselist=False,
    viewonly=True,
)
