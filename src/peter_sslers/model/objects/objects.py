# stdlib
import datetime
import json

# pypi
from pyramid.decorator import reify
import sqlalchemy as sa
from sqlalchemy.orm import relationship as sa_orm_relationship
from sqlalchemy.orm.session import Session as sa_Session

# from sqlalchemy import inspect as sa_inspect

# local
from .mixins import _Mixin_Hex_Pretty
from .mixins import _Mixin_Timestamps_Pretty
from .. import utils as model_utils
from ..meta import Base


# ==============================================================================


class AcmeAccount(Base, _Mixin_Timestamps_Pretty):
    """
    Represents a registered account with the LetsEncrypt Service.
    This is used for authentication to the LE API, it is not tied to any certificates.

    A `PrivateKey` can be locked to an `AcmeAccount` via `PrivateKey.acme_account_id__owner`
    """

    __tablename__ = "acme_account"

    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)

    contact = sa.Column(sa.Unicode(255), nullable=True)
    terms_of_service = sa.Column(sa.Unicode(255), nullable=True)
    account_url = sa.Column(sa.Unicode(255), nullable=True, unique=True)

    count_acme_orders = sa.Column(sa.Integer, nullable=True, default=0)
    count_certificate_signeds = sa.Column(sa.Integer, nullable=True, default=0)

    timestamp_last_certificate_request = sa.Column(sa.DateTime, nullable=True)
    timestamp_last_certificate_issue = sa.Column(sa.DateTime, nullable=True)
    timestamp_last_authenticated = sa.Column(sa.DateTime, nullable=True)

    is_active = sa.Column(sa.Boolean, nullable=False, default=True)
    is_global_default = sa.Column(sa.Boolean, nullable=True, default=None)

    acme_account_provider_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_account_provider.id"), nullable=False
    )

    private_key_cycle_id = sa.Column(
        sa.Integer, nullable=False
    )  # see .utils.PrivateKeyCycle
    private_key_technology_id = sa.Column(
        sa.Integer, nullable=False
    )  # see .utils.KeyTechnology

    timestamp_deactivated = sa.Column(sa.DateTime, nullable=True)

    operations_event_id__created = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    # active
    acme_account_key = sa_orm_relationship(
        "AcmeAccountKey",
        primaryjoin=(
            "and_("
            "AcmeAccount.id==AcmeAccountKey.acme_account_id,"
            "AcmeAccountKey.is_active.is_(True)"
            ")"
        ),
        uselist=False,
        viewonly=True,  # the `AcmeAccountKey.is_active` join complicates things
    )
    acme_account_keys_all = sa_orm_relationship(
        "AcmeAccountKey",
        primaryjoin="AcmeAccount.id==AcmeAccountKey.acme_account_id",
        uselist=True,
        back_populates="acme_account",
    )
    acme_account_provider = sa_orm_relationship(
        "AcmeAccountProvider",
        primaryjoin=("AcmeAccount.acme_account_provider_id==AcmeAccountProvider.id"),
        uselist=False,
        back_populates="acme_accounts",
    )
    acme_orders = sa_orm_relationship(
        "AcmeOrder",
        primaryjoin="AcmeAccount.id==AcmeOrder.acme_account_id",
        order_by="AcmeOrder.id.desc()",
        uselist=True,
        back_populates="acme_account",
    )
    acme_orderlesss = sa_orm_relationship(
        "AcmeOrderless",
        primaryjoin="AcmeAccount.id==AcmeOrderless.acme_account_id",
        uselist=True,
        back_populates="acme_account",
    )
    operations_object_events = sa_orm_relationship(
        "OperationsObjectEvent",
        primaryjoin="AcmeAccount.id==OperationsObjectEvent.acme_account_id",
        back_populates="acme_account",
    )
    operations_event__created = sa_orm_relationship(
        "OperationsEvent",
        primaryjoin=("AcmeAccount.operations_event_id__created==OperationsEvent.id"),
        uselist=False,
    )
    private_keys__owned = sa_orm_relationship(
        "PrivateKey",
        primaryjoin="AcmeAccount.id==PrivateKey.acme_account_id__owner",
        uselist=True,
        back_populates="acme_account__owner",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def is_usable(self):
        """check the AcmeAccount and AcmeAccountKey are both active"""
        if self.is_active:
            # `.acme_account_key` is joined on `is_active`
            if self.acme_account_key:
                return True
        return False

    @property
    def is_can_authenticate(self):
        if self.acme_account_provider.protocol == "acme-v2":
            return True
        return False

    @property
    def is_can_deactivate(self):
        if self.is_active:
            return True
        return False

    @property
    def is_can_key_change(self):
        if self.is_active:
            return True
        return False

    @property
    def is_global_default_candidate(self):
        if self.is_global_default:
            return False
        if not self.is_active:
            return False
        if not self.acme_account_key:
            return False
        if not self.acme_account_key.is_active:
            return False
        if self.acme_account_provider.is_default:
            return True
        return False

    @reify
    def key_spki_search(self):
        if not self.acme_account_key:
            return "type=error&error=missing-acme-account-key"
        return self.acme_account_key.key_spki_search

    @reify
    def key_pem_sample(self):
        if not self.acme_account_key:
            return ""
        return self.acme_account_key.key_pem_sample

    @reify
    def private_key_cycle(self):
        return model_utils.PrivateKeyCycle.as_string(self.private_key_cycle_id)

    @reify
    def private_key_technology(self):
        return model_utils.KeyTechnology.as_string(self.private_key_technology_id)

    @property
    def as_json(self):
        return {
            "is_active": True if self.is_active else False,
            "is_deactivated": self.timestamp_deactivated or False,
            "is_global_default": True if self.is_global_default else False,
            "acme_account_provider_id": self.acme_account_provider_id,
            "acme_account_provider_name": self.acme_account_provider.name,
            "acme_account_provider_url": self.acme_account_provider.url,
            "acme_account_provider_protocol": self.acme_account_provider.protocol,
            "AcmeAccountKey": self.acme_account_key.as_json
            if self.acme_account_key
            else None,
            "id": self.id,
            "private_key_cycle": self.private_key_cycle,
            "contact": self.contact,
            "account_url": self.account_url,
        }


class AcmeAccountKey(Base, _Mixin_Timestamps_Pretty, _Mixin_Hex_Pretty):
    """
    Represents a key associated with the AcmeAccount on the LetsEncrypt Service.
    This is used for authentication to the LE API, it is not tied to any certificates directly.
    """

    __tablename__ = "acme_account_key"
    __table_args__ = (
        sa.Index(
            "uidx_acme_account_key_active",
            "acme_account_id",
            "is_active",
            unique=True,
        ),
    )

    id = sa.Column(sa.Integer, primary_key=True)
    acme_account_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_account.id"), nullable=False
    )
    is_active = sa.Column(sa.Boolean, nullable=True, default=None)

    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    timestamp_deactivated = sa.Column(sa.DateTime, nullable=True)
    key_technology_id = sa.Column(
        sa.Integer, nullable=False
    )  # see .utils.KeyTechnology

    key_pem = sa.Column(sa.Text, nullable=True)
    key_pem_md5 = sa.Column(sa.Unicode(32), nullable=False)
    spki_sha256 = sa.Column(sa.Unicode(64), nullable=False)

    operations_event_id__created = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )

    acme_account_key_source_id = sa.Column(
        sa.Integer, nullable=False
    )  # see .utils.AcmeAccountKeySource

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_account = sa_orm_relationship(
        "AcmeAccount",
        primaryjoin="AcmeAccountKey.acme_account_id==AcmeAccount.id",
        uselist=False,
        back_populates="acme_account_keys_all",
    )

    operations_object_events = sa_orm_relationship(
        "OperationsObjectEvent",
        primaryjoin=("AcmeAccountKey.id==OperationsObjectEvent.acme_account_key_id"),
        back_populates="acme_account_key",
    )
    operations_event__created = sa_orm_relationship(
        "OperationsEvent",
        primaryjoin=("AcmeAccountKey.operations_event_id__created==OperationsEvent.id"),
        uselist=False,
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @reify
    def acme_account_key_source(self):
        return model_utils.AcmeAccountKeySource.as_string(
            self.acme_account_key_source_id
        )

    @reify
    def key_spki_search(self):
        return "type=spki&spki=%s&source=acme_account_key&acme_account_key.id=%s&acme_account.id=%s" % (
            self.spki_sha256,
            self.id,
            self.acme_account_id,
        )

    @reify
    def key_pem_sample(self):
        # strip the pem, because the last line is whitespace after
        # "-----END RSA PRIVATE KEY-----"
        pem_lines = self.key_pem.strip().split("\n")
        return "%s...%s" % (pem_lines[1][0:5], pem_lines[-2][-5:])

    @property
    def key_technology(self):
        if self.key_technology_id:
            return model_utils.KeyTechnology.as_string(self.key_technology_id)
        return None

    @property
    def as_json(self):
        return {
            "id": self.id,
            "key_pem": self.key_pem,
            "key_pem_md5": self.key_pem_md5,
            "spki_sha256": self.spki_sha256,
            "acme_account_key_source": self.acme_account_key_source,
            "is_active": self.is_active,
        }


# ==============================================================================


class AcmeAccountProvider(Base, _Mixin_Timestamps_Pretty):
    """
    Represents an AcmeAccountProvider
    """

    __tablename__ = "acme_account_provider"
    __table_args__ = (
        sa.CheckConstraint(
            "(endpoint IS NOT NULL AND directory IS NULL)"
            " OR "
            " (endpoint IS NULL AND directory IS NOT NULL)",
            name="check_endpoint_or_directory",
        ),
        sa.CheckConstraint(
            "(protocol = 'acme-v1')" " OR " "(protocol = 'acme-v2')",
            name="check_protocol",
        ),
    )
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    name = sa.Column(sa.Unicode(32), nullable=False, unique=True)
    endpoint = sa.Column(sa.Unicode(255), nullable=True, unique=True)  # either/or: A
    directory = sa.Column(sa.Unicode(255), nullable=True, unique=True)  # either/or: A
    server = sa.Column(sa.Unicode(255), nullable=False, unique=True)
    is_default = sa.Column(sa.Boolean, nullable=True, default=None)
    is_enabled = sa.Column(sa.Boolean, nullable=True, default=None)
    protocol = sa.Column(sa.Unicode(32), nullable=False)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_accounts = sa_orm_relationship(
        "AcmeAccount",
        primaryjoin=("AcmeAccountProvider.id==AcmeAccount.acme_account_provider_id"),
        order_by="AcmeAccount.id.desc()",
        uselist=True,
        back_populates="acme_account_provider",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _disable(self):
        """
        This should only be invoked by commandline tools
        """
        _changed = 0
        if self.is_default:
            self.is_default = False
            _changed += 1
        if self.is_enabled:
            self.is_enabled = False
            _changed += 1
        return True if _changed else False

    @property
    def url(self):
        return self.directory or self.endpoint

    @property
    def as_json(self):
        return {
            "id": self.id,
            "timestamp_created": self.timestamp_created_isoformat,
            "name": self.name,
            "endpoint": self.endpoint,
            "directory": self.directory,
            "is_default": self.is_default or False,
            "is_enabled": self.is_enabled or False,
            "protocol": self.protocol,
        }


# ==============================================================================


class AcmeAuthorization(Base, _Mixin_Timestamps_Pretty):
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

    Example:

       {
         "status": "valid",
         "expires": "2015-03-01T14:09:07.99Z",

         "identifier": {
           "type": "dns",
           "value": "www.example.org"
         },

         "challenges": [
           {
             "url": "https://example.com/acme/chall/prV_B7yEyA4",
             "type": "http-01",
             "status": "valid",
             "token": "DGyRejmCefe7v4NfDGDKfA",
             "validated": "2014-12-01T12:05:58.16Z"
           }
         ],

         "wildcard": false
       }

    ------------------------------------------------------------------------

    Authorizations

        https://tools.ietf.org/html/rfc8555#section-7.1.4

            status (required, string):  The status of this authorization.
                Possible values are "pending", "valid", "invalid", "deactivated",
                "expired", and "revoked".  See Section 7.1.6.

        https://tools.ietf.org/html/rfc8555#page-31

           Authorization objects are created in the "pending" state.  If one of
           the challenges listed in the authorization transitions to the "valid"
           state, then the authorization also changes to the "valid" state.  If
           the client attempts to fulfill a challenge and fails, or if there is
           an error while the authorization is still pending, then the
           authorization transitions to the "invalid" state.  Once the
           authorization is in the "valid" state, it can expire ("expired"), be
           deactivated by the client ("deactivated", see Section 7.5.2), or
           revoked by the server ("revoked").

        Therefore:

            "pending"
                newly created
            "valid"
                one or more challenges is valid
            "invalid"
                a challenge failed
            "deactivated"
                deactivated by the client
            "expired"
                a valid challenge has expired
            "revoked"
                revoked by the server
    """

    __tablename__ = "acme_authorization"
    id = sa.Column(sa.Integer, primary_key=True)
    authorization_url = sa.Column(sa.Unicode(255), nullable=False, unique=True)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    acme_status_authorization_id = sa.Column(
        sa.Integer, nullable=False
    )  # Acme_Status_Authorization
    domain_id = sa.Column(sa.Integer, sa.ForeignKey("domain.id"), nullable=True)
    timestamp_expires = sa.Column(sa.DateTime, nullable=True)
    timestamp_updated = sa.Column(sa.DateTime, nullable=True)
    wildcard = sa.Column(sa.Boolean, nullable=True, default=None)

    # the RFC does not explicitly tie an AcmeAuthorization to a single AcmeOrder
    # this is only used to easily grab an AcmeAccount
    acme_order_id__created = sa.Column(
        sa.Integer,
        sa.ForeignKey("acme_order.id", use_alter=True),
        nullable=False,
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    domain = sa_orm_relationship(
        "Domain",
        primaryjoin="AcmeAuthorization.domain_id==Domain.id",
        uselist=False,
        back_populates="acme_authorizations",
    )
    acme_challenges = sa_orm_relationship(
        "AcmeChallenge",
        primaryjoin="AcmeAuthorization.id==AcmeChallenge.acme_authorization_id",
        uselist=True,
        back_populates="acme_authorization",
    )

    acme_challenge_http_01 = sa_orm_relationship(
        "AcmeChallenge",
        primaryjoin=(
            "and_("
            "AcmeAuthorization.id==AcmeChallenge.acme_authorization_id,"
            "AcmeChallenge.acme_challenge_type_id==%s"
            ")" % model_utils.AcmeChallengeType.from_string("http-01")
        ),
        uselist=False,
        overlaps="acme_challenges,acme_challenge_dns_01,acme_challenge_http_01,acme_challenge_tls_alpn_01",
    )
    acme_challenge_dns_01 = sa_orm_relationship(
        "AcmeChallenge",
        primaryjoin=(
            "and_("
            "AcmeAuthorization.id==AcmeChallenge.acme_authorization_id,"
            "AcmeChallenge.acme_challenge_type_id==%s"
            ")" % model_utils.AcmeChallengeType.from_string("dns-01")
        ),
        uselist=False,
        overlaps="acme_challenges,acme_challenge_dns_01,acme_challenge_http_01,acme_challenge_tls_alpn_01",
    )
    acme_challenge_tls_alpn_01 = sa_orm_relationship(
        "AcmeChallenge",
        primaryjoin=(
            "and_("
            "AcmeAuthorization.id==AcmeChallenge.acme_authorization_id,"
            "AcmeChallenge.acme_challenge_type_id==%s"
            ")" % model_utils.AcmeChallengeType.from_string("tls-alpn-01")
        ),
        uselist=False,
        overlaps="acme_challenges,acme_challenge_dns_01,acme_challenge_http_01,acme_challenge_tls_alpn_01",
    )
    # this is only used to easily grab an AcmeAccount
    acme_order_created = sa_orm_relationship(
        "AcmeOrder",
        primaryjoin="AcmeAuthorization.acme_order_id__created==AcmeOrder.id",
        uselist=False,
    )
    to_acme_orders = sa_orm_relationship(
        "AcmeOrder2AcmeAuthorization",
        primaryjoin=(
            "AcmeAuthorization.id==AcmeOrder2AcmeAuthorization.acme_authorization_id"
        ),
        uselist=True,
        back_populates="acme_authorization",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def acme_status_authorization(self):
        return model_utils.Acme_Status_Authorization.as_string(
            self.acme_status_authorization_id
        )

    @property
    def is_acme_server_pending(self):
        if (
            self.acme_status_authorization
            in model_utils.Acme_Status_Authorization.OPTIONS_POSSIBLY_PENDING
        ):
            return True
        return False

    @property
    def is_can_acme_server_deactivate(self):
        # ???: is there a better way to test this?
        if not self.authorization_url:
            return False
        if (
            self.acme_status_authorization
            not in model_utils.Acme_Status_Authorization.OPTIONS_DEACTIVATE
        ):
            return False
        return True

    @property
    def is_can_acme_server_process(self):
        """
        can the auth be triggered?
        two scenarios:
        1_ auth is *discovered*, not synced yet
        2_ auth is synced, can be triggered
        """
        if (
            self.acme_status_authorization_id
            == model_utils.Acme_Status_Authorization.ID_DISCOVERED
        ):
            return True
        return self.is_can_acme_server_trigger

    @property
    def is_can_acme_server_trigger(self):
        """
        can the auth be triggered?
        this requires a loaded auth
        """
        if not self.authorization_url:
            return False
        if (
            self.acme_status_authorization
            not in model_utils.Acme_Status_Authorization.OPTIONS_TRIGGER
        ):
            return False
        #
        # we only support `acme_challenge_http_01`
        #
        if not self.acme_challenge_http_01:
            return False
        if not self.acme_challenge_http_01.is_can_acme_server_trigger:
            return False
        return True

    @property
    def is_can_acme_server_sync(self):
        # ???: is there a better way to test this?
        if not self.authorization_url:
            return False
        return True

    @property
    def as_json(self):
        dbSession = sa_Session.object_session(self)
        request = dbSession.info["request"]
        admin_url = request.admin_url if request else ""

        return {
            "id": self.id,
            "acme_status_authorization": self.acme_status_authorization,
            "acme_challenge_http_01_id": self.acme_challenge_http_01.id
            if self.acme_challenge_http_01
            else None,
            "acme_challenge_dns_01_id": self.acme_challenge_dns_01.id
            if self.acme_challenge_dns_01
            else None,
            "domain": {
                "id": self.domain_id,
                "domain_name": self.domain.domain_name,
            }
            if self.domain_id
            else None,
            "url_acme_server_sync": "%s/acme-authorization/%s/acme-server/sync.json"
            % (admin_url, self.id)
            if self.is_can_acme_server_sync
            else None,
            "url_acme_server_deactivate": "%s/acme-authorization/%s/acme-server/deactivate.json"
            % (admin_url, self.id)
            if self.is_can_acme_server_deactivate
            else None,
        }


# ==============================================================================


class AcmeChallenge(Base, _Mixin_Timestamps_Pretty):
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

    - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    Challenges

        https://tools.ietf.org/html/rfc8555#section-8

            status (required, string):  The status of this challenge.  Possible
               values are "pending", "processing", "valid", and "invalid" (see
               Section 7.1.6).

        https://tools.ietf.org/html/rfc8555#section-7.1.6

            Challenge objects are created in the "pending" state.  They
            transition to the "processing" state when the client responds to the
            challenge (see Section 7.5.1) and the server begins attempting to
            validate that the client has completed the challenge.  Note that
            within the "processing" state, the server may attempt to validate the
            challenge multiple times (see Section 8.2).  Likewise, client
            requests for retries do not cause a state change.  If validation is
            successful, the challenge moves to the "valid" state; if there is an
            error, the challenge moves to the "invalid" state.

        Therefore:

            "pending"
                newly created
            "processing"
                the client has responded to the challenge
            "valid"
                the ACME server has validated the challenge
            "invalid"
                the ACME server encountered an error when validating
    """

    __tablename__ = "acme_challenge"
    __table_args__ = (
        sa.CheckConstraint(
            "(acme_authorization_id IS NOT NULL AND acme_orderless_id IS NULL)"
            " OR "
            " (acme_authorization_id IS NULL AND acme_orderless_id IS NOT NULL)",
            name="check_authorization_or_orderless",
        ),
        sa.CheckConstraint(
            "token IS NOT NULL"
            " OR "
            " (token IS NULL AND acme_orderless_id IS NOT NULL)",
            name="token_sanity",
        ),
    )

    id = sa.Column(sa.Integer, primary_key=True)

    # our challenge will either be from:
    # 1) an `AcmeOrder`->`AcmeAuthorization`
    acme_authorization_id = sa.Column(
        sa.Integer,
        sa.ForeignKey("acme_authorization.id"),
        nullable=True,
    )
    # 2) an `AcmeOrderless`
    acme_orderless_id = sa.Column(
        sa.Integer,
        sa.ForeignKey("acme_orderless.id"),
        nullable=True,
    )

    # `AcmeOrderless` requires a domain; duplicating this for `AcmeOrder` is fine
    domain_id = sa.Column(sa.Integer, sa.ForeignKey("domain.id"), nullable=False)

    # in all situations, we need to track these:
    acme_challenge_type_id = sa.Column(
        sa.Integer, nullable=False
    )  # `model_utils.AcmeChallengeType`
    acme_status_challenge_id = sa.Column(
        sa.Integer, nullable=False
    )  # Acme_Status_Challenge

    # this is on the acme server
    challenge_url = sa.Column(sa.Unicode(255), nullable=True, unique=True)

    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    timestamp_updated = sa.Column(sa.DateTime, nullable=True)

    token = sa.Column(
        sa.Unicode(255), nullable=True
    )  # only nullable if this is an orderless challenge
    # token_clean = re.sub(r"[^A-Za-z0-9_\-]", "_", dbAcmeAuthorization.acme_challenge_http_01.token)
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
        back_populates="acme_challenges",
        overlaps="acme_challenge_dns_01,acme_challenge_http_01,acme_challenge_tls_alpn_01",
    )
    acme_orderless = sa_orm_relationship(
        "AcmeOrderless",
        primaryjoin="AcmeChallenge.acme_orderless_id==AcmeOrderless.id",
        uselist=False,
        back_populates="acme_challenges",
    )
    domain = sa_orm_relationship(
        "Domain",
        primaryjoin="AcmeChallenge.domain_id==Domain.id",
        uselist=False,
        back_populates="acme_challenges",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def acme_challenge_type(self):
        if self.acme_challenge_type_id:
            return model_utils.AcmeChallengeType.as_string(self.acme_challenge_type_id)
        return None

    @property
    def acme_status_challenge(self):
        return model_utils.Acme_Status_Challenge.as_string(
            self.acme_status_challenge_id
        )

    @property
    def domain_name(self):
        return self.domain.domain_name

    @property
    def challenge_instructions_short(self):
        if self.acme_challenge_type == "http-01":
            return "PeterSSLers is configured to answer this challenge."
        elif self.acme_challenge_type == "dns-01":
            return "This challenge may require DNS configuration."
        return "PeterSSLers can not answer this challenge."

    @property
    def is_can_acme_server_sync(self):
        if not self.challenge_url:
            return False
        if not self.acme_authorization_id:
            # auth's order_id needed for the AcmeAccount
            return False
        return True

    @property
    def is_can_acme_server_trigger(self):
        if not self.challenge_url:
            return False
        if not self.acme_authorization_id:
            # auth's order_id needed for the AcmeAccount
            return False
        if (
            self.acme_status_challenge
            not in model_utils.Acme_Status_Challenge.OPTIONS_TRIGGER
        ):
            return False
        return True

    @property
    def is_configured_to_answer(self):
        if not self.is_can_acme_server_trigger:
            return False
        if self.acme_challenge_type == "http-01":
            return True
        elif self.acme_challenge_type == "dns-01":
            if self.domain.acme_dns_server_account__active:
                return True
        return False

    @property
    def as_json(self):
        dbSession = sa_Session.object_session(self)
        request = dbSession.info["request"]
        admin_url = request.admin_url if request else ""

        return {
            "id": self.id,
            "acme_challenge_type": self.acme_challenge_type,
            "acme_status_challenge": self.acme_status_challenge,
            "domain": {
                "id": self.domain_id,
                "domain_name": self.domain.domain_name,
            },
            "keyauthorization": self.keyauthorization,
            "timestamp_created": self.timestamp_created_isoformat,
            "timestamp_updated": self.timestamp_updated_isoformat,
            "token": self.token,
            "url_acme_server_sync": "%s/acme-challenge/%s/acme-server/sync.json"
            % (admin_url, self.id)
            if self.is_can_acme_server_sync
            else None,
            "url_acme_server_trigger": "%s/acme-challenge/%s/acme-server/trigger.json"
            % (admin_url, self.id)
            if self.is_can_acme_server_trigger
            else None,
            # "acme_event_log_id": self.acme_event_log_id,
        }


# ==============================================================================


class AcmeChallengeCompeting(Base, _Mixin_Timestamps_Pretty):
    # This is for tracking an EdgeCase
    __tablename__ = "acme_challenge_competing"

    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    domain_id = sa.Column(sa.Integer, sa.ForeignKey("domain.id"), nullable=True)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    domain = sa_orm_relationship(
        "Domain",
        primaryjoin="AcmeChallengeCompeting.domain_id==Domain.id",
        uselist=False,
    )

    acme_challenge_competing_2_acme_challenge = sa_orm_relationship(
        "AcmeChallengeCompeting2AcmeChallenge",
        primaryjoin=(
            "AcmeChallengeCompeting.id==AcmeChallengeCompeting2AcmeChallenge.acme_challenge_competing_id"
        ),
        uselist=True,
        back_populates="acme_challenge_competing",
    )


class AcmeChallengeCompeting2AcmeChallenge(Base, _Mixin_Timestamps_Pretty):
    __tablename__ = "acme_challenge_competing_2_acme_challenge"

    acme_challenge_competing_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_challenge_competing.id"), primary_key=True
    )
    acme_challenge_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_challenge.id"), primary_key=True
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_challenge_competing = sa_orm_relationship(
        "AcmeChallengeCompeting",
        primaryjoin=(
            "AcmeChallengeCompeting2AcmeChallenge.acme_challenge_competing_id==AcmeChallengeCompeting.id"
        ),
        uselist=False,
        back_populates="acme_challenge_competing_2_acme_challenge",
    )

    acme_challenge = sa_orm_relationship(
        "AcmeChallenge",
        primaryjoin=(
            "AcmeChallengeCompeting2AcmeChallenge.acme_challenge_id==AcmeChallenge.id"
        ),
        uselist=False,
    )


# ==============================================================================


class AcmeChallengePoll(Base, _Mixin_Timestamps_Pretty):
    """
    log ACME Challenge polls
    """

    __tablename__ = "acme_challenge_poll"

    id = sa.Column(sa.Integer, primary_key=True)
    acme_challenge_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_challenge.id"), nullable=False
    )
    timestamp_polled = sa.Column(sa.DateTime, nullable=False)
    remote_ip_address_id = sa.Column(
        sa.Integer, sa.ForeignKey("remote_ip_address.id"), nullable=False
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_challenge = sa_orm_relationship(
        "AcmeChallenge",
        primaryjoin="AcmeChallengePoll.acme_challenge_id==AcmeChallenge.id",
        uselist=False,
        back_populates="acme_challenge_polls",
    )
    remote_ip_address = sa_orm_relationship(
        "RemoteIpAddress",
        primaryjoin="AcmeChallengePoll.remote_ip_address_id==RemoteIpAddress.id",
        uselist=False,
        back_populates="acme_challenge_polls",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def as_json(self):
        return {
            "id": self.id,
            "AcmeChallenge": self.acme_challenge.as_json,
            "timestamp_polled": self.timestamp_polled_isoformat,
            "remote_ip_address": {
                "id": self.remote_ip_address_id,
                "ip_address": self.remote_ip_address.remote_ip_address,
            },
        }


# ==============================================================================


class AcmeChallengeUnknownPoll(Base, _Mixin_Timestamps_Pretty):
    """
    log polls of non-existant ace challenges
    """

    __tablename__ = "acme_challenge_unknown_poll"

    id = sa.Column(sa.Integer, primary_key=True)
    domain = sa.Column(sa.Unicode(255), nullable=False)
    challenge = sa.Column(sa.Unicode(255), nullable=False)
    timestamp_polled = sa.Column(sa.DateTime, nullable=False)
    remote_ip_address_id = sa.Column(
        sa.Integer, sa.ForeignKey("remote_ip_address.id"), nullable=False
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    remote_ip_address = sa_orm_relationship(
        "RemoteIpAddress",
        primaryjoin="AcmeChallengeUnknownPoll.remote_ip_address_id==RemoteIpAddress.id",
        uselist=False,
        back_populates="acme_challenge_unknown_polls",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def as_json(self):
        return {
            "id": self.id,
            "domain": self.domain,
            "challenge": self.challenge,
            "timestamp_polled": self.timestamp_polled_isoformat,
            "remote_ip_address": {
                "id": self.remote_ip_address_id,
                "ip_address": self.remote_ip_address.remote_ip_address,
            },
        }


# ==============================================================================


class AcmeDnsServer(Base, _Mixin_Timestamps_Pretty):

    __tablename__ = "acme_dns_server"
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    is_active = sa.Column(sa.Boolean, nullable=False, default=True)
    is_global_default = sa.Column(sa.Boolean, nullable=True, default=None)
    root_url = sa.Column(sa.Unicode(255), nullable=False)
    operations_event_id__created = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_dns_server_accounts = sa_orm_relationship(
        "AcmeDnsServerAccount",
        primaryjoin="AcmeDnsServer.id==AcmeDnsServerAccount.acme_dns_server_id",
        uselist=True,
        back_populates="acme_dns_server",
    )
    operations_event__created = sa_orm_relationship(
        "OperationsEvent",
        primaryjoin="AcmeDnsServer.operations_event_id__created==OperationsEvent.id",
        uselist=False,
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def as_json(self):
        return {
            "id": self.id,
            "root_url": self.root_url,
            "timestamp_created": self.timestamp_created_isoformat,
            "is_active": True if self.is_active else False,
            "is_global_default": True if self.is_global_default else False,
        }


# ==============================================================================


class AcmeDnsServerAccount(Base, _Mixin_Timestamps_Pretty):
    __table_args__ = (
        sa.UniqueConstraint(
            "acme_dns_server_id",
            "domain_id",
            "is_active",
            name="domain_active_account",
        ),
    )

    __tablename__ = "acme_dns_server_account"
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    acme_dns_server_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_dns_server.id"), nullable=False
    )
    domain_id = sa.Column(sa.Integer, sa.ForeignKey("domain.id"), nullable=False)
    is_active = sa.Column(
        sa.Boolean, nullable=True, default=True
    )  # allow NULL for constraint to work
    username = sa.Column(sa.Unicode(255), nullable=False)
    password = sa.Column(sa.Unicode(255), nullable=False)
    fulldomain = sa.Column(sa.Unicode(255), nullable=False)
    subdomain = sa.Column(sa.Unicode(255), nullable=False)
    allowfrom = sa.Column(sa.Unicode(255), nullable=True)
    operations_event_id__created = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_dns_server = sa_orm_relationship(
        "AcmeDnsServer",
        primaryjoin="AcmeDnsServerAccount.acme_dns_server_id==AcmeDnsServer.id",
        uselist=False,
        back_populates="acme_dns_server_accounts",
    )
    domain = sa_orm_relationship(
        "Domain",
        primaryjoin="AcmeDnsServerAccount.domain_id==Domain.id",
        uselist=False,
        back_populates="acme_dns_server_accounts",
    )
    operations_event__created = sa_orm_relationship(
        "OperationsEvent",
        primaryjoin="AcmeDnsServerAccount.operations_event_id__created==OperationsEvent.id",
        uselist=False,
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def password_sample(self):
        return "%s...%s" % (self.password[:5], self.password[-5:])

    @property
    def as_json(self):
        return {
            "AcmeDnsServer": self.acme_dns_server.as_json,
            "Domain": self.domain.as_json,
            "id": self.id,
            "timestamp_created": self.timestamp_created_isoformat,
            "username": self.username,
            "password": self.password,
            "fulldomain": self.fulldomain,
            "subdomain": self.subdomain,
            "allowfrom": json.loads(self.allowfrom),
        }

    @property
    def pyacmedns_dict(self):
        """
        :returns: a dict of items required for a pyacmedns client
        """
        return {
            "username": self.username,
            "password": self.password,
            "fulldomain": self.fulldomain,
            "subdomain": self.subdomain,
            "allowfrom": json.loads(self.allowfrom) if self.allowfrom else [],
        }


# ==============================================================================


class AcmeEventLog(Base, _Mixin_Timestamps_Pretty):
    """
    log acme requests
    """

    __tablename__ = "acme_event_log"
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_event = sa.Column(sa.DateTime, nullable=False)
    acme_event_id = sa.Column(sa.Integer, nullable=False)  # AcmeEvent
    acme_account_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_account.id", use_alter=True), nullable=True
    )
    acme_authorization_id = sa.Column(
        sa.Integer,
        sa.ForeignKey("acme_authorization.id", use_alter=True),
        nullable=True,
    )
    acme_challenge_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_challenge.id", use_alter=True), nullable=True
    )
    acme_order_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_order.id", use_alter=True), nullable=True
    )
    certificate_request_id = sa.Column(
        sa.Integer,
        sa.ForeignKey("certificate_request.id", use_alter=True),
        nullable=True,
    )
    certificate_signed_id = sa.Column(
        sa.Integer,
        sa.ForeignKey("certificate_signed.id", use_alter=True),
        nullable=True,
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

    @property
    def as_json(self):
        return {
            "id": self.id,
            "timestamp_event": self.timestamp_event_isoformat,
            "acme_event": self.acme_event,
            "acme_account_id": self.acme_account_id,
            "acme_authorization_id": self.acme_authorization_id,
            "acme_challenge_id": self.acme_challenge_id,
            "acme_order_id": self.acme_order_id,
            "certificate_request_id": self.certificate_request_id,
            "certificate_signed_id": self.certificate_signed_id,
        }


# ==============================================================================


class AcmeOrder(Base, _Mixin_Timestamps_Pretty):
    """
    ACME Order Object [https://tools.ietf.org/html/rfc8555#section-7.1.3]

    An ACME Order is essentially a Certificate Request

    It contains the following objects:
        Identifiers (Domains)
        Authorizations (Authorization Objects)
        Certificate (Signed Certificate)

    `private_key_id`:
        Can not be null. If a deferred PrivateKey key is requested (e.g. auto-generated),
        then it should be set to `0`, to note the corresponding placeholder PrivateKey

    `AcmeOrder.is_processing` - a boolean triplet with the following meaning:
        True :  The AcmeOrder has been generated. It is `Active` and processing.
                All Authorizations/Challenges are blocking for Domains on this order.

        None :  The AcmeOrder has completed, it may be successful or a failure.
                Any Authorizations/Challenges on this order's domains are OFF.

        False : The AcmeOrder has been cancelled by the user.
                Any Authorizations/Challenges on this order's domains are OFF.

    - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    https://tools.ietf.org/html/rfc8555#section-7.4

        identifiers (required, array of object):  An array of identifier
        objects that the client wishes to submit an order for.

            type (required, string):  The type of identifier.

            value (required, string):  The identifier itself.

            notBefore (optional, string):  The requested value of the notBefore
                field in the certificate, in the date format defined in [RFC3339].

            notAfter (optional, string):  The requested value of the notAfter
                field in the certificate, in the date format defined in [RFC3339].

        Example - Request

            POST /acme/new-order HTTP/1.1
            Host: example.com
            Content-Type: application/jose+json

            {
              "protected": base64url({
                "alg": "ES256",
                "kid": "https://example.com/acme/acct/evOfKhNU60wg",
                "nonce": "5XJ1L3lEkMG7tR6pA00clA",
                "url": "https://example.com/acme/new-order"
              }),
              "payload": base64url({
                "identifiers": [
                  { "type": "dns", "value": "www.example.org" },
                  { "type": "dns", "value": "example.org" }
                ],
                "notBefore": "2016-01-01T00:04:00+04:00",
                "notAfter": "2016-01-08T00:04:00+04:00"
              }),
              "signature": "H6ZXtGjTZyUnPeKn...wEA4TklBdh3e454g"
            }

        Example - Response

            HTTP/1.1 201 Created
            Replay-Nonce: MYAuvOpaoIiywTezizk5vw
            Link: <https://example.com/acme/directory>;rel="index"
            Location: https://example.com/acme/order/TOlocE8rfgo

            {
             "status": "pending",
             "expires": "2016-01-05T14:09:07.99Z",

             "notBefore": "2016-01-01T00:00:00Z",
             "notAfter": "2016-01-08T00:00:00Z",

             "identifiers": [
               { "type": "dns", "value": "www.example.org" },
               { "type": "dns", "value": "example.org" }
             ],

             "authorizations": [
               "https://example.com/acme/authz/PAniVnsZcis",
               "https://example.com/acme/authz/r4HqLzrSrpI"
             ],

             "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
            }

    """

    __tablename__ = "acme_order"

    id = sa.Column(sa.Integer, primary_key=True)
    is_processing = sa.Column(
        sa.Boolean, nullable=True, default=True
    )  # see notes above
    is_auto_renew = sa.Column(sa.Boolean, nullable=True, default=True)
    is_renewed = sa.Column(sa.Boolean, nullable=True, default=None)
    is_save_alternate_chains = sa.Column(sa.Boolean, nullable=False, default=True)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    acme_order_type_id = sa.Column(
        sa.Integer, nullable=False
    )  # see: `.utils.AcmeOrderType`
    acme_status_order_id = sa.Column(
        sa.Integer, nullable=True, default=True
    )  # see: `.utils.Acme_Status_Order`
    acme_order_processing_strategy_id = sa.Column(
        sa.Integer, nullable=False
    )  # see: `utils.AcmeOrder_ProcessingStrategy`
    acme_order_processing_status_id = sa.Column(
        sa.Integer, nullable=False
    )  # see: `utils.AcmeOrder_ProcessingStatus`
    order_url = sa.Column(sa.Unicode(255), nullable=True, unique=True)
    finalize_url = sa.Column(sa.Unicode(255), nullable=True)
    certificate_url = sa.Column(sa.Unicode(255), nullable=True)
    timestamp_expires = sa.Column(sa.DateTime, nullable=True)
    timestamp_updated = sa.Column(sa.DateTime, nullable=True)
    private_key_cycle_id__renewal = sa.Column(
        sa.Integer, nullable=False
    )  # see .utils.PrivateKeyCycle; if the order is renewed, what is the default cycle strategy?
    private_key_strategy_id__requested = sa.Column(
        sa.Integer, nullable=False
    )  # see .utils.PrivateKeyStrategy; how are we specifying the private key? NOW or deferred?
    private_key_strategy_id__final = sa.Column(
        sa.Integer, nullable=True
    )  # see .utils.PrivateKeyStrategy; how did we end up choosing a private key?
    acme_event_log_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_event_log.id"), nullable=False
    )  # When was this created?  AcmeEvent['v2|newOrder']

    timestamp_finalized = sa.Column(sa.DateTime, nullable=True)
    acme_account_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_account.id"), nullable=False
    )
    certificate_request_id = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_request.id"), nullable=True
    )
    certificate_signed_id = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_signed.id"), nullable=True
    )
    private_key_id__requested = sa.Column(
        sa.Integer, sa.ForeignKey("private_key.id"), nullable=False
    )
    private_key_id = sa.Column(
        sa.Integer, sa.ForeignKey("private_key.id"), nullable=False
    )
    unique_fqdn_set_id = sa.Column(
        sa.Integer, sa.ForeignKey("unique_fqdn_set.id"), nullable=False
    )
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    acme_order_id__retry_of = sa.Column(
        sa.Integer,
        sa.ForeignKey("acme_order.id"),
        nullable=True,
    )
    acme_order_id__renewal_of = sa.Column(
        sa.Integer,
        sa.ForeignKey("acme_order.id"),
        nullable=True,
    )
    certificate_signed_id__renewal_of = sa.Column(
        sa.Integer,
        sa.ForeignKey("certificate_signed.id", use_alter=True),
        nullable=True,
    )
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_account = sa_orm_relationship(
        "AcmeAccount",
        primaryjoin="AcmeOrder.acme_account_id==AcmeAccount.id",
        uselist=False,
        back_populates="acme_orders",
    )
    acme_order_submissions = sa_orm_relationship(
        "AcmeOrderSubmission",
        primaryjoin="AcmeOrder.id==AcmeOrderSubmission.acme_order_id",
        uselist=True,
        back_populates="acme_order",
    )
    acme_order_2_acme_challenge_type_specifics = sa_orm_relationship(
        "AcmeOrder2AcmeChallengeTypeSpecific",
        primaryjoin="AcmeOrder.id==AcmeOrder2AcmeChallengeTypeSpecific.acme_order_id",
        uselist=True,
        back_populates="acme_order",
    )
    certificate_request = sa_orm_relationship(
        "CertificateRequest",
        primaryjoin="AcmeOrder.certificate_request_id==CertificateRequest.id",
        uselist=False,
        back_populates="acme_orders",
    )
    certificate_signed = sa_orm_relationship(
        "CertificateSigned",
        primaryjoin="AcmeOrder.certificate_signed_id==CertificateSigned.id",
        uselist=False,
        back_populates="acme_order",
    )
    certificate_signed__renewal_of = sa_orm_relationship(
        "CertificateSigned",
        primaryjoin="AcmeOrder.certificate_signed_id__renewal_of==CertificateSigned.id",
        back_populates="acme_order__renewals",
        uselist=False,
    )
    operations_object_events = sa_orm_relationship(
        "OperationsObjectEvent",
        primaryjoin="AcmeOrder.id==OperationsObjectEvent.acme_order_id",
        back_populates="acme_order",
    )
    private_key__requested = sa_orm_relationship(
        "PrivateKey",
        primaryjoin="AcmeOrder.private_key_id__requested==PrivateKey.id",
        uselist=False,
    )
    private_key = sa_orm_relationship(
        "PrivateKey",
        primaryjoin="AcmeOrder.private_key_id==PrivateKey.id",
        back_populates="acme_orders",
        uselist=False,
    )
    queue_certificate__generator = sa.orm.relationship(
        "QueueCertificate",
        primaryjoin="AcmeOrder.id==QueueCertificate.acme_order_id__generated",
        back_populates="acme_order__generated",
        uselist=False,
    )
    to_acme_authorizations = sa_orm_relationship(
        "AcmeOrder2AcmeAuthorization",
        primaryjoin="AcmeOrder.id==AcmeOrder2AcmeAuthorization.acme_order_id",
        uselist=True,
        back_populates="acme_order",
    )
    unique_fqdn_set = sa_orm_relationship(
        "UniqueFQDNSet",
        primaryjoin="AcmeOrder.unique_fqdn_set_id==UniqueFQDNSet.id",
        uselist=False,
        back_populates="acme_orders",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def acme_status_order(self):
        return model_utils.Acme_Status_Order.as_string(self.acme_status_order_id)

    @reify
    def acme_order_type(self):
        return model_utils.AcmeOrderType.as_string(self.acme_order_type_id)

    @property
    def acme_order_processing_strategy(self):
        return model_utils.AcmeOrder_ProcessingStrategy.as_string(
            self.acme_order_processing_strategy_id
        )

    @reify
    def acme_order_processing_status(self):
        return model_utils.AcmeOrder_ProcessingStatus.as_string(
            self.acme_order_processing_status_id
        )

    @reify
    def private_key_cycle__renewal(self):
        return model_utils.PrivateKeyCycle.as_string(self.private_key_cycle_id__renewal)

    @reify
    def private_key_strategy__requested(self):
        return (
            model_utils.PrivateKeyStrategy.as_string(
                self.private_key_strategy_id__requested
            )
            if self.private_key_strategy_id__requested
            else ""
        )

    @reify
    def private_key_strategy__final(self):
        return (
            model_utils.PrivateKeyStrategy.as_string(
                self.private_key_strategy_id__final
            )
            if self.private_key_strategy_id__final
            else ""
        )

    @property
    def acme_authorization_ids(self):
        return [i.acme_authorization_id for i in self.to_acme_authorizations]

    @property
    def acme_authorizations(self):
        authorizations = []
        for _to_auth in self.to_acme_authorizations:
            authorizations.append(_to_auth.acme_authorization)
        return authorizations

    @property
    def acme_authorizations_pending(self):
        authorizations = []
        for _to_auth in self.to_acme_authorizations:
            if (
                _to_auth.acme_authorization.acme_status_authorization
                in model_utils.Acme_Status_Authorization.OPTIONS_POSSIBLY_PENDING
            ):
                authorizations.append(_to_auth.acme_authorization)
        return authorizations

    @property
    def authorizations_can_deactivate(self):
        authorizations = []
        for _to_auth in self.to_acme_authorizations:
            if (
                _to_auth.acme_authorization.acme_status_authorization
                in model_utils.Acme_Status_Authorization.OPTIONS_DEACTIVATE
            ):
                authorizations.append(_to_auth.acme_authorization)
        return authorizations

    @property
    def domains_as_list(self):
        domain_names = [
            to_d.domain.domain_name.lower() for to_d in self.unique_fqdn_set.to_domains
        ]
        domain_names = list(set(domain_names))
        domain_names = sorted(domain_names)
        return domain_names

    @property
    def domains_challenged(self):
        domain_names = self.domains_as_list
        domains_challenged = model_utils.DomainsChallenged()
        for _specified in self.acme_order_2_acme_challenge_type_specifics:
            _domain_name = _specified.domain.domain_name
            _acme_challenge_type = _specified.acme_challenge_type
            if domains_challenged[_acme_challenge_type] is None:
                domains_challenged[_acme_challenge_type] = []
            domains_challenged[_acme_challenge_type].append(_domain_name)
            if _domain_name in domain_names:
                domain_names.remove(_domain_name)
        if domain_names:
            # default challenge type is http-01
            domains_challenged.ENSURE_DEFAULT_HTTP01()
            if domains_challenged["http-01"] is None:
                domains_challenged["http-01"] = domain_names
            else:
                domains_challenged["http-01"].extend(domain_names)
        return domains_challenged

    @property
    def is_can_acme_server_sync(self):
        # note: is there a better test?
        if not self.order_url:
            return False
        if self.acme_status_order in model_utils.Acme_Status_Order.OPTIONS_X_ACME_SYNC:
            return False
        return True

    @property
    def is_can_acme_server_deactivate_authorizations(self):
        # note: is there a better test?
        if not self.order_url:
            return False
        if (
            self.acme_status_order
            in model_utils.Acme_Status_Order.OPTIONS_X_DEACTIVATE_AUTHORIZATIONS
        ):
            return False

        # now loop the authorizations...
        auths_deactivate = self.authorizations_can_deactivate
        if not auths_deactivate:
            return False

        return True

    @property
    def is_can_acme_server_download_certificate(self):
        """
        can we download a CertificateSigned from the AcmeServer?
        only works for VALID AcmeOrder if we do not have a CertificateSigned
        """
        if self.acme_status_order == "valid":
            if self.certificate_url:
                if not self.certificate_signed_id:
                    return True
        return False

    @reify
    def acme_process_steps(self):
        """
        this is a JSON payload which can be shown to an API client or used to
        render more informative instructions on the AcmeOrder process page.
        """
        rval = {
            "authorizations": [],
            "authorizations_remaining": 0,
            "finalize": None,
            "download": None,
            "next_step": None,
        }
        if self.acme_status_order in model_utils.Acme_Status_Order.OPTIONS_inactive:
            return rval

        if self.acme_status_order == "pending":
            rval["finalize"] = True
            for _to_auth in self.to_acme_authorizations:
                _pending = (
                    True
                    if (
                        _to_auth.acme_authorization.acme_status_authorization
                        in model_utils.Acme_Status_Authorization.OPTIONS_POSSIBLY_PENDING
                    )
                    else None
                )
                _auth_tuple = (_pending, _to_auth.acme_authorization.as_json)
                rval["authorizations"].append(_auth_tuple)
                if _pending:
                    rval["authorizations_remaining"] += 1
            if rval["authorizations_remaining"]:
                rval["next_step"] = "challenge"
        elif self.acme_status_order == "ready":
            rval["finalize"] = True
            rval["download"] = True
            rval["next_step"] = "finalize"
        elif self.acme_status_order == "processing":
            rval["finalize"] = False
            rval["download"] = True
            rval["next_step"] = "download"

        return rval

    @property
    def is_can_acme_process(self):
        # `process` will iterate authorizations and finalize
        if self.acme_status_order in model_utils.Acme_Status_Order.OPTIONS_PROCESS:
            return True
        return False

    @property
    def is_can_acme_finalize(self):
        if self.acme_status_order in model_utils.Acme_Status_Order.OPTIONS_FINALIZE:
            return True
        return False

    @property
    def is_can_mark_invalid(self):
        if (
            self.acme_status_order
            not in model_utils.Acme_Status_Order.OPTIONS_X_MARK_INVALID
        ):
            return True
        return False

    @property
    def is_can_retry(self):
        if self.acme_status_order not in model_utils.Acme_Status_Order.OPTIONS_RETRY:
            return False
        return True

    @property
    def is_renewable_quick(self):
        if self.acme_status_order in model_utils.Acme_Status_Order.OPTIONS_RENEW:
            if self.acme_account.is_active:
                if self.private_key.is_active:
                    return True
        return False

    @property
    def is_renewable_queue(self):
        if self.acme_account.is_active:
            return True
        return False

    @property
    def is_renewable_custom(self):
        if self.acme_status_order in model_utils.Acme_Status_Order.OPTIONS_RENEW:
            if self.acme_account.is_active:
                return True
        return False

    @property
    def as_json(self):
        dbSession = sa_Session.object_session(self)
        request = dbSession.info["request"]
        admin_url = request.admin_url if request else ""

        return {
            "id": self.id,
            "AcmeAccount": {
                "id": self.acme_account_id,
                "key_pem_md5": self.acme_account.acme_account_key.key_pem_md5,
            },
            "acme_status_order": self.acme_status_order,
            "acme_order_type": self.acme_order_type,
            "acme_order_processing_status": self.acme_order_processing_status,
            "acme_order_processing_strategy": self.acme_order_processing_strategy,
            "acme_process_steps": self.acme_process_steps,
            "certificate_request_id": self.certificate_request_id,
            "domains_as_list": self.domains_as_list,
            "domains_challenged": self.domains_challenged,
            "finalize_url": self.finalize_url,
            "certificate_url": self.certificate_url,
            "is_processing": True if self.is_processing else False,
            "is_auto_renew": True if self.is_auto_renew else False,
            "is_can_acme_process": self.is_can_acme_process,
            "is_can_mark_invalid": self.is_can_mark_invalid,
            "is_can_retry": self.is_can_retry,
            "is_renewable_custom": True if self.is_renewable_custom else False,
            "is_renewable_queue": True if self.is_renewable_queue else False,
            "is_renewable_quick": True if self.is_renewable_quick else False,
            "is_can_acme_server_deactivate_authorizations": True
            if self.is_can_acme_server_deactivate_authorizations
            else False,
            "is_renewed": True if self.is_renewed else False,
            "order_url": self.order_url,
            "PrivateKey": {
                "id": self.private_key_id,
                "key_pem_md5": self.private_key.key_pem_md5
                if self.private_key_id
                else None,
            },
            "certificate_signed_id": self.certificate_signed_id,
            "certificate_signed_id__renewal_of": self.certificate_signed_id__renewal_of,
            "timestamp_created": self.timestamp_created_isoformat,
            "timestamp_expires": self.timestamp_expires_isoformat,
            "timestamp_finalized": self.timestamp_finalized_isoformat,
            "timestamp_updated": self.timestamp_updated_isoformat,
            "unique_fqdn_set_id": self.unique_fqdn_set_id,
            "url_acme_server_sync": "%s/acme-order/%s/acme-server/sync.json"
            % (admin_url, self.id)
            if self.is_can_acme_server_sync
            else None,
            "url_acme_certificate_signed_download": "%s/acme-order/%s/acme-server/download-certificate.json"
            % (admin_url, self.id)
            if self.is_can_acme_server_download_certificate
            else None,
            "url_acme_process": "%s/acme-order/%s/acme-process.json"
            % (admin_url, self.id)
            if self.is_can_acme_process
            else None,
            "private_key_cycle__renewal": self.private_key_cycle__renewal,
            "private_key_strategy__requested": self.private_key_strategy__requested,
            "private_key_strategy__final": self.private_key_strategy__final,
            "acme_authorization_ids": self.acme_authorization_ids,
        }


class AcmeOrderSubmission(Base):
    """
    Boulder (LetsEncrypt) may re-use the same AcmeOrder in certain situations.
    Usually this is to:
        * defend against buggy clients who submit multiple consecutive PENDING orders
        * turn an INVALID order for a given Account + Unique Set of Domains into "PENDING"
    """

    __tablename__ = "acme_order_submission"

    id = sa.Column(sa.Integer, primary_key=True)
    acme_order_id = sa.Column(sa.Integer, sa.ForeignKey("acme_order.id"), nullable=True)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)

    acme_order = sa_orm_relationship(
        "AcmeOrder",
        primaryjoin="AcmeOrderSubmission.acme_order_id==AcmeOrder.id",
        uselist=False,
        back_populates="acme_order_submissions",
    )


# ==============================================================================


class AcmeOrder2AcmeAuthorization(Base):
    """
    On first glance, it may seem like there is a duplication and potential for
    consolidation between these two tables:
        ``AcmeOrder2AcmeAuthorization``
            acme_order_id
            acme_authorization_id
        ``AcmeOrder2AcmeChallengeTypeSpecific``
            acme_order_id
            domain_id
            acme_challenge_type_id

    If only!!

    When an ``AcmeOrder`` is created, only the ``AcmeAuthorization``'s URL is
    known to the Client. The Client does not know which ``Domain`` corresponds
    to which ``AcmeAuthorization``. This correlation is only surfaced when the
    ``AcmeAuthorization`` is "synced" to the ACME Server.

    Similarly, users of The Client specify their preferred challenges in
    regards to each ``Domain`` when an ``AcmeOrder`` is created.

    Also!!

    We track `is_present_on_new_order` now.
    """

    __tablename__ = "acme_order_2_acme_authorization"

    acme_order_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_order.id"), primary_key=True
    )
    acme_authorization_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_authorization.id"), primary_key=True
    )
    is_present_on_new_order = sa.Column(sa.Boolean, default=None)

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


# ==============================================================================


class AcmeOrder2AcmeChallengeTypeSpecific(Base):
    """
    See docstring for ``AcmeOrder2AcmeAuthorization```
    """

    __tablename__ = "acme_order_2_acme_challenge_type_specific"
    acme_order_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_order.id"), nullable=False, primary_key=True
    )
    domain_id = sa.Column(
        sa.Integer, sa.ForeignKey("domain.id"), nullable=False, primary_key=True
    )
    acme_challenge_type_id = sa.Column(
        sa.Integer, nullable=False
    )  # `model_utils.AcmeChallengeType`
    # this is just for logging and reconciliation
    acme_challenge_id__triggered = sa.Column(
        sa.Integer,
        sa.ForeignKey("acme_challenge.id"),
        nullable=True,
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_order = sa_orm_relationship(
        "AcmeOrder",
        primaryjoin="AcmeOrder2AcmeChallengeTypeSpecific.acme_order_id==AcmeOrder.id",
        uselist=False,
        back_populates="acme_order_2_acme_challenge_type_specifics",
    )

    domain = sa_orm_relationship(
        "Domain",
        primaryjoin="AcmeOrder2AcmeChallengeTypeSpecific.domain_id==Domain.id",
        uselist=False,
        back_populates="acme_order_2_acme_challenge_type_specifics",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def acme_challenge_type(self):
        if self.acme_challenge_type_id:
            return model_utils.AcmeChallengeType.as_string(self.acme_challenge_type_id)
        return None

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def as_json(self):
        return {
            "acme_order_id": self.acme_order_id,
            "domain_id": self.domain_id,
            "acme_challenge_type": self.acme_challenge_type,
            "acme_challenge_id__triggered": self.acme_challenge_id__triggered,
        }


# ==============================================================================


class AcmeOrderless(Base, _Mixin_Timestamps_Pretty):
    """
    AcmeOrderless allows us to support the "AcmeFlow"
    """

    __tablename__ = "acme_orderless"

    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    timestamp_finalized = sa.Column(sa.DateTime, nullable=True)
    timestamp_updated = sa.Column(sa.DateTime, nullable=True)
    is_processing = sa.Column(sa.Boolean, nullable=False)

    acme_account_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_account.id"), nullable=True
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_account = sa_orm_relationship(
        "AcmeAccount",
        primaryjoin="AcmeOrderless.acme_account_id==AcmeAccount.id",
        uselist=False,
        back_populates="acme_orderlesss",
    )
    acme_challenges = sa_orm_relationship(
        "AcmeChallenge",
        primaryjoin="AcmeOrderless.id==AcmeChallenge.acme_orderless_id",
        uselist=True,
        back_populates="acme_orderless",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def domains_status(self):
        _status = {}
        for challenge in self.acme_challenges:
            _status[challenge.domain_name] = {
                "acme_challenge_id": challenge.id,
                "acme_challenge_type": challenge.acme_challenge_type,
                "acme_status_challenge": challenge.acme_status_challenge,
            }
        return _status

    @property
    def as_json(self):
        return {
            "id": self.id,
            "timestamp_created": self.timestamp_created_isoformat,
            "timestamp_finalized": self.timestamp_finalized_isoformat,
            "timestamp_updated": self.timestamp_updated_isoformat,
            "domains_status": self.domains_status,
            "acme_account_id": self.acme_account_id,
            "is_processing": self.is_processing,
        }


# ==============================================================================


class CertificateCA(Base, _Mixin_Timestamps_Pretty, _Mixin_Hex_Pretty):
    """
    These are trusted "Certificate Authority" Certificates from LetsEncrypt that
    are used to sign server certificates.

    These are directly tied to a CertificateSigned and are needed to create a
    "fullchain" certificate for most deployments.
    """

    __tablename__ = "certificate_ca"
    id = sa.Column(sa.Integer, primary_key=True)
    display_name = sa.Column(sa.Unicode(255), nullable=False)

    # TODO: migrate this to an association table that tracks different trusted root stores
    is_trusted_root = sa.Column(
        sa.Boolean, nullable=True, default=None
    )  # this is just used to track if we know this cert is in trusted root stores.
    key_technology_id = sa.Column(
        sa.Integer, nullable=False
    )  # see .utils.KeyTechnology

    cert_pem = sa.Column(sa.Text, nullable=False, unique=True)
    cert_pem_md5 = sa.Column(sa.Unicode(32), nullable=True, unique=True)
    spki_sha256 = sa.Column(sa.Unicode(64), nullable=False)
    fingerprint_sha1 = sa.Column(sa.Unicode(255), nullable=False)

    timestamp_not_before = sa.Column(sa.DateTime, nullable=False)
    timestamp_not_after = sa.Column(sa.DateTime, nullable=False)
    cert_subject = sa.Column(sa.Text, nullable=False)
    cert_issuer = sa.Column(sa.Text, nullable=False)

    # these are not guaranteed
    cert_issuer_uri = sa.Column(sa.Text, nullable=True)
    cert_authority_key_identifier = sa.Column(sa.Text, nullable=True)
    cert_issuer__reconciled = sa.Column(
        sa.Boolean, nullable=True, default=None
    )  # status, True or False
    cert_issuer__certificate_ca_id = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_ca.id"), nullable=True
    )  # who did we reconcile this to/
    reconciled_uris = sa.Column(sa.Text, nullable=True)

    count_active_certificates = sa.Column(
        sa.Integer, nullable=True
    )  # internal tracking
    operations_event_id__created = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )  # internal tracking
    signed_by__certificate_ca_id = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_ca.id"), nullable=True
    )  # internal tracking
    cross_signed_by__certificate_ca_id = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_ca.id"), nullable=True
    )  # internal tracking

    timestamp_created = sa.Column(sa.DateTime, nullable=False)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    certificate_ca_chains_0 = sa_orm_relationship(
        "CertificateCAChain",
        primaryjoin="CertificateCA.id==CertificateCAChain.certificate_ca_0_id",
        back_populates="certificate_ca_0",
    )
    certificate_ca_chains_n = sa_orm_relationship(
        "CertificateCAChain",
        primaryjoin="CertificateCA.id==CertificateCAChain.certificate_ca_n_id",
        back_populates="certificate_ca_n",
    )
    cert_issuer__certificate_ca = sa_orm_relationship(
        "CertificateCA",
        primaryjoin="CertificateCA.cert_issuer__certificate_ca_id==remote(CertificateCA.id)",
        uselist=False,
    )
    operations_event__created = sa_orm_relationship(
        "OperationsEvent",
        primaryjoin="CertificateCA.operations_event_id__created==OperationsEvent.id",
        uselist=False,
    )
    operations_object_events = sa_orm_relationship(
        "OperationsObjectEvent",
        primaryjoin="CertificateCA.id==OperationsObjectEvent.certificate_ca_id",
        back_populates="certificate_ca",
    )

    to_root_store_versions = sa_orm_relationship(
        "RootStoreVersion_2_CertificateCA",
        primaryjoin="CertificateCA.id==RootStoreVersion_2_CertificateCA.certificate_ca_id",
        back_populates="certificate_ca",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @reify
    def cert_spki_search(self):
        return "type=spki&spki=%s&source=certificate_ca&certificate_ca.id=%s" % (
            self.spki_sha256,
            self.id,
        )

    @reify
    def cert_subject_search(self):
        return (
            "type=cert_subject&cert_subject=%s&source=certificate_ca&certificate_ca.id=%s"
            % (self.cert_subject, self.id)
        )

    @reify
    def cert_issuer_search(self):
        return (
            "type=cert_issuer&cert_issuer=%s&source=certificate_ca&certificate_ca.id=%s"
            % (self.cert_issuer, self.id)
        )

    @reify
    def fingerprint_sha1_preview(self):
        return "%s&hellip;" % (self.fingerprint_sha1__colon or "")[:8]

    @property
    def key_technology(self):
        if self.key_technology_id:
            return model_utils.KeyTechnology.as_string(self.key_technology_id)
        return None

    @property
    def button_view(self):
        dbSession = sa_Session.object_session(self)
        request = dbSession.info["request"]

        if not request:
            return "<!-- ERROR. could not derive the `request` -->"

        button = (
            """<a class="label label-info" href="%(admin_prefix)s/certificate-ca/%(id)s" """
            """data-sha1-preview="%(sha1_preview)s">"""
            """<span class="glyphicon glyphicon-file" aria-hidden="true"></span>"""
            """CertificateCA-%(id)s</a>"""
            """<code>%(sha1_preview)s</code>"""
            """|"""
            """<code>%(cert_subject)s</code>"""
            """|"""
            """<code>%(cert_issuer)s</code>"""
            % {
                "admin_prefix": request.registry.settings["app_settings"][
                    "admin_prefix"
                ],
                "id": self.id,
                "sha1_preview": self.fingerprint_sha1_preview,
                "cert_issuer": self.cert_issuer,
                "cert_subject": self.cert_subject,
            }
        )
        return button

    @property
    def button_search_spki(self):
        dbSession = sa_Session.object_session(self)
        request = dbSession.info["request"]

        if not request:
            return "<!-- ERROR. could not derive the `request` -->"

        button = (
            """<a class="btn btn-xs btn-info" href="%(admin_prefix)s/search?%(cert_spki_search)s">"""
            """<span class="glyphicon glyphicon-search" aria-hidden="true"></span>"""
            """</a>"""
            % {
                "admin_prefix": request.registry.settings["app_settings"][
                    "admin_prefix"
                ],
                "cert_spki_search": self.cert_spki_search,
            }
        )
        return button

    @property
    def as_json(self):
        return {
            "id": self.id,
            "display_name": self.display_name,
            "cert_pem_md5": self.cert_pem_md5,
            "cert_pem": self.cert_pem,
            "cert_subject": self.cert_subject,
            "cert_issuer": self.cert_issuer,
            "fingerprint_sha1": self.fingerprint_sha1,
            "spki_sha256": self.spki_sha256,
            "key_technology": self.key_technology,
            "timestamp_created": self.timestamp_created_isoformat,
            "timestamp_not_after": self.timestamp_not_after_isoformat,
            "timestamp_not_before": self.timestamp_not_before_isoformat,
        }


class CertificateCAChain(Base, _Mixin_Timestamps_Pretty):
    """
    These are pre-assembled chains of CertificateCA objects.
    """

    __tablename__ = "certificate_ca_chain"
    id = sa.Column(sa.Integer, primary_key=True)
    display_name = sa.Column(sa.Unicode(255), nullable=False)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)

    # this is the PEM encoding of the ENTIRE chain, not just element 0
    # while this could be assembled, for now it is being cached here
    chain_pem = sa.Column(sa.Text, nullable=False, unique=True)
    chain_pem_md5 = sa.Column(sa.Unicode(32), nullable=False, unique=True)

    # how many items are in the chain?
    chain_length = sa.Column(sa.Integer, nullable=False)

    # this is the first item in the chain; what signs the CertificateSigned
    certificate_ca_0_id = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_ca.id"), nullable=False
    )
    # this is the last item in the chain; usually a leaf of a trusted root
    certificate_ca_n_id = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_ca.id"), nullable=False
    )
    # this is a comma(,) separated list of the involved CertificateCA ids
    # using a string here is not a normalized data storage, but is more useful and efficient
    certificate_ca_ids_string = sa.Column(sa.Unicode(255), nullable=False)

    operations_event_id__created = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    certificate_ca_0 = sa_orm_relationship(
        "CertificateCA",
        primaryjoin="CertificateCAChain.certificate_ca_0_id==CertificateCA.id",
        uselist=False,
        back_populates="certificate_ca_chains_0",
    )

    certificate_ca_n = sa_orm_relationship(
        "CertificateCA",
        primaryjoin="CertificateCAChain.certificate_ca_n_id==CertificateCA.id",
        uselist=False,
        back_populates="certificate_ca_chains_n",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def button_view(self):
        dbSession = sa_Session.object_session(self)
        request = dbSession.info["request"]

        if not request:
            return "<!-- ERROR. could not derive the `request` -->"

        button = (
            """<a class="label label-info" href="%(admin_prefix)s/certificate-ca-chain/%(id)s">"""
            """<span class="glyphicon glyphicon-file" aria-hidden="true"></span>"""
            """CertificateCAChain-%(id)s</a>"""
            % {
                "admin_prefix": request.registry.settings["app_settings"][
                    "admin_prefix"
                ],
                "id": self.id,
            }
        )
        return button

    @property
    def button_compatible_search_view(self):
        dbSession = sa_Session.object_session(self)
        request = dbSession.info["request"]

        if not request:
            return "<!-- ERROR. could not derive the `request` -->"

        button = (
            """<a class="label label-info" href="%(admin_prefix)s/certificate-ca-chain/%(id)s">"""
            """<span class="glyphicon glyphicon-file" aria-hidden="true"></span>"""
            """CertificateCAChain-%(id)s</a>"""
            % {
                "admin_prefix": request.registry.settings["app_settings"][
                    "admin_prefix"
                ],
                "id": self.id,
            }
        )
        return button

    @reify
    def certificate_ca_ids(self):
        _certificate_ca_ids = self.certificate_ca_ids_string.split(",")
        return _certificate_ca_ids

    @reify
    def certificate_cas_all(self):
        # reify vs property, because this queries the database
        certificate_ca_ids = self.certificate_ca_ids
        dbSession = sa_Session.object_session(self)
        dbCertificateCAs = (
            dbSession.query(CertificateCA)
            .filter(CertificateCA.id.in_(certificate_ca_ids))
            .all()
        )
        return dbCertificateCAs

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def as_json(self):
        return {
            "id": self.id,
            "display_name": self.display_name,
            "chain_pem_md5": self.chain_pem_md5,
            "chain_pem": self.chain_pem,
            "timestamp_created": self.timestamp_created_isoformat,
            "certificate_ca_ids": self.certificate_ca_ids,
            "certificate_cas": [i.as_json for i in self.certificate_cas_all],
        }


# ==============================================================================


class CertificateCAPreference(Base, _Mixin_Timestamps_Pretty):
    """
    These are trusted "Certificate Authority" Certificates from LetsEncrypt that
    are used to sign server certificates.

    These are directly tied to a CertificateSigned and are needed to create a
    "fullchain" certificate for most deployments.
    """

    __tablename__ = "certificate_ca_preference"
    id = sa.Column(sa.Integer, primary_key=True)
    certificate_ca_id = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_ca.id"), nullable=False, unique=True
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    certificate_ca = sa_orm_relationship(
        "CertificateCA",
        primaryjoin="CertificateCAPreference.certificate_ca_id==CertificateCA.id",
        uselist=False,
    )


# ==============================================================================


class CertificateCAReconciliation(Base):
    __tablename__ = "certificate_ca_reconciliation"
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_operation = sa.Column(sa.DateTime, nullable=False)
    certificate_ca_id = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_ca.id"), nullable=False
    )
    result = sa.Column(
        sa.Boolean, nullable=True, default=None
    )  # True - success; False - failure
    certificate_ca_id__issuer__reconciled = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_ca.id"), nullable=True
    )


# ==============================================================================


class CertificateRequest(Base, _Mixin_Timestamps_Pretty, _Mixin_Hex_Pretty):
    """
    A CertificateRequest is submitted to the LetsEncrypt signing authority.
    In goes your hope, out comes your dreams.

    The domains will be stored in the UniqueFQDNSet table
    * UniqueFQDNSet - the signing authority has a ratelimit on 'unique' sets of fully qualified domain names.
    """

    __tablename__ = "certificate_request"

    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    certificate_request_source_id = sa.Column(
        sa.Integer, nullable=False
    )  # see .utils.CertificateRequestSource
    csr_pem = sa.Column(sa.Text, nullable=False)
    csr_pem_md5 = sa.Column(sa.Unicode(32), nullable=False)
    spki_sha256 = sa.Column(sa.Unicode(64), nullable=False)

    key_technology_id = sa.Column(
        sa.Integer, nullable=False
    )  # see .utils.KeyTechnology
    operations_event_id__created = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )
    private_key_id = sa.Column(
        sa.Integer, sa.ForeignKey("private_key.id"), nullable=True
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
    certificate_signeds = sa_orm_relationship(
        "CertificateSigned",
        primaryjoin="CertificateRequest.id==CertificateSigned.certificate_request_id",
        back_populates="certificate_request",
        uselist=True,
    )
    operations_object_events = sa_orm_relationship(
        "OperationsObjectEvent",
        primaryjoin="CertificateRequest.id==OperationsObjectEvent.certificate_request_id",
        back_populates="certificate_request",
    )
    private_key = sa_orm_relationship(
        "PrivateKey",
        primaryjoin="CertificateRequest.private_key_id==PrivateKey.id",
        uselist=False,
        back_populates="certificate_requests",
    )
    unique_fqdn_set = sa_orm_relationship(
        "UniqueFQDNSet",
        primaryjoin="CertificateRequest.unique_fqdn_set_id==UniqueFQDNSet.id",
        uselist=False,
        back_populates="certificate_requests",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @reify
    def certificate_request_source(self):
        return model_utils.CertificateRequestSource.as_string(
            self.certificate_request_source_id
        )

    @property
    def certificate_signed_id__latest(self):
        if self.certificate_signed__latest:
            return self.certificate_signed__latest.id
        return None

    @reify
    def csr_spki_search(self):
        return (
            "type=spki&spki=%s&source=certificate_request&certificate_request.id=%s"
            % (self.spki_sha256, self.id)
        )

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
    def key_technology(self):
        if self.key_technology_id:
            return model_utils.KeyTechnology.as_string(self.key_technology_id)
        return None

    @property
    def as_json(self):
        return {
            "id": self.id,
            "certificate_request_source": self.certificate_request_source,
            "csr_pem_md5": self.csr_pem_md5,
            "private_key_id": self.private_key_id,
            "spki_sha256": self.spki_sha256,
            "timestamp_created": self.timestamp_created_isoformat,
            "unique_fqdn_set_id": self.unique_fqdn_set_id,
        }

    @property
    def as_json_extended(self):
        return {
            "id": self.id,
            "certificate_request_source": self.certificate_request_source,
            "certificate_signed_id__latest": self.certificate_signed_id__latest,
            "csr_pem": self.csr_pem,
            "csr_pem_md5": self.csr_pem_md5,
            "domains": self.domains_as_list,
            "key_technology": self.key_technology,
            "private_key_id": self.private_key_id,
            "spki_sha256": self.spki_sha256,
            "timestamp_created": self.timestamp_created_isoformat,
            "unique_fqdn_set_id": self.unique_fqdn_set_id,
        }


# ==============================================================================


class CertificateSigned(Base, _Mixin_Timestamps_Pretty, _Mixin_Hex_Pretty):
    """
    A signed Server Certificate.
    To install on a webserver, must be paired with the PrivateKey and Trusted CertificateCA.

    The domains will be stored in:
    * UniqueFQDNSet - the signing authority has a ratelimit on 'unique' sets of fully qualified domain names.
    """

    __tablename__ = "certificate_signed"
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    timestamp_not_before = sa.Column(sa.DateTime, nullable=False)
    timestamp_not_after = sa.Column(sa.DateTime, nullable=False)
    is_single_domain_cert = sa.Column(sa.Boolean, nullable=True, default=None)
    key_technology_id = sa.Column(
        sa.Integer, nullable=False
    )  # see .utils.KeyTechnology

    cert_pem = sa.Column(sa.Text, nullable=False, unique=True)
    cert_pem_md5 = sa.Column(sa.Unicode(32), nullable=False, unique=True)
    spki_sha256 = sa.Column(sa.Unicode(64), nullable=False)
    fingerprint_sha1 = sa.Column(sa.Unicode(255), nullable=False)
    cert_subject = sa.Column(sa.Text, nullable=False)
    cert_issuer = sa.Column(sa.Text, nullable=False)
    is_active = sa.Column(sa.Boolean, nullable=False, default=True)
    is_deactivated = sa.Column(
        sa.Boolean, nullable=True, default=None
    )  # used to determine `is_active` toggling; if "True" then `is_active` can-not be toggled.
    is_revoked = sa.Column(
        sa.Boolean, nullable=True, default=None
    )  # used to determine is_active toggling. this will set 'is_deactivated' to True
    is_compromised_private_key = sa.Column(
        sa.Boolean, nullable=True, default=None
    )  # used to determine is_active toggling. this will set 'is_deactivated' to True
    unique_fqdn_set_id = sa.Column(
        sa.Integer, sa.ForeignKey("unique_fqdn_set.id"), nullable=False
    )
    timestamp_revoked_upstream = sa.Column(
        sa.DateTime, nullable=True
    )  # if set, the cert was reported revoked upstream and this is FINAL

    # as of .40, CertificateSigneds do not auto-renew. Instead, AcmeOrders do.
    # is_auto_renew = sa.Column(sa.Boolean, nullable=True, default=None)

    # acme_order_id__generated_by = sa.Column(sa.Integer, sa.ForeignKey("acme_order.id"), nullable=True,)

    # this is the private key
    private_key_id = sa.Column(
        sa.Integer, sa.ForeignKey("private_key.id"), nullable=False
    )

    # tracking
    # `use_alter=True` is needed for setup/drop
    certificate_request_id = sa.Column(
        sa.Integer,
        sa.ForeignKey("certificate_request.id", use_alter=True),
        nullable=True,
    )
    operations_event_id__created = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_account = sa_orm_relationship(
        AcmeAccount,
        primaryjoin="CertificateSigned.id==AcmeOrder.certificate_signed_id",
        secondary=(
            "join("
            "AcmeOrder, "
            "AcmeAccount, "
            "AcmeOrder.acme_account_id==AcmeAccount.id"
            ")"
        ),
        uselist=False,
        viewonly=True,
    )
    acme_order = sa_orm_relationship(
        "AcmeOrder",
        primaryjoin="CertificateSigned.id==AcmeOrder.certificate_signed_id",
        uselist=False,
        back_populates="certificate_signed",
    )
    certificate_request = sa_orm_relationship(
        "CertificateRequest",
        primaryjoin="CertificateSigned.certificate_request_id==CertificateRequest.id",
        back_populates="certificate_signeds",
        uselist=False,
    )
    certificate_signed_chains = sa_orm_relationship(
        "CertificateSignedChain",
        primaryjoin="CertificateSigned.id==CertificateSignedChain.certificate_signed_id",
        uselist=True,
        back_populates="certificate_signed",
    )
    coverage_assurance_events = sa_orm_relationship(
        "CoverageAssuranceEvent",
        primaryjoin="CertificateSigned.id==CoverageAssuranceEvent.certificate_signed_id",
        back_populates="certificate_signed",
        uselist=True,
    )
    operations_event__created = sa_orm_relationship(
        "OperationsEvent",
        primaryjoin="CertificateSigned.operations_event_id__created==OperationsEvent.id",
        uselist=False,
    )
    operations_object_events = sa_orm_relationship(
        "OperationsObjectEvent",
        primaryjoin="CertificateSigned.id==OperationsObjectEvent.certificate_signed_id",
        back_populates="certificate_signed",
    )
    private_key = sa_orm_relationship(
        "PrivateKey",
        primaryjoin="CertificateSigned.private_key_id==PrivateKey.id",
        uselist=False,
        back_populates="certificate_signeds",
    )
    unique_fqdn_set = sa_orm_relationship(
        "UniqueFQDNSet",
        primaryjoin="CertificateSigned.unique_fqdn_set_id==UniqueFQDNSet.id",
        uselist=False,
        back_populates="certificate_signeds",
    )
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    acme_order__renewals = sa_orm_relationship(
        "AcmeOrder",
        primaryjoin="CertificateSigned.id==AcmeOrder.certificate_signed_id__renewal_of",
        back_populates="certificate_signed__renewal_of",
        uselist=True,
    )
    queue_certificate__parent = sa_orm_relationship(
        "QueueCertificate",
        primaryjoin="CertificateSigned.id==QueueCertificate.certificate_signed_id__generated",
        back_populates="certificate_signed__generated",
        uselist=True,
    )
    queue_certificate__renewal = sa_orm_relationship(
        "QueueCertificate",
        primaryjoin="CertificateSigned.id==QueueCertificate.certificate_signed_id__source",
        back_populates="certificate_signed__source",
        uselist=True,
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def cert_spki_search(self):
        return "type=spki&spki=%s&source=certificate&certificate.id=%s" % (
            self.spki_sha256,
            self.id,
        )

    @property
    def cert_subject_search(self):
        return (
            "type=cert_subject&cert_subject=%s&source=certificate&certificate.id=%s"
            % (self.cert_subject, self.id)
        )

    @property
    def cert_issuer_search(self):
        return (
            "type=cert_issuer&cert_issuer=%s&source=certificate&certificate.id=%s"
            % (self.cert_issuer, self.id)
        )

    @property
    def cert_chain_pem(self):
        if not self.certificate_ca_chain__preferred:
            return None
        return self.certificate_ca_chain__preferred.chain_pem

    @property
    def cert_fullchain_pem(self):
        if not self.certificate_ca_chain__preferred:
            return None
        # certs are standardized to have a newline
        return "\n".join((self.cert_pem.strip(), self.cert_chain_pem))

    @reify
    def certificate_ca_ids__upchain(self):
        # this loops `ORM:certificate_signed_chains`
        # this is NOT in order of preference
        _ids = set([])
        for _to_certificate_ca_chain in self.certificate_signed_chains:
            _chain = _to_certificate_ca_chain.certificate_ca_chain
            _ids.add(_chain.certificate_ca_0_id)
        _ids = list(_ids)
        return _ids

    @reify
    def certificate_cas__upchain(self):
        # this loops `ORM:certificate_signed_chains`
        # this is NOT in order of preference
        _cas = set([])
        for _to_certificate_ca_chain in self.certificate_signed_chains:
            _chain = _to_certificate_ca_chain.certificate_ca_chain
            _cas.add(_chain.certificate_ca_0)
        _cas = list(_cas)
        return _cas

    @reify
    def certificate_ca_chain_ids(self):
        # this loops `ORM:certificate_signed_chains`
        # this is NOT in order of preference
        _ids = [i.certificate_ca_chain_id for i in self.certificate_signed_chains]
        return _ids

    @reify
    def certificate_ca_chain_id__preferred(self):
        # this invokes `certificate_ca_chain__preferred`
        # which then loops `ORM:certificate_signed_chains`
        if self.certificate_ca_chain__preferred:
            return self.certificate_ca_chain__preferred.id
        return None

    @reify
    def certificate_ca_chain__preferred(self):
        # this loops `ORM:certificate_signed_chains`
        if not self.certificate_signed_chains:
            return None
        try:
            dbSession = sa_Session.object_session(self)
            request = dbSession.info["request"]

            # only search for a preference if they exist
            if request and request.dbCertificateCAPreferences:
                # TODO: first match or shortest match?
                # first match for now!
                # there are a lot of ways to compute this,
                # this is not efficient. this is just a quick pass
                preferred_ca_ids = [
                    i.certificate_ca_id for i in request.dbCertificateCAPreferences
                ]
                for _preferred_ca_id in preferred_ca_ids:
                    for _csc in self.certificate_signed_chains:
                        _ca_chain = _csc.certificate_ca_chain
                        # right now we don't care WHERE in the chain the
                        # certificate CA pref is, just that it is in the chain
                        if _preferred_ca_id in _ca_chain.certificate_ca_ids:
                            return _ca_chain

            # we have None! so just return the first one we have
            return self.certificate_signed_chains[0].certificate_ca_chain

        except Exception as exc:  # noqa: F841
            pass
        return None

    @reify
    def expiring_days(self):
        if self._expiring_days is None:
            self._expiring_days = (
                self.timestamp_not_after - datetime.datetime.utcnow()
            ).days
        return self._expiring_days

    _expiring_days = None

    @reify
    def expiring_days_label(self):
        if self.is_active:
            if self.expiring_days <= 0:
                return "danger"
            elif self.expiring_days <= 30:
                return "warning"
            elif self.expiring_days > 30:
                return "success"
        return "danger"

    def custom_config_payload(self, certificate_ca_chain_id=None, id_only=False):
        # if there is no `certificate_ca_chain_id` specified, use the default
        if not certificate_ca_chain_id:
            certificate_ca_chain_id = self.certificate_ca_chain_id__preferred

        # invoke this to trigger a invalid error
        dbCertificateCAChain = self.valid_certificate_ca_chain(  # noqa: F841
            certificate_ca_chain_id=certificate_ca_chain_id
        )

        # the ids are strings so that the fullchain id can be split by a client without further processing

        if id_only:
            return {
                "id": str(self.id),
                "private_key": {"id": str(self.private_key.id)},
                "certificate": {"id": str(self.id)},
                "chain": {"id": str(certificate_ca_chain_id)},
                "fullchain": {"id": "%s,%s" % (self.id, certificate_ca_chain_id)},
            }

        return {
            "id": str(self.id),
            "private_key": {
                "id": str(self.private_key.id),
                "pem": self.private_key.key_pem,
            },
            "certificate": {"id": str(self.id), "pem": self.cert_pem},
            "chain": {
                "id": str(certificate_ca_chain_id),
                "pem": self.valid_cert_chain_pem(
                    certificate_ca_chain_id=certificate_ca_chain_id
                ),
            },
            "fullchain": {
                "id": "%s,%s" % (self.id, certificate_ca_chain_id),
                "pem": self.valid_cert_fullchain_pem(
                    certificate_ca_chain_id=certificate_ca_chain_id
                ),
            },
        }

    @property
    def config_payload(self):
        return self.custom_config_payload(certificate_ca_chain_id=None, id_only=False)

    @property
    def config_payload_idonly(self):
        return self.custom_config_payload(certificate_ca_chain_id=None, id_only=True)

    @property
    def is_can_renew_letsencrypt(self):
        """only allow renew of LE certificates"""
        # if self.acme_account_id:
        #    return True
        return False

    @property
    def domains_as_string(self):
        return self.unique_fqdn_set.domains_as_string

    @property
    def domains_as_list(self):
        return self.unique_fqdn_set.domains_as_list

    @property
    def key_technology(self):
        if self.key_technology_id:
            return model_utils.KeyTechnology.as_string(self.key_technology_id)
        return None

    @property
    def renewals_managed_by(self):
        if self.acme_order:
            return "AcmeOrder"
        return "CertificateSigned"

    """
    @property
    def backup__private_key_cycle_id(self):
        if self.acme_order:
            _private_key_cycle__renewal = self.acme_order.private_key_cycle__renewal
            if _private_key_cycle__renewal == "account_key_default":
                 ???
            return self.acme_order.private_key_cycle_id__renewal
        else:
            return model_utils.PrivateKeyCycle.from_string(
                model_utils.PrivateKeyCycle._DEFAULT_system_renewal
            )
    """

    @property
    def renewal__private_key_cycle_id(self):
        if self.acme_order:
            return self.acme_order.private_key_cycle_id__renewal
        else:
            return model_utils.PrivateKeyCycle.from_string(
                model_utils.PrivateKeyCycle._DEFAULT_system_renewal
            )

    @property
    def renewal__private_key_strategy_id(self):
        if self.acme_order:
            _private_key_cycle__renewal = self.acme_order.private_key_cycle__renewal
            if _private_key_cycle__renewal != "account_key_default":
                _private_key_strategy = (
                    model_utils.PrivateKeyCycle_2_PrivateKeyStrategy[
                        _private_key_cycle__renewal
                    ]
                )
            else:
                _private_key_strategy = (
                    model_utils.PrivateKeyCycle_2_PrivateKeyStrategy[
                        self.acme_order.acme_account.private_key_cycle
                    ]
                )
            return model_utils.PrivateKeyStrategy.from_string(_private_key_strategy)
        else:
            return model_utils.PrivateKeyStrategy.from_string(
                model_utils.PrivateKeyStrategy._DEFAULT_system_renewal
            )

    def valid_certificate_ca_chain(self, certificate_ca_chain_id=None):
        """return a single CertificateCA, or the default"""
        for _to_upchain in self.certificate_signed_chains:
            if _to_upchain.certificate_ca_chain_id == certificate_ca_chain_id:
                return _to_upchain.certificate_ca_chain
        raise ValueError("No CertificateCAChain available (?!?!)")

    def valid_cert_chain_pem(self, certificate_ca_chain_id=None):
        certificate_chain = self.valid_certificate_ca_chain(
            certificate_ca_chain_id=certificate_ca_chain_id
        )
        return certificate_chain.chain_pem

    def valid_cert_fullchain_pem(self, certificate_ca_chain_id=None):
        certificate_chain = self.valid_certificate_ca_chain(
            certificate_ca_chain_id=certificate_ca_chain_id
        )
        # certs are standardized to have a newline
        return "\n".join((self.cert_pem.strip(), certificate_chain.chain_pem))

    @property
    def as_json(self):
        return {
            "acme_order.is_auto_renew": self.acme_order.is_auto_renew
            if self.acme_order
            else None,
            "domains_as_list": self.domains_as_list,
            "id": self.id,
            "is_active": True if self.is_active else False,
            "is_deactivated": True if self.is_deactivated else False,
            "is_revoked": True if self.is_revoked else False,
            "is_compromised_private_key": True
            if self.is_compromised_private_key
            else False,
            "timestamp_not_after": self.timestamp_not_after_isoformat,
            "timestamp_not_before": self.timestamp_not_before_isoformat,
            "timestamp_revoked_upstream": self.timestamp_revoked_upstream_isoformat,
            "certificate_ca_chain_id__preferred": self.certificate_ca_chain_id__preferred,
            "certificate_ca_chain_ids": self.certificate_ca_chain_ids,
            "certificate_ca_ids__upchain": self.certificate_ca_ids__upchain,
            "cert_pem": self.cert_pem,
            "cert_pem_md5": self.cert_pem_md5,
            "cert_subject": self.cert_subject,
            "cert_issuer": self.cert_issuer,
            "fingerprint_sha1": self.fingerprint_sha1,
            "spki_sha256": self.spki_sha256,
            "key_technology": self.key_technology,
            "private_key_id": self.private_key_id,
            # "acme_account_id": self.acme_account_id,
            "renewals_managed_by": self.renewals_managed_by,
            "unique_fqdn_set_id": self.unique_fqdn_set_id,
        }


# ==============================================================================


class CertificateSignedChain(Base):
    """
    It is possible for alternate chains to be provided for a CertificateSigned

    ``is_upstream_default`` is a boolean used to track if the issuing ACME Server
    presented the CertificateCAChain as the primary/default chain (``True``), or if
    the upstream server provided the CertificateCA as an alternate chain.
    """

    __tablename__ = "certificate_signed_chain"
    id = sa.Column(sa.Integer, primary_key=True)
    certificate_signed_id = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_signed.id"), nullable=False
    )
    certificate_ca_chain_id = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_ca_chain.id"), nullable=False
    )
    is_upstream_default = sa.Column(sa.Boolean, nullable=True, default=None)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    certificate_ca_chain = sa_orm_relationship(
        "CertificateCAChain",
        primaryjoin="CertificateSignedChain.certificate_ca_chain_id==CertificateCAChain.id",
        uselist=False,
    )
    certificate_signed = sa_orm_relationship(
        "CertificateSigned",
        primaryjoin="CertificateSignedChain.certificate_signed_id==CertificateSigned.id",
        uselist=False,
        back_populates="certificate_signed_chains",
    )


# ==============================================================================


class CoverageAssuranceEvent(Base, _Mixin_Timestamps_Pretty):
    """
    A CoverageAssuranceEvent occurs when a CertificateSigned is deactivated
    """

    __tablename__ = "coverage_assurance_event"
    __table_args__ = (
        sa.CheckConstraint(
            "(private_key_id IS NOT NULL OR certificate_signed_id IS NOT NULL OR queue_certificate_id IS NOT NULL)",
            name="check_pkey_andor_certs",
        ),
    )

    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    private_key_id = sa.Column(
        sa.Integer, sa.ForeignKey("private_key.id"), nullable=True
    )
    certificate_signed_id = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_signed.id"), nullable=True
    )
    queue_certificate_id = sa.Column(
        sa.Integer, sa.ForeignKey("queue_certificate.id"), nullable=True
    )
    coverage_assurance_event_type_id = sa.Column(
        sa.Integer, nullable=False
    )  # `model_utils.CoverageAssuranceEventType`
    coverage_assurance_event_status_id = sa.Column(
        sa.Integer, nullable=False
    )  # `model_utils.CoverageAssuranceEventStatus`
    coverage_assurance_resolution_id = sa.Column(
        sa.Integer, nullable=False
    )  # `model_utils.CoverageAssuranceResolution`
    coverage_assurance_event_id__parent = sa.Column(
        sa.Integer, sa.ForeignKey("coverage_assurance_event.id"), nullable=True
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    certificate_signed = sa_orm_relationship(
        "CertificateSigned",
        primaryjoin="CoverageAssuranceEvent.certificate_signed_id==CertificateSigned.id",
        back_populates="coverage_assurance_events",
        uselist=False,
    )
    coverage_assurance_event__children = sa_orm_relationship(
        "CoverageAssuranceEvent",
        backref=sa.orm.backref("coverage_assurance_event__parent", remote_side=[id]),
    )
    operations_object_events = sa_orm_relationship(
        "OperationsObjectEvent",
        primaryjoin="CoverageAssuranceEvent.id==OperationsObjectEvent.coverage_assurance_event_id",
        back_populates="coverage_assurance_event",
        uselist=True,
    )
    private_key = sa_orm_relationship(
        "PrivateKey",
        primaryjoin="CoverageAssuranceEvent.private_key_id==PrivateKey.id",
        back_populates="coverage_assurance_events",
        uselist=False,
    )
    queue_certificate = sa_orm_relationship(
        "QueueCertificate",
        primaryjoin="CoverageAssuranceEvent.queue_certificate_id==QueueCertificate.id",
        back_populates="coverage_assurance_events",
        uselist=False,
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def coverage_assurance_event_type(self):
        return model_utils.CoverageAssuranceEventType.as_string(
            self.coverage_assurance_event_type_id
        )

    @property
    def coverage_assurance_event_status(self):
        return model_utils.CoverageAssuranceEventStatus.as_string(
            self.coverage_assurance_event_status_id
        )

    @property
    def coverage_assurance_resolution(self):
        return model_utils.CoverageAssuranceResolution.as_string(
            self.coverage_assurance_resolution_id
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def as_json(self):
        payload = {
            "id": self.id,
            "timestamp_created": self.timestamp_created_isoformat,
            "private_key_id": self.private_key_id,
            "certificate_signed_id": self.private_key_id,
            "coverage_assurance_event_type": self.coverage_assurance_event_type,
            "coverage_assurance_event_status": self.coverage_assurance_event_status,
            "coverage_assurance_resolution": self.coverage_assurance_resolution,
            "coverage_assurance_event_id__parent": self.coverage_assurance_event_id__parent,
        }
        return payload


# ==============================================================================


class Domain(Base, _Mixin_Timestamps_Pretty):
    """
    A Fully Qualified Domain
    """

    __tablename__ = "domain"
    __table_args__ = (
        sa.Index(
            "uidx_domain",
            model_utils.indexable_lower(sa.text("domain_name")),
            unique=True,
        ),
    )

    id = sa.Column(sa.Integer, primary_key=True)
    domain_name = sa.Column(sa.Unicode(255), nullable=False)
    is_active = sa.Column(sa.Boolean, nullable=False, default=True)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)

    is_from_queue_domain = sa.Column(
        sa.Boolean, nullable=True, default=None
    )  # ???: deprecation candidate
    certificate_signed_id__latest_single = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_signed.id"), nullable=True
    )
    certificate_signed_id__latest_multi = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_signed.id"), nullable=True
    )
    operations_event_id__created = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_authorizations = sa_orm_relationship(
        "AcmeAuthorization",
        primaryjoin="Domain.id==AcmeAuthorization.domain_id",
        order_by="AcmeAuthorization.id.desc()",
        uselist=True,
        back_populates="domain",
    )
    acme_challenges = sa_orm_relationship(
        "AcmeChallenge",
        primaryjoin="Domain.id==AcmeChallenge.domain_id",
        uselist=True,
        back_populates="domain",
    )
    acme_dns_server_accounts = sa_orm_relationship(
        "AcmeDnsServerAccount",
        primaryjoin="Domain.id==AcmeDnsServerAccount.domain_id",
        uselist=True,
        back_populates="domain",
    )
    acme_dns_server_account__active = sa_orm_relationship(
        "AcmeDnsServerAccount",
        primaryjoin=(
            "and_("
            "Domain.id==AcmeDnsServerAccount.domain_id,"
            "AcmeDnsServerAccount.is_active.is_(True)"
            ")"
        ),
        uselist=False,
        overlaps="acme_dns_server_accounts,domain",
    )
    acme_order_2_acme_challenge_type_specifics = sa_orm_relationship(
        "AcmeOrder2AcmeChallengeTypeSpecific",
        primaryjoin="Domain.id==AcmeOrder2AcmeChallengeTypeSpecific.domain_id",
        uselist=True,
        back_populates="domain",
    )
    certificate_signed__latest_single = sa_orm_relationship(
        "CertificateSigned",
        primaryjoin="Domain.certificate_signed_id__latest_single==CertificateSigned.id",
        uselist=False,
    )
    certificate_signed__latest_multi = sa_orm_relationship(
        "CertificateSigned",
        primaryjoin="Domain.certificate_signed_id__latest_multi==CertificateSigned.id",
        uselist=False,
    )
    domain_autocerts = sa_orm_relationship(
        "DomainAutocert",
        primaryjoin="Domain.id==DomainAutocert.domain_id",
        uselist=True,
        back_populates="domain",
    )
    operations_object_events = sa_orm_relationship(
        "OperationsObjectEvent",
        primaryjoin="Domain.id==OperationsObjectEvent.domain_id",
        back_populates="domain",
    )
    queue_domain = sa.orm.relationship(
        "QueueDomain",
        primaryjoin="Domain.id==QueueDomain.domain_id",
        uselist=False,
        back_populates="domain",
    )
    to_fqdns = sa_orm_relationship(
        "UniqueFQDNSet2Domain",
        primaryjoin="Domain.id==UniqueFQDNSet2Domain.domain_id",
        back_populates="domain",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def has_active_certificates(self):
        return (
            True
            if (
                self.certificate_signed_id__latest_single
                or self.certificate_signed_id__latest_multi
            )
            else False
        )

    @property
    def as_json(self):
        payload = {
            "id": self.id,
            "is_active": True if self.is_active else False,
            "domain_name": self.domain_name,
            "certificate__latest_multi": {},
            "certificate__latest_single": {},
        }
        if self.certificate_signed_id__latest_multi:
            payload["certificate__latest_multi"] = {
                "id": self.certificate_signed_id__latest_multi,
                "timestamp_not_after": self.certificate_signed__latest_multi.timestamp_not_after_isoformat,
                "expiring_days": self.certificate_signed__latest_multi.expiring_days,
            }
        if self.certificate_signed_id__latest_single:
            payload["certificate__latest_single"] = {
                "id": self.certificate_signed_id__latest_single,
                "timestamp_not_after": self.certificate_signed__latest_single.timestamp_not_after_isoformat,
                "expiring_days": self.certificate_signed__latest_single.expiring_days,
            }
        return payload

    def as_json_config(self, id_only=False, active_only=None):
        """
        this is slightly different
        * everything is lowercase
        * id is a string
        """
        rval = {
            "domain": {
                "id": str(self.id),
                "domain_name": self.domain_name,
                "is_active": self.is_active,
            },
            "certificate_signed__latest_single": None,
            "certificate_signed__latest_multi": None,
        }
        if active_only and not self.is_active:
            return rval
        if self.certificate_signed_id__latest_single:
            if id_only:
                rval[
                    "certificate_signed__latest_single"
                ] = self.certificate_signed__latest_single.config_payload_idonly
            else:
                rval[
                    "certificate_signed__latest_single"
                ] = self.certificate_signed__latest_single.config_payload
        if self.certificate_signed_id__latest_multi:
            if id_only:
                rval[
                    "certificate_signed__latest_multi"
                ] = self.certificate_signed__latest_multi.config_payload_idonly
            else:
                rval[
                    "certificate_signed__latest_multi"
                ] = self.certificate_signed__latest_multi.config_payload
        return rval


# ==============================================================================


class DomainAutocert(Base, _Mixin_Timestamps_Pretty):
    """
    Track autocerts of a domain specifically, because the process should 'block'
    """

    __tablename__ = "domain_autocert"
    id = sa.Column(sa.Integer, primary_key=True)
    domain_id = sa.Column(sa.Integer, sa.ForeignKey("domain.id"), nullable=True)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    timestamp_finished = sa.Column(sa.DateTime, nullable=True)
    is_successful = sa.Column(sa.Boolean, nullable=True, default=None)
    acme_order_id = sa.Column(sa.Integer, sa.ForeignKey("acme_order.id"), nullable=True)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_order = sa_orm_relationship(
        "AcmeOrder",
        primaryjoin="DomainAutocert.acme_order_id==AcmeOrder.id",
        uselist=False,
        # no back_populates
    )
    domain = sa_orm_relationship(
        "Domain",
        primaryjoin="DomainAutocert.domain_id==Domain.id",
        uselist=False,
        back_populates="domain_autocerts",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def as_json(self):
        payload = {
            "id": self.id,
            "Domain": {
                "id": self.domain_id,
                "domain_name": self.domain.domain_name,
            },
            "timestamp_created": self.timestamp_created_isoformat,
            "timestamp_finished": self.timestamp_finished_isoformat,
            "is_successful": self.is_successful,
            "AcmeOrder": {"id": self.acme_order_id} if self.acme_order_id else None,
        }
        return payload


# ==============================================================================


class DomainBlocklisted(Base, _Mixin_Timestamps_Pretty):
    """
    A Fully Qualified Domain that has been blocklisted from the system
    """

    __tablename__ = "domain_blocklisted"
    __table_args__ = (
        sa.Index(
            "uidx_domain_blocklisted",
            model_utils.indexable_lower(sa.text("domain_name")),
            unique=True,
        ),
    )

    id = sa.Column(sa.Integer, primary_key=True)
    domain_name = sa.Column(sa.Unicode(255), nullable=False)

    @property
    def as_json(self):
        return {
            "id": self.id,
            "domain_name": self.domain_name,
        }


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
        self.event_payload = json.dumps(payload_dict, sort_keys=True)


# ==============================================================================


class OperationsObjectEvent(Base, _Mixin_Timestamps_Pretty):
    """Domains updates are noted here"""

    __tablename__ = "operations_object_event"
    __table_args__ = (
        sa.CheckConstraint(
            " ( "
            " CASE WHEN acme_account_id IS NOT NULL THEN 1 ELSE 0 END "
            " + "
            " CASE WHEN acme_account_key_id IS NOT NULL THEN 1 ELSE 0 END "
            " + "
            " CASE WHEN acme_order_id IS NOT NULL THEN 1 ELSE 0 END "
            " + "
            " CASE WHEN acme_dns_server_id IS NOT NULL THEN 1 ELSE 0 END "
            " + "
            " CASE WHEN certificate_ca_id IS NOT NULL THEN 1 ELSE 0 END"
            " + "
            " CASE WHEN certificate_ca_chain_id IS NOT NULL THEN 1 ELSE 0 END"
            " + "
            " CASE WHEN certificate_request_id IS NOT NULL THEN 1 ELSE 0 END "
            " + "
            " CASE WHEN certificate_signed_id IS NOT NULL THEN 1 ELSE 0 END "
            " + "
            " CASE WHEN coverage_assurance_event_id IS NOT NULL THEN 1 ELSE 0 END "
            " + "
            " CASE WHEN domain_id IS NOT NULL THEN 1 ELSE 0 END "
            " + "
            " CASE WHEN private_key_id IS NOT NULL THEN 1 ELSE 0 END "
            " + "
            " CASE WHEN queue_certificate_id IS NOT NULL THEN 1 ELSE 0 END "
            " + "
            " CASE WHEN queue_domain_id IS NOT NULL THEN 1 ELSE 0 END "
            " + "
            " CASE WHEN unique_fqdn_set_id IS NOT NULL THEN 1 ELSE 0 END "
            " ) = 1",
            name="check1",
        ),
    )

    id = sa.Column(sa.Integer, primary_key=True)
    operations_event_id = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=True
    )
    operations_object_event_status_id = sa.Column(
        sa.Integer, nullable=False
    )  # references OperationsObjectEventStatus

    acme_account_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_account.id"), nullable=True
    )
    acme_account_key_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_account_key.id"), nullable=True
    )
    acme_dns_server_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_dns_server.id"), nullable=True
    )
    acme_order_id = sa.Column(sa.Integer, sa.ForeignKey("acme_order.id"), nullable=True)
    certificate_ca_id = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_ca.id"), nullable=True
    )
    certificate_ca_chain_id = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_ca_chain.id"), nullable=True
    )
    certificate_request_id = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_request.id"), nullable=True
    )
    certificate_signed_id = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_signed.id"), nullable=True
    )
    coverage_assurance_event_id = sa.Column(
        sa.Integer, sa.ForeignKey("coverage_assurance_event.id"), nullable=True
    )
    domain_id = sa.Column(sa.Integer, sa.ForeignKey("domain.id"), nullable=True)
    private_key_id = sa.Column(
        sa.Integer, sa.ForeignKey("private_key.id"), nullable=True
    )
    queue_certificate_id = sa.Column(
        sa.Integer, sa.ForeignKey("queue_certificate.id"), nullable=True
    )
    queue_domain_id = sa.Column(
        sa.Integer, sa.ForeignKey("queue_domain.id"), nullable=True
    )
    unique_fqdn_set_id = sa.Column(
        sa.Integer, sa.ForeignKey("unique_fqdn_set.id"), nullable=True
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    operations_event = sa_orm_relationship(
        "OperationsEvent",
        primaryjoin="OperationsObjectEvent.operations_event_id==OperationsEvent.id",
        uselist=False,
        back_populates="object_events",
    )

    acme_account = sa_orm_relationship(
        "AcmeAccount",
        primaryjoin="OperationsObjectEvent.acme_account_id==AcmeAccount.id",
        uselist=False,
        back_populates="operations_object_events",
    )
    acme_account_key = sa_orm_relationship(
        "AcmeAccountKey",
        primaryjoin="OperationsObjectEvent.acme_account_key_id==AcmeAccountKey.id",
        uselist=False,
        back_populates="operations_object_events",
    )
    acme_order = sa_orm_relationship(
        "AcmeOrder",
        primaryjoin="OperationsObjectEvent.acme_order_id==AcmeOrder.id",
        uselist=False,
        back_populates="operations_object_events",
    )
    certificate_ca = sa_orm_relationship(
        "CertificateCA",
        primaryjoin="OperationsObjectEvent.certificate_ca_id==CertificateCA.id",
        uselist=False,
        back_populates="operations_object_events",
    )
    certificate_request = sa_orm_relationship(
        "CertificateRequest",
        primaryjoin="OperationsObjectEvent.certificate_request_id==CertificateRequest.id",
        uselist=False,
        back_populates="operations_object_events",
    )
    certificate_signed = sa_orm_relationship(
        "CertificateSigned",
        primaryjoin="OperationsObjectEvent.certificate_signed_id==CertificateSigned.id",
        uselist=False,
        back_populates="operations_object_events",
    )
    coverage_assurance_event = sa_orm_relationship(
        "CoverageAssuranceEvent",
        primaryjoin="OperationsObjectEvent.coverage_assurance_event_id==CoverageAssuranceEvent.id",
        uselist=False,
        back_populates="operations_object_events",
    )
    domain = sa_orm_relationship(
        "Domain",
        primaryjoin="OperationsObjectEvent.domain_id==Domain.id",
        uselist=False,
        back_populates="operations_object_events",
    )

    private_key = sa_orm_relationship(
        "PrivateKey",
        primaryjoin="OperationsObjectEvent.private_key_id==PrivateKey.id",
        uselist=False,
        back_populates="operations_object_events",
    )
    queue_certificate = sa_orm_relationship(
        "QueueCertificate",
        primaryjoin="OperationsObjectEvent.queue_certificate_id==QueueCertificate.id",
        uselist=False,
        back_populates="operations_object_events",
    )
    queue_domain = sa_orm_relationship(
        "QueueDomain",
        primaryjoin="OperationsObjectEvent.queue_domain_id==QueueDomain.id",
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


class PrivateKey(Base, _Mixin_Timestamps_Pretty, _Mixin_Hex_Pretty):
    """
    These keys are used to sign CertificateRequests and are the PrivateKey component to a CertificateSigned.

    If `acme_account_id__owner` is specified, this key can only be used in combination with that key.
    """

    __tablename__ = "private_key"
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    key_technology_id = sa.Column(
        sa.Integer, nullable=False
    )  # see .utils.KeyTechnology
    key_pem = sa.Column(sa.Text, nullable=False)
    key_pem_md5 = sa.Column(sa.Unicode(32), nullable=False)
    spki_sha256 = sa.Column(sa.Unicode(64), nullable=False)

    count_active_certificates = sa.Column(sa.Integer, nullable=True)
    is_active = sa.Column(sa.Boolean, nullable=False, default=True)
    is_compromised = sa.Column(sa.Boolean, nullable=True, default=None)
    count_acme_orders = sa.Column(sa.Integer, nullable=True, default=0)
    count_certificate_signeds = sa.Column(sa.Integer, nullable=True, default=0)
    timestamp_last_certificate_request = sa.Column(sa.DateTime, nullable=True)
    timestamp_last_certificate_issue = sa.Column(sa.DateTime, nullable=True)
    operations_event_id__created = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )
    private_key_source_id = sa.Column(
        sa.Integer, nullable=False
    )  # see .utils.PrivateKeySource
    private_key_type_id = sa.Column(
        sa.Integer,
        nullable=False,
    )  # see .utils.PrivateKeyType
    acme_account_id__owner = sa.Column(
        sa.Integer, sa.ForeignKey("acme_account.id"), nullable=True
    )  # lock a PrivateKey to an AcmeAccount
    private_key_id__replaces = sa.Column(
        sa.Integer, sa.ForeignKey("private_key.id"), nullable=True
    )  # if this key replaces a compromised PrivateKey, note it.

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_account__owner = sa_orm_relationship(
        "AcmeAccount",
        primaryjoin="PrivateKey.acme_account_id__owner==AcmeAccount.id",
        uselist=False,
        back_populates="private_keys__owned",
    )
    acme_orders = sa_orm_relationship(
        "AcmeOrder",
        primaryjoin="PrivateKey.id==AcmeOrder.private_key_id",
        order_by="AcmeOrder.id.desc()",
        back_populates="private_key",
    )
    certificate_requests = sa_orm_relationship(
        "CertificateRequest",
        primaryjoin="PrivateKey.id==CertificateRequest.private_key_id",
        order_by="CertificateRequest.id.desc()",
        back_populates="private_key",
    )
    certificate_signeds = sa_orm_relationship(
        "CertificateSigned",
        primaryjoin="PrivateKey.id==CertificateSigned.private_key_id",
        order_by="CertificateSigned.id.desc()",
        back_populates="private_key",
    )
    coverage_assurance_events = sa_orm_relationship(
        "CoverageAssuranceEvent",
        primaryjoin="PrivateKey.id==CoverageAssuranceEvent.private_key_id",
        back_populates="private_key",
        uselist=True,
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
    def is_autogenerated_calendar(self):
        if self.private_key_type in model_utils.PrivateKeyType._options_calendar:
            return True
        return False

    @property
    def autogenerated_calendar_repr(self):
        if not self.is_autogenerated_calendar:
            return ""
        if self.private_key_type in model_utils.PrivateKeyType._options_calendar_weekly:
            return "%s.%s" % self.timestamp_created.isocalendar()[0:2]
        # daily
        return "%s.%s.%s" % self.timestamp_created.isocalendar()[0:3]

    @property
    def is_key_usable(self):
        if self.is_compromised or not self.is_active:
            return False
        return True

    @property
    def can_key_sign(self):
        if self.is_compromised or not self.is_active or (self.id == 0):
            return False
        return True

    @property
    def is_placeholder(self):
        if self.id == 0:
            return True
        return False

    @property
    def key_spki_search(self):
        return "type=spki&spki=%s&source=private_key&private_key.id=%s" % (
            self.spki_sha256,
            self.id,
        )

    @property
    def key_pem_sample(self):
        # strip the pem, because the last line is whitespace after "-----END RSA PRIVATE KEY-----"
        try:
            pem_lines = self.key_pem.strip().split("\n")
            return "%s...%s" % (pem_lines[1][0:5], pem_lines[-2][-5:])
        except Exception as exc:  # noqa: F841
            # it's possible to have no lines if this is the placeholder key
            return "..."

    @property
    def key_technology(self):
        if self.key_technology_id:
            return model_utils.KeyTechnology.as_string(self.key_technology_id)
        return None

    @reify
    def private_key_source(self):
        return model_utils.PrivateKeySource.as_string(self.private_key_source_id)

    @reify
    def private_key_type(self):
        return model_utils.PrivateKeyType.as_string(self.private_key_type_id)

    @property
    def as_json(self):
        return {
            "id": self.id,
            "is_active": True if self.is_active else False,
            "is_compromised": True if self.is_compromised else False,
            "key_pem_md5": self.key_pem_md5,
            "key_pem": self.key_pem,
            "key_technology": self.key_technology,
            "spki_sha256": self.spki_sha256,
            "timestamp_created": self.timestamp_created_isoformat,
            "private_key_source": self.private_key_source,
            "private_key_type": self.private_key_type,
            "private_key_id__replaces": self.private_key_id__replaces,
            "autogenerated_calendar_repr": self.autogenerated_calendar_repr,
        }


# ==============================================================================


class QueueCertificate(Base, _Mixin_Timestamps_Pretty):
    """
    An item to be renewed.
    If something is expired, it will be placed here for renewal

    - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    `QueueCertificate.is_active` - a boolean triplet with the following meaning:
        True  :  The QueueCertificate is active and should be part of the next processing batch.
        False :  The QueueCertificate has processed, it may be successful or a failure.
        None  :  The QueueCertificate has been cancelled by the user.
    """

    __tablename__ = "queue_certificate"
    __table_args__ = (
        sa.CheckConstraint(
            "(CASE WHEN acme_order_id__source IS NOT NULL THEN 1 ELSE 0 END"
            " + "
            " CASE WHEN certificate_signed_id__source IS NOT NULL THEN 1 ELSE 0 END "
            " + "
            " CASE WHEN unique_fqdn_set_id__source IS NOT NULL THEN 1 ELSE 0 END "
            " ) = 1",
            name="check_queue_certificate_source",
        ),
    )

    id = sa.Column(sa.Integer, primary_key=True)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    timestamp_processed = sa.Column(sa.DateTime, nullable=True)
    timestamp_process_attempt = sa.Column(
        sa.DateTime, nullable=True
    )  # if not-null then an attempt was made on this item
    process_result = sa.Column(
        sa.Boolean, nullable=True, default=None
    )  # True/False are attempts; None is untouched
    operations_event_id__created = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )
    is_active = sa.Column(
        sa.Boolean, nullable=False, default=True
    )  # see docstring above for QueueCertificate.is_active
    private_key_strategy_id__requested = sa.Column(
        sa.Integer, nullable=False
    )  # see .utils.PrivateKeyStrategy

    # this is our core requirements. all must be present
    acme_account_id = sa.Column(
        sa.Integer, sa.ForeignKey("acme_account.id"), nullable=False
    )
    private_key_id = sa.Column(
        sa.Integer, sa.ForeignKey("private_key.id"), nullable=False
    )
    unique_fqdn_set_id = sa.Column(
        sa.Integer, sa.ForeignKey("unique_fqdn_set.id"), nullable=False
    )

    # bookkeeping - what is the source?
    # only one of these 3 can be not-null, see `check_queue_certificate_source`
    acme_order_id__source = sa.Column(
        sa.Integer, sa.ForeignKey("acme_order.id"), nullable=True
    )
    certificate_signed_id__source = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_signed.id"), nullable=True
    )
    unique_fqdn_set_id__source = sa.Column(
        sa.Integer, sa.ForeignKey("unique_fqdn_set.id"), nullable=True
    )

    # bookkeeping - what is generated?
    acme_order_id__generated = sa.Column(
        sa.Integer, sa.ForeignKey("acme_order.id"), nullable=True
    )
    certificate_request_id__generated = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_request.id"), nullable=True
    )
    certificate_signed_id__generated = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_signed.id"), nullable=True
    )

    # let's require this
    private_key_cycle_id__renewal = sa.Column(
        sa.Integer, nullable=False
    )  # see .utils.PrivateKeyCycle

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_account = sa.orm.relationship(
        "AcmeAccount",
        primaryjoin="QueueCertificate.acme_account_id==AcmeAccount.id",
        uselist=False,
    )
    acme_order__generated = sa.orm.relationship(
        "AcmeOrder",
        primaryjoin="QueueCertificate.acme_order_id__generated==AcmeOrder.id",
        back_populates="queue_certificate__generator",
        uselist=False,
    )
    acme_order__source = sa.orm.relationship(
        "AcmeOrder",
        primaryjoin="QueueCertificate.acme_order_id__source==AcmeOrder.id",
        uselist=False,
    )
    certificate_request__generated = sa.orm.relationship(
        "CertificateRequest",
        primaryjoin="QueueCertificate.certificate_request_id__generated==CertificateRequest.id",
        uselist=False,
    )
    certificate_signed__generated = sa.orm.relationship(
        "CertificateSigned",
        primaryjoin="QueueCertificate.certificate_signed_id__generated==CertificateSigned.id",
        back_populates="queue_certificate__parent",
        uselist=False,
    )
    certificate_signed__source = sa.orm.relationship(
        "CertificateSigned",
        primaryjoin="QueueCertificate.certificate_signed_id__source==CertificateSigned.id",
        back_populates="queue_certificate__renewal",
        uselist=False,
    )
    coverage_assurance_events = sa_orm_relationship(
        "CoverageAssuranceEvent",
        primaryjoin="QueueCertificate.id==CoverageAssuranceEvent.queue_certificate_id",
        back_populates="queue_certificate",
        uselist=True,
    )
    operations_event__created = sa.orm.relationship(
        "OperationsEvent",
        primaryjoin="QueueCertificate.operations_event_id__created==OperationsEvent.id",
        uselist=False,
    )
    operations_object_events = sa.orm.relationship(
        "OperationsObjectEvent",
        primaryjoin="QueueCertificate.id==OperationsObjectEvent.queue_certificate_id",
        back_populates="queue_certificate",
    )
    private_key = sa.orm.relationship(
        "PrivateKey",
        primaryjoin="QueueCertificate.private_key_id==PrivateKey.id",
        uselist=False,
    )
    unique_fqdn_set = sa.orm.relationship(
        "UniqueFQDNSet",
        primaryjoin="QueueCertificate.unique_fqdn_set_id==UniqueFQDNSet.id",
        uselist=False,
        back_populates="queue_certificates",
        overlaps="queue_certificates__active",
    )
    unique_fqdn_set__source = sa.orm.relationship(
        "UniqueFQDNSet",
        primaryjoin="QueueCertificate.unique_fqdn_set_id__source==UniqueFQDNSet.id",
        uselist=False,
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def domains_as_list(self):
        return self.unique_fqdn_set.domains_as_list

    @reify
    def private_key_cycle__renewal(self):
        return model_utils.PrivateKeyCycle.as_string(self.private_key_cycle_id__renewal)

    @reify
    def private_key_strategy__requested(self):
        return (
            model_utils.PrivateKeyStrategy.as_string(
                self.private_key_strategy_id__requested
            )
            if self.private_key_strategy_id__requested
            else ""
        )

    @property
    def as_json(self):
        rval = {
            "id": self.id,
            "process_result": self.process_result,
            "timestamp_created": self.timestamp_created_isoformat,
            "timestamp_processed": self.timestamp_processed_isoformat,
            "timestamp_process_attempt": self.timestamp_process_attempt_isoformat,
            "is_active": self.is_active,
            "acme_account_id": self.acme_account_id,
            "private_key_strategy__requested": self.private_key_strategy__requested,
            "private_key_cycle__renewal": self.private_key_cycle__renewal,
            "private_key_id": self.private_key_id,
            "unique_fqdn_set_id": self.unique_fqdn_set_id,
            "generated": {
                "acme_order_id__generated": self.acme_order_id__generated,
                "certificate_request_id__generated": self.certificate_request_id__generated,
                "certificate_signed_id__generated": self.certificate_signed_id__generated,
            },
            "source": {
                "acme_order_id__source": self.acme_order_id__source,
                "certificate_signed_id__source": self.certificate_signed_id__source,
                "unique_fqdn_set_id__source": self.unique_fqdn_set_id__source,
            },
        }
        if self.acme_order_id__generated:
            rval["generated"]["AcmeOrder"] = {
                "id": self.acme_order_id__generated,
                "status": self.acme_order__generated.acme_status_order,
            }
        return rval


# ==============================================================================


class QueueDomain(Base, _Mixin_Timestamps_Pretty):
    """
    A list of domains to be queued into CertificateSigneds.
    This is only used for batch processing consumer Domains
    Domains that are included in CertificateRequests or CertificateSigneds
    The DomainQueue will allow you to queue-up Domain names for management

    - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    `QueueDomain.is_active` - a boolean triplet with the following meaning:
        True  :  The QueueDomain is active and should be part of the next processing batch.
        False :  The QueueDomain has completed, it may be successful or a failure.
        None  :  The QueueDomain has been cancelled by the user.
    """

    __tablename__ = "queue_domain"
    id = sa.Column(sa.Integer, primary_key=True)
    domain_name = sa.Column(sa.Unicode(255), nullable=False)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    timestamp_processed = sa.Column(sa.DateTime, nullable=True)
    domain_id = sa.Column(sa.Integer, sa.ForeignKey("domain.id"), nullable=True)
    is_active = sa.Column(
        sa.Boolean, nullable=True, default=True
    )  # see docstring above for QueueDomain.is_active
    operations_event_id__created = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    domain = sa.orm.relationship(
        "Domain",
        primaryjoin="QueueDomain.domain_id==Domain.id",
        uselist=False,
        back_populates="queue_domain",
    )

    operations_event__created = sa.orm.relationship(
        "OperationsEvent",
        primaryjoin="QueueDomain.operations_event_id__created==OperationsEvent.id",
        uselist=False,
    )

    operations_object_events = sa.orm.relationship(
        "OperationsObjectEvent",
        primaryjoin="QueueDomain.id==OperationsObjectEvent.queue_domain_id",
        back_populates="queue_domain",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def as_json(self):
        return {
            "id": self.id,
            "domain_name": self.domain_name,
            "timestamp_created": self.timestamp_created_isoformat,
            "timestamp_processed": self.timestamp_processed_isoformat,
            "domain_id": self.domain_id,
            "is_active": True if self.is_active else False,
        }


# ==============================================================================


class RemoteIpAddress(Base, _Mixin_Timestamps_Pretty):
    """
    tracking remote ips, we should only see our tests and the letsencrypt service
    """

    __tablename__ = "remote_ip_address"

    id = sa.Column(sa.Integer, primary_key=True)
    remote_ip_address = sa.Column(sa.Unicode(255), nullable=False)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_challenge_polls = sa_orm_relationship(
        "AcmeChallengePoll",
        primaryjoin="RemoteIpAddress.id==AcmeChallengePoll.remote_ip_address_id",
        uselist=True,
        back_populates="remote_ip_address",
    )
    acme_challenge_unknown_polls = sa_orm_relationship(
        "AcmeChallengeUnknownPoll",
        primaryjoin="RemoteIpAddress.id==AcmeChallengeUnknownPoll.remote_ip_address_id",
        uselist=True,
        back_populates="remote_ip_address",
    )


# ==============================================================================


class RootStore(Base, _Mixin_Timestamps_Pretty):
    __tablename__ = "root_store"
    __table_args__ = (
        sa.Index(
            "uidx_root_store_name",
            model_utils.indexable_lower(sa.text("name")),
            unique=True,
        ),
    )

    id = sa.Column(sa.Integer, primary_key=True)
    name = sa.Column(sa.Text, nullable=False)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    root_store_versions = sa_orm_relationship(
        "RootStoreVersion",
        primaryjoin="RootStore.id==RootStoreVersion.root_store_id",
        back_populates="root_store",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def as_json(self):
        return {
            "id": self.id,
            "name": self.name,
            "versions": [i.as_json for i in self.root_store_versions],
        }


class RootStoreVersion(Base, _Mixin_Timestamps_Pretty):
    __tablename__ = "root_store_version"
    __table_args__ = (
        sa.Index(
            "uidx_root_store_version",
            "root_store_id",
            model_utils.indexable_lower(sa.text("version_string")),
            unique=True,
        ),
    )

    id = sa.Column(sa.Integer, primary_key=True)
    root_store_id = sa.Column(
        sa.Integer, sa.ForeignKey("root_store.id"), nullable=False
    )
    version_string = sa.Column(sa.Integer, nullable=False)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    root_store = sa_orm_relationship(
        "RootStore",
        primaryjoin="RootStoreVersion.root_store_id==RootStore.id",
        uselist=False,
        back_populates="root_store_versions",
    )
    to_certificate_cas = sa_orm_relationship(
        "RootStoreVersion_2_CertificateCA",
        primaryjoin="RootStoreVersion.id==RootStoreVersion_2_CertificateCA.root_store_version_id",
        back_populates="root_store_version",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def as_json(self):
        return {
            "id": self.id,
            "name": self.root_store.name,
            "version_string": self.version_string,
        }


class RootStoreVersion_2_CertificateCA(Base, _Mixin_Timestamps_Pretty):
    __tablename__ = "root_store_version_2_certificate_ca"
    id = sa.Column(sa.Integer, primary_key=True)
    root_store_version_id = sa.Column(
        sa.Integer, sa.ForeignKey("root_store_version.id"), nullable=False
    )
    certificate_ca_id = sa.Column(
        sa.Integer, sa.ForeignKey("certificate_ca.id"), nullable=False
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    root_store_version = sa_orm_relationship(
        "RootStoreVersion",
        primaryjoin="RootStoreVersion_2_CertificateCA.root_store_version_id==RootStoreVersion.id",
        uselist=False,
        back_populates="to_certificate_cas",
    )
    certificate_ca = sa_orm_relationship(
        "CertificateCA",
        primaryjoin="RootStoreVersion_2_CertificateCA.certificate_ca_id==CertificateCA.id",
        uselist=False,
        back_populates="to_root_store_versions",
    )


# ==============================================================================


class UniqueFQDNSet(Base, _Mixin_Timestamps_Pretty):
    """
    UniqueFQDNSets are used for two reasons:

    1. They simplify tracking Lineage of Certificates vs Certbot's approach.
    2. There is a ratelimit in effect from LetsEncrypt for unique sets of
       fully-qualified domain names

    Domains are actually associated to the UniqueFQDNSet by the table:
    `UniqueFQDNSet2Domain`.

    The column `domain_ids_string` is a unique list of ordered ids, separated by
    commas. This is used as a fingerprint for searching and deduplication.
    """

    # note: RATELIMIT.FQDN

    __tablename__ = "unique_fqdn_set"
    id = sa.Column(sa.Integer, primary_key=True)
    domain_ids_string = sa.Column(sa.Text, nullable=False, unique=True)
    count_domains = sa.Column(sa.Integer, nullable=False)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    operations_event_id__created = sa.Column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_orders = sa_orm_relationship(
        "AcmeOrder",
        primaryjoin="UniqueFQDNSet.id==AcmeOrder.unique_fqdn_set_id",
        uselist=True,
        back_populates="unique_fqdn_set",
    )
    certificate_requests = sa_orm_relationship(
        "CertificateRequest",
        primaryjoin="UniqueFQDNSet.id==CertificateRequest.unique_fqdn_set_id",
        back_populates="unique_fqdn_set",
    )
    certificate_signeds = sa_orm_relationship(
        "CertificateSigned",
        primaryjoin="UniqueFQDNSet.id==CertificateSigned.unique_fqdn_set_id",
        back_populates="unique_fqdn_set",
    )
    to_domains = sa_orm_relationship(
        "UniqueFQDNSet2Domain",
        primaryjoin="UniqueFQDNSet.id==UniqueFQDNSet2Domain.unique_fqdn_set_id",
        back_populates="unique_fqdn_set",
    )
    queue_certificates = sa_orm_relationship(
        "QueueCertificate",
        primaryjoin="UniqueFQDNSet.id==QueueCertificate.unique_fqdn_set_id",
        back_populates="unique_fqdn_set",
    )
    queue_certificates__active = sa_orm_relationship(
        "QueueCertificate",
        primaryjoin=(
            "and_("
            "UniqueFQDNSet.id==QueueCertificate.unique_fqdn_set_id,"
            "QueueCertificate.is_active==True"
            ")"
        ),
        overlaps="queue_certificates",
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
    def domains(self):
        return [to_d.domain for to_d in self.to_domains]

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
    def domain_objects(self):
        domain_objects = {
            to_d.domain.domain_name.lower(): to_d.domain for to_d in self.to_domains
        }
        return domain_objects

    @property
    def as_json(self):
        return {
            "id": self.id,
            "timestamp_created": self.timestamp_created_isoformat,
            "count_domains": self.count_domains,
            "domains_as_list": self.domains_as_list,
        }


# ==============================================================================


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


__all__ = (
    "AcmeAccount",
    "AcmeAccountKey",
    "AcmeAccountProvider",
    "AcmeAuthorization",
    "AcmeChallenge",
    "AcmeChallengeCompeting",
    "AcmeChallengeCompeting2AcmeChallenge",
    "AcmeChallengePoll",
    "AcmeChallengeUnknownPoll",
    "AcmeDnsServer",
    "AcmeDnsServerAccount",
    "AcmeEventLog",
    "AcmeOrder",
    "AcmeOrderSubmission",
    "AcmeOrder2AcmeAuthorization",
    "AcmeOrder2AcmeChallengeTypeSpecific",
    "AcmeOrderless",
    "CertificateCA",
    "CertificateCAChain",
    "CertificateCAPreference",
    "CertificateCAReconciliation",
    "CertificateRequest",
    "CertificateSigned",
    "CertificateSignedChain",
    "CoverageAssuranceEvent",
    "Domain",
    "DomainAutocert",
    "DomainBlocklisted",
    "OperationsEvent",
    "OperationsObjectEvent",
    "PrivateKey",
    "QueueCertificate",
    "QueueDomain",
    "RemoteIpAddress",
    "RootStore",
    "RootStoreVersion",
    "RootStoreVersion_2_CertificateCA",
    "UniqueFQDNSet",
    "UniqueFQDNSet2Domain",
)
