"""
Style note:

    as_json should be:
        id          # id
        ObjectA     # CameCaseObjects, alphabetical
        ObjectB
        # - -       # comment line
        a           # attributes, alphabetical
        b
        c
        d
"""

# stdlib
import datetime
import json
import logging
import os
import pprint
from typing import Dict
from typing import List
from typing import Optional
from typing import TYPE_CHECKING
from typing import Union

# pypi
from pyramid.decorator import reify
import sqlalchemy as sa
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship as sa_orm_relationship
from sqlalchemy.orm.session import Session as sa_Session

# from sqlalchemy import inspect as sa_inspect

# local
from .mixins import _Mixin_AcmeAccount_Effective
from .mixins import _Mixin_Hex_Pretty
from .mixins import _Mixin_Timestamps_Pretty
from .. import utils as model_utils
from ..meta import Base
from ..utils import TZDateTime

if TYPE_CHECKING:
    from ...lib.context import ApiContext


log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

# ==============================================================================


class AcmeAccount(Base, _Mixin_Timestamps_Pretty):
    """
    Represents a registered account with the LetsEncrypt Service.
    This is used for authentication to the LE API, it is not tied to any certificates.

    A `PrivateKey` can be locked to an `AcmeAccount` via `PrivateKey.acme_account_id__owner`
    """

    __tablename__ = "acme_account"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    contact: Mapped[Optional[str]] = mapped_column(sa.Unicode(255), nullable=True)
    name: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(64), nullable=True, unique=True
    )
    account_url: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(255), nullable=True, unique=True
    )
    count_acme_orders: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0
    )
    count_certificate_signeds: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0
    )
    timestamp_last_certificate_request: Mapped[Optional[datetime.datetime]] = (
        mapped_column(TZDateTime(timezone=True), nullable=True)
    )
    timestamp_last_certificate_issue: Mapped[Optional[datetime.datetime]] = (
        mapped_column(TZDateTime(timezone=True), nullable=True)
    )
    timestamp_last_authenticated: Mapped[Optional[datetime.datetime]] = mapped_column(
        TZDateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    is_render_in_selects: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=True, default=None
    )
    acme_server_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_server.id"), nullable=False
    )
    private_key_technology_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see .utils.KeyTechnology

    order_default_private_key_technology_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see .utils.KeyTechnology
    order_default_private_key_cycle_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see .utils.PrivateKeyCycle
    order_default_acme_profile: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(64), nullable=True
    )
    timestamp_deactivated: Mapped[Optional[datetime.datetime]] = mapped_column(
        TZDateTime(timezone=True), nullable=True
    )
    operations_event_id__created: Mapped[int] = mapped_column(
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
    acme_server = sa_orm_relationship(
        "AcmeServer",
        primaryjoin=("AcmeAccount.acme_server_id==AcmeServer.id"),
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
    enrollment_factorys__primary = sa_orm_relationship(
        "EnrollmentFactory",
        primaryjoin="AcmeAccount.id==EnrollmentFactory.acme_account_id__primary",
        back_populates="acme_account__primary",
    )
    enrollment_factorys__backup = sa_orm_relationship(
        "EnrollmentFactory",
        primaryjoin="AcmeAccount.id==EnrollmentFactory.acme_account_id__backup",
        back_populates="acme_account__backup",
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
    renewal_configurations__primary = sa_orm_relationship(
        "RenewalConfiguration",
        primaryjoin="AcmeAccount.id==RenewalConfiguration.acme_account_id__primary",
        back_populates="acme_account__primary",
    )
    renewal_configurations__backup = sa_orm_relationship(
        "RenewalConfiguration",
        primaryjoin="AcmeAccount.id==RenewalConfiguration.acme_account_id__backup",
        back_populates="acme_account__backup",
    )
    system_configurations__primary = sa_orm_relationship(
        "SystemConfiguration",
        primaryjoin="AcmeAccount.id==SystemConfiguration.acme_account_id__primary",
        back_populates="acme_account__primary",
    )
    system_configurations__backup = sa_orm_relationship(
        "SystemConfiguration",
        primaryjoin="AcmeAccount.id==SystemConfiguration.acme_account_id__backup",
        back_populates="acme_account__backup",
    )
    tos = sa_orm_relationship(
        "AcmeAccount_2_TermsOfService",
        primaryjoin="and_(AcmeAccount.id==AcmeAccount_2_TermsOfService.acme_account_id, AcmeAccount_2_TermsOfService.is_active.is_(True))",
        uselist=False,
        back_populates="acme_account",
        viewonly=True,  # the `AcmeAccount_2_TermsOfService.is_active` join complicates things
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def displayable(self) -> str:
        return "[%s] %s (%s) @ %s" % (
            self.id,
            self.name or "",
            self.contact,
            self.acme_server.name,
        )

    @property
    def is_usable(self) -> bool:
        """check the AcmeAccount and AcmeAccountKey are both active"""
        if self.is_active:
            # `.acme_account_key` is joined on `is_active`
            if self.acme_account_key:
                return True
        return False

    @property
    def is_can_authenticate(self) -> bool:
        if self.acme_server.protocol == "acme-v2":
            return True
        return False

    @property
    def is_can_deactivate(self) -> bool:
        if self.system_configurations__primary or self.system_configurations__backup:
            return False
        if self.is_active:
            return True
        return False

    @property
    def is_can_unset_active(self) -> bool:
        if self.system_configurations__primary or self.system_configurations__backup:
            return False
        if self.is_active:
            return True
        return False

    @property
    def is_can_key_change(self) -> bool:
        if self.is_active:
            return True
        return False

    @reify
    def key_spki_search(self) -> str:
        if not self.acme_account_key:
            return "type=error&error=missing-acme-account-key"
        return self.acme_account_key.key_spki_search

    @reify
    def key_pem_sample(self) -> str:
        if not self.acme_account_key:
            return ""
        return self.acme_account_key.key_pem_sample

    @property
    def private_key_technology(self) -> str:
        return model_utils.KeyTechnology.as_string(self.private_key_technology_id)

    @property
    def order_default_private_key_cycle(self) -> str:
        return model_utils.PrivateKeyCycle.as_string(
            self.order_default_private_key_cycle_id
        )

    @property
    def order_default_private_key_technology(self) -> str:
        return model_utils.KeyTechnology.as_string(
            self.order_default_private_key_technology_id
        )

    @property
    def terms_of_service(self) -> str:
        if not self.tos:
            return "<no TOS recorded>"
        return self.tos.terms_of_service

    @property
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            "AcmeAccountKey": (
                self.acme_account_key.as_json if self.acme_account_key else None
            ),
            # - -
            "is_active": True if self.is_active else False,
            "is_deactivated": self.timestamp_deactivated or False,
            "acme_server_id": self.acme_server_id,
            "acme_server_name": self.acme_server.name,
            "acme_server_url": self.acme_server.url,
            "acme_server_protocol": self.acme_server.protocol,
            "private_key_technology": self.private_key_technology,
            "order_default_private_key_cycle": self.order_default_private_key_cycle,
            "order_default_private_key_technology": self.order_default_private_key_technology,
            "contact": self.contact,
            "account_url": self.account_url,
            "name": self.name,
            "terms_of_service": self.terms_of_service,
        }

    @property
    def as_json_minimal(self) -> Dict:
        rval = self.as_json
        rval["AcmeAccountKey"] = (
            self.acme_account_key.as_json_minimal if self.acme_account_key else None
        )
        return rval

    @property
    def as_json_minimal_extended(self) -> Dict:
        rval = {
            "id": self.id,
            "account_url": self.account_url,
        }
        rval["AcmeAccountKey"] = (
            self.acme_account_key.as_json_minimal if self.acme_account_key else None
        )
        rval["AcmeServer"] = self.acme_server.as_json_minimal
        return rval

    @property
    def as_json_labels(self) -> Dict:
        rval = {
            "id": self.id,
            "label": self.displayable,
        }
        return rval


class AcmeAccount_2_TermsOfService(Base, _Mixin_Timestamps_Pretty):
    __tablename__ = "acme_account_2_terms_of_service"
    __table_args__ = (
        sa.Index(
            "uidx_acme_account_2_terms_of_service",
            "acme_account_id",
            "is_active",
            unique=True,
        ),
    )

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    acme_account_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_account.id"), nullable=False
    )
    is_active: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=True
    )  # allow NULL because of the index
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    terms_of_service: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(255), nullable=True
    )

    acme_account = sa_orm_relationship(
        "AcmeAccount",
        primaryjoin="AcmeAccount.id==AcmeAccount_2_TermsOfService.acme_account_id",
        uselist=False,
        back_populates="tos",
    )


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

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    acme_account_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_account.id"), nullable=False
    )
    is_active: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=None
    )

    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    timestamp_deactivated: Mapped[Optional[datetime.datetime]] = mapped_column(
        TZDateTime(timezone=True), nullable=True
    )
    key_technology_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see .utils.KeyTechnology
    key_deactivation_type_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=True
    )  # see .utils.KeyDeactivationType

    key_pem: Mapped[str] = mapped_column(sa.Text, nullable=False)
    key_pem_md5: Mapped[str] = mapped_column(sa.Unicode(32), nullable=False)
    spki_sha256: Mapped[str] = mapped_column(sa.Unicode(64), nullable=False)

    operations_event_id__created: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )

    acme_account_key_source_id: Mapped[int] = mapped_column(
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
    def acme_account_key_source(self) -> str:
        return model_utils.AcmeAccountKeySource.as_string(
            self.acme_account_key_source_id
        )

    @reify
    def key_pem_sample(self) -> str:
        # strip the pem, because the last line is whitespace after
        # "-----END RSA PRIVATE KEY-----"
        if not self.key_pem:
            return ""
        pem_lines = self.key_pem.strip().split("\n")
        return "%s...%s" % (pem_lines[1][0:5], pem_lines[-2][-5:])

    @property
    def key_technology(self) -> Optional[str]:
        if self.key_technology_id is None:
            return None
        return model_utils.KeyTechnology.as_string(self.key_technology_id)

    @reify
    def key_spki_search(self) -> str:
        return (
            "type=spki&spki=%s&source=acme_account_key&acme_account_key.id=%s&acme_account.id=%s"
            % (
                self.spki_sha256,
                self.id,
                self.acme_account_id,
            )
        )

    @property
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            # - -
            "is_active": self.is_active,
            "key_pem": self.key_pem,
            "key_pem_md5": self.key_pem_md5,
            "spki_sha256": self.spki_sha256,
        }

    @property
    def as_json_minimal(self) -> Dict:
        rval = self.as_json
        del rval["key_pem"]
        return rval


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
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    authorization_url: Mapped[str] = mapped_column(
        sa.Unicode(255), nullable=False, unique=True
    )
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    acme_status_authorization_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # Acme_Status_Authorization
    domain_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("domain.id"), nullable=True
    )
    timestamp_expires: Mapped[Optional[datetime.datetime]] = mapped_column(
        TZDateTime(timezone=True), nullable=True
    )
    timestamp_updated: Mapped[Optional[datetime.datetime]] = mapped_column(
        TZDateTime(timezone=True), nullable=True
    )
    timestamp_deactivated: Mapped[Optional[datetime.datetime]] = mapped_column(
        TZDateTime(timezone=True), nullable=True
    )
    wildcard: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=None
    )

    # the RFC does not explicitly tie an AcmeAuthorization to a single AcmeOrder
    # this is only used to easily grab an AcmeAccount
    acme_order_id__created: Mapped[int] = mapped_column(
        sa.Integer,
        sa.ForeignKey("acme_order.id", use_alter=True),
        nullable=False,
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

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
            ")" % model_utils.AcmeChallengeType.http_01
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
            ")" % model_utils.AcmeChallengeType.dns_01
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
            ")" % model_utils.AcmeChallengeType.tls_alpn_01
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
    domain = sa_orm_relationship(
        "Domain",
        primaryjoin="AcmeAuthorization.domain_id==Domain.id",
        uselist=False,
        back_populates="acme_authorizations",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def acme_status_authorization(self) -> str:
        return model_utils.Acme_Status_Authorization.as_string(
            self.acme_status_authorization_id
        )

    @property
    def is_acme_server_pending(self) -> bool:
        if (
            self.acme_status_authorization
            in model_utils.Acme_Status_Authorization.OPTIONS_POSSIBLY_PENDING
        ):
            return True
        return False

    @property
    def is_can_acme_server_deactivate(self) -> bool:
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
    def is_can_acme_server_process(self) -> bool:
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
    def is_can_acme_server_trigger(self) -> bool:
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
    def is_can_acme_server_sync(self) -> bool:
        # ???: is there a better way to test this?
        if not self.authorization_url:
            return False
        return True

    @property
    def as_json(self) -> Dict:
        dbSession = sa_Session.object_session(self)
        if TYPE_CHECKING:
            assert dbSession
        request = dbSession.info.get("request")
        admin_url = request.admin_url if request else ""

        return {
            "id": self.id,
            "Domain": (
                {
                    "id": self.domain_id,
                    "domain_name": self.domain.domain_name,
                }
                if self.domain_id
                else None
            ),
            # - -
            "acme_status_authorization": self.acme_status_authorization,
            "acme_challenge_http_01_id": (
                self.acme_challenge_http_01.id if self.acme_challenge_http_01 else None
            ),
            "acme_challenge_dns_01_id": (
                self.acme_challenge_dns_01.id if self.acme_challenge_dns_01 else None
            ),
            "url_acme_server_sync": (
                "%s/acme-authorization/%s/acme-server/sync.json" % (admin_url, self.id)
                if self.is_can_acme_server_sync
                else None
            ),
            "url_acme_server_deactivate": (
                "%s/acme-authorization/%s/acme-server/deactivate.json"
                % (admin_url, self.id)
                if self.is_can_acme_server_deactivate
                else None
            ),
        }


# ==============================================================================


class AcmeAuthorizationPotential(Base, _Mixin_Timestamps_Pretty):
    """
    This class is used to pre-block on a domain to handle race conditions

    """

    __table_args__ = (
        sa.UniqueConstraint(
            "acme_order_id",
            "domain_id",
            name="acme_authorization_potential_uidx",
        ),
    )

    __tablename__ = "acme_authorization_potential"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    acme_order_id: Mapped[int] = mapped_column(
        sa.Integer,
        sa.ForeignKey("acme_order.id", use_alter=True),
        nullable=False,
    )
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    domain_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("domain.id"), nullable=True
    )
    acme_challenge_type_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # `model_utils.AcmeChallengeType`
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    # this is used to easily grab an AcmeAccount, and also deactivate orders on backref
    acme_order = sa_orm_relationship(
        "AcmeOrder",
        primaryjoin="AcmeAuthorizationPotential.acme_order_id==AcmeOrder.id",
        uselist=False,
        back_populates="acme_authorization_potentials",
    )
    domain = sa_orm_relationship(
        "Domain",
        primaryjoin="AcmeAuthorizationPotential.domain_id==Domain.id",
        uselist=False,
        back_populates="acme_authorization_potentials",
    )

    @property
    def acme_challenge_type(self) -> Optional[str]:
        if self.acme_challenge_type_id:
            return model_utils.AcmeChallengeType.as_string(self.acme_challenge_type_id)
        return None

    @property
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            # - -
            "acme_order_id": self.acme_order_id,
            "domain_id": self.domain_id,
            "acme_challenge_type": self.acme_challenge_type,
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

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)

    # our challenge will either be from:
    # 1) an `AcmeOrder`->`AcmeAuthorization`
    acme_authorization_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer,
        sa.ForeignKey("acme_authorization.id"),
        nullable=False,
    )

    # legacy `AcmeOrderless` required a domain;
    # duplicating this is fine and useful
    domain_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("domain.id"), nullable=False
    )

    # in all situations, we need to track these:
    acme_challenge_type_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # `model_utils.AcmeChallengeType`
    acme_status_challenge_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # Acme_Status_Challenge

    # this is on the acme server
    challenge_url: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(255), nullable=False, unique=True
    )

    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    timestamp_updated: Mapped[Optional[datetime.datetime]] = mapped_column(
        TZDateTime(timezone=True), nullable=True
    )

    token: Mapped[Optional[str]] = mapped_column(sa.Unicode(255), nullable=False)
    # token_clean = re.sub(r"[^A-Za-z0-9_\-]", "_", dbAcmeAuthorization.acme_challenge_http_01.token)
    # keyauthorization = "{0}.{1}".format(token_clean, accountkey_thumbprint)
    keyauthorization: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(255), nullable=True
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    #     acme_event_log = sa_orm_relationship(
    #         "AcmeEventLog",
    #         primaryjoin="AcmeChallenge.acme_event_log_id==AcmeEventLog.id",
    #         uselist=False,
    #         back_populates="acme_challenges",
    #     )

    acme_authorization = sa_orm_relationship(
        "AcmeAuthorization",
        primaryjoin="AcmeChallenge.acme_authorization_id==AcmeAuthorization.id",
        uselist=False,
        back_populates="acme_challenges",
        overlaps="acme_challenge_dns_01,acme_challenge_http_01,acme_challenge_tls_alpn_01",
    )
    acme_challenge_polls = sa_orm_relationship(
        "AcmeChallengePoll",
        primaryjoin="AcmeChallenge.id==AcmeChallengePoll.acme_challenge_id",
        uselist=True,
        back_populates="acme_challenge",
    )
    domain = sa_orm_relationship(
        "Domain",
        primaryjoin="AcmeChallenge.domain_id==Domain.id",
        uselist=False,
        back_populates="acme_challenges",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def acme_challenge_type(self) -> Optional[str]:
        if self.acme_challenge_type_id:
            return model_utils.AcmeChallengeType.as_string(self.acme_challenge_type_id)
        return None

    @property
    def acme_status_challenge(self) -> str:
        return model_utils.Acme_Status_Challenge.as_string(
            self.acme_status_challenge_id
        )

    @property
    def domain_name(self) -> str:
        return self.domain.domain_name

    @property
    def challenge_instructions_short(self) -> str:
        if self.acme_challenge_type == "http-01":
            return "PeterSSLers is configured to answer this challenge."
        elif self.acme_challenge_type == "dns-01":
            return "This challenge may require DNS configuration."
        elif self.acme_challenge_type == "tls-alpn-01":
            return "`TLS-ALPN-01` challenges are not currently supported."
        return "PeterSSLers can not answer this challenge."

    @property
    def is_can_acme_server_sync(self) -> bool:
        if not self.challenge_url:
            return False
        if not self.acme_authorization_id:
            # auth's order_id needed for the AcmeAccount
            return False
        return True

    @property
    def is_can_acme_server_trigger(self) -> bool:
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
        if self.acme_challenge_type == "http-01":
            return True
        elif self.acme_challenge_type == "dns-01":
            if self.domain.acme_dns_server_account__active:
                return True
        return False

    @property
    def is_configured_to_answer(self) -> bool:
        if not self.is_can_acme_server_trigger:
            return False
        if self.acme_challenge_type == "http-01":
            return True
        elif self.acme_challenge_type == "dns-01":
            if self.domain.acme_dns_server_account__active:
                return True
        return False

    @property
    def as_json(self) -> Dict:
        dbSession = sa_Session.object_session(self)
        if TYPE_CHECKING:
            assert dbSession
        request = dbSession.info.get("request")
        admin_url = request.admin_url if request else ""

        return {
            "id": self.id,
            "Domain": {
                "id": self.domain_id,
                "domain_name": self.domain.domain_name,
            },
            # - -
            "acme_challenge_type": self.acme_challenge_type,
            "acme_status_challenge": self.acme_status_challenge,
            "keyauthorization": self.keyauthorization,
            "timestamp_created": self.timestamp_created_isoformat,
            "timestamp_updated": self.timestamp_updated_isoformat,
            "token": self.token,
            "url_acme_server_sync": (
                "%s/acme-challenge/%s/acme-server/sync.json" % (admin_url, self.id)
                if self.is_can_acme_server_sync
                else None
            ),
            "url_acme_server_trigger": (
                "%s/acme-challenge/%s/acme-server/trigger.json" % (admin_url, self.id)
                if self.is_can_acme_server_trigger
                else None
            ),
            # "acme_event_log_id": self.acme_event_log_id,
        }


# ==============================================================================


class AcmeChallengeCompeting(Base, _Mixin_Timestamps_Pretty):
    # This is for tracking an EdgeCase
    __tablename__ = "acme_challenge_competing"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    domain_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("domain.id"), nullable=True
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_challenge_competing_2_acme_challenge = sa_orm_relationship(
        "AcmeChallengeCompeting2AcmeChallenge",
        primaryjoin=(
            "AcmeChallengeCompeting.id==AcmeChallengeCompeting2AcmeChallenge.acme_challenge_competing_id"
        ),
        uselist=True,
        back_populates="acme_challenge_competing",
    )
    domain = sa_orm_relationship(
        "Domain",
        primaryjoin="AcmeChallengeCompeting.domain_id==Domain.id",
        uselist=False,
    )


class AcmeChallengeCompeting2AcmeChallenge(Base, _Mixin_Timestamps_Pretty):
    __tablename__ = "acme_challenge_competing_2_acme_challenge"

    acme_challenge_competing_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_challenge_competing.id"), primary_key=True
    )
    acme_challenge_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_challenge.id"), primary_key=True
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_challenge = sa_orm_relationship(
        "AcmeChallenge",
        primaryjoin=(
            "AcmeChallengeCompeting2AcmeChallenge.acme_challenge_id==AcmeChallenge.id"
        ),
        uselist=False,
    )
    acme_challenge_competing = sa_orm_relationship(
        "AcmeChallengeCompeting",
        primaryjoin=(
            "AcmeChallengeCompeting2AcmeChallenge.acme_challenge_competing_id==AcmeChallengeCompeting.id"
        ),
        uselist=False,
        back_populates="acme_challenge_competing_2_acme_challenge",
    )


# ==============================================================================


class AcmeChallengePoll(Base, _Mixin_Timestamps_Pretty):
    """
    log ACME Challenge polls
    """

    __tablename__ = "acme_challenge_poll"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    acme_challenge_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_challenge.id"), nullable=False
    )
    timestamp_polled: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    remote_ip_address_id: Mapped[int] = mapped_column(
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
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            "AcmeChallenge": self.acme_challenge.as_json,
            # - -
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

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    challenge: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    timestamp_polled: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    remote_ip_address_id: Mapped[int] = mapped_column(
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
    def as_json(self) -> Dict:
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
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    is_global_default: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=None
    )
    api_url: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    domain: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    operations_event_id__created: Mapped[int] = mapped_column(
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
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            "api_url": self.api_url,
            "domain": self.domain,
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
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    acme_dns_server_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_dns_server.id"), nullable=False
    )
    domain_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("domain.id"), nullable=False
    )
    is_active: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=True
    )  # allow NULL for constraint to work
    username: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    password: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    fulldomain: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    subdomain: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    allowfrom: Mapped[Optional[str]] = mapped_column(sa.Unicode(255), nullable=True)
    operations_event_id__created: Mapped[int] = mapped_column(
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
    def password_sample(self) -> str:
        return "%s...%s" % (self.password[:5], self.password[-5:])

    @property
    def cname_source(self) -> str:
        #  note: the cname source should end with a .
        return self.domain.acme_challenge_domain_name

    @property
    def cname_target(self) -> str:
        #  note: the cname target should end with a .
        return "%s.%s." % (self.subdomain, self.acme_dns_server.domain)

    @property
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            "AcmeDnsServer": self.acme_dns_server.as_json,
            "Domain": self.domain.as_json,
            # - -
            "timestamp_created": self.timestamp_created_isoformat,
            "username": self.username,
            "password": self.password,
            "fulldomain": self.fulldomain,
            "subdomain": self.subdomain,
            "allowfrom": json.loads(self.allowfrom) if self.allowfrom else [],
            # - -
            "cname_source": self.cname_source,
            "cname_target": self.cname_target,
        }

    @property
    def pyacmedns_dict(self) -> Dict:
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
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    timestamp_event: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    acme_event_id: Mapped[int] = mapped_column(sa.Integer, nullable=False)  # AcmeEvent
    acme_account_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_account.id", use_alter=True), nullable=True
    )
    acme_authorization_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer,
        sa.ForeignKey("acme_authorization.id", use_alter=True),
        nullable=True,
    )
    acme_challenge_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_challenge.id", use_alter=True), nullable=True
    )
    acme_order_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_order.id", use_alter=True), nullable=True
    )
    certificate_request_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer,
        sa.ForeignKey("certificate_request.id", use_alter=True),
        nullable=True,
    )
    certificate_signed_id: Mapped[Optional[int]] = mapped_column(
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
    def acme_event(self) -> Optional[str]:
        if self.acme_event_id:
            return model_utils.AcmeEvent.as_string(self.acme_event_id)
        return None

    @property
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            # - -
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

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    is_processing: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=True
    )  # see notes above
    # this should always be true; maybe one day it will be a toggle
    is_save_alternate_chains: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=True
    )
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    acme_order_type_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see: `.utils.AcmeOrderType`
    acme_status_order_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0
    )  # see: `.utils.Acme_Status_Order`; 0 is `*discovered*` an internal marker
    acme_order_processing_strategy_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see: `utils.AcmeOrder_ProcessingStrategy`
    acme_order_processing_status_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see: `utils.AcmeOrder_ProcessingStatus`
    # utils.CertificateType.[RAW_IMPORTED, MANAGED_PRIMARY, MANAGED_BACKUP]
    # AcmeOrder.certificate_type_id MUST never change; CertificateSigned.certificate_type_id MAY change
    certificate_type_id: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    order_url: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(255), nullable=True, unique=True
    )
    finalize_url: Mapped[Optional[str]] = mapped_column(sa.Unicode(255), nullable=True)
    certificate_url: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(255), nullable=True
    )
    timestamp_expires: Mapped[Optional[datetime.datetime]] = mapped_column(
        TZDateTime(timezone=True), nullable=True
    )
    timestamp_updated: Mapped[Optional[datetime.datetime]] = mapped_column(
        TZDateTime(timezone=True), nullable=True
    )
    private_key_strategy_id__requested: Mapped[Optional[int]] = mapped_column(
        sa.Integer, nullable=True
    )  # see .utils.PrivateKeyStrategy; how are we specifying the private key? NOW or deferred?
    private_key_strategy_id__final: Mapped[Optional[int]] = mapped_column(
        sa.Integer, nullable=True
    )  # see .utils.PrivateKeyStrategy; how did we end up choosing a private key?
    acme_event_log_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_event_log.id"), nullable=False
    )  # When was this created?  AcmeEvent['v2|newOrder']

    timestamp_finalized: Mapped[Optional[datetime.datetime]] = mapped_column(
        TZDateTime(timezone=True), nullable=True
    )
    acme_account_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_account.id"), nullable=False
    )
    certificate_request_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer,
        sa.ForeignKey("certificate_request.id", use_alter=True),
        nullable=True,
    )
    certificate_signed_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer,
        sa.ForeignKey("certificate_signed.id", use_alter=True),
        nullable=True,
    )
    private_key_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("private_key.id", use_alter=True), nullable=False
    )
    private_key_cycle_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see .utils.PrivateKeyCycle
    renewal_configuration_id: Mapped[int] = mapped_column(
        sa.Integer,
        sa.ForeignKey("renewal_configuration.id", use_alter=True),
        nullable=True,
    )
    unique_fqdn_set_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("unique_fqdn_set.id"), nullable=False
    )
    uniquely_challenged_fqdn_set_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("uniquely_challenged_fqdn_set.id"), nullable=False
    )
    private_key_deferred_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, nullable=False
    )
    note: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True)
    profile: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True)
    replaces__requested: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True)
    replaces: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True)
    certificate_signed_id__replaces: Mapped[Optional[int]] = mapped_column(
        sa.Integer,
        sa.ForeignKey("certificate_signed.id"),
        nullable=True,
    )
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    acme_order_id__retry_of: Mapped[Optional[int]] = mapped_column(
        sa.Integer,
        sa.ForeignKey("acme_order.id"),
        nullable=True,
    )
    acme_order_id__renewal_of: Mapped[Optional[int]] = mapped_column(
        sa.Integer,
        sa.ForeignKey("acme_order.id"),
        nullable=True,
    )
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_account = sa_orm_relationship(
        "AcmeAccount",
        primaryjoin="AcmeOrder.acme_account_id==AcmeAccount.id",
        uselist=False,
        back_populates="acme_orders",
    )
    acme_authorization_potentials = sa_orm_relationship(
        "AcmeAuthorizationPotential",
        primaryjoin="AcmeOrder.id==AcmeAuthorizationPotential.acme_order_id",
        back_populates="acme_order",
    )
    acme_order_submissions = sa_orm_relationship(
        "AcmeOrderSubmission",
        primaryjoin="AcmeOrder.id==AcmeOrderSubmission.acme_order_id",
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
    certificate_signed__replaces = sa_orm_relationship(
        "CertificateSigned",
        primaryjoin="AcmeOrder.certificate_signed_id__replaces==CertificateSigned.id",
        uselist=False,
    )
    operations_object_events = sa_orm_relationship(
        "OperationsObjectEvent",
        primaryjoin="AcmeOrder.id==OperationsObjectEvent.acme_order_id",
        back_populates="acme_order",
    )
    private_key = sa_orm_relationship(
        "PrivateKey",
        primaryjoin="AcmeOrder.private_key_id==PrivateKey.id",
        back_populates="acme_orders",
        uselist=False,
    )
    renewal_configuration = sa.orm.relationship(
        "RenewalConfiguration",
        primaryjoin="AcmeOrder.renewal_configuration_id==RenewalConfiguration.id",
        back_populates="acme_orders",
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
    uniquely_challenged_fqdn_set = sa_orm_relationship(
        "UniquelyChallengedFQDNSet",
        primaryjoin="AcmeOrder.uniquely_challenged_fqdn_set_id==UniquelyChallengedFQDNSet.id",
        uselist=False,
        back_populates="acme_orders",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def acme_status_order(self) -> str:
        return model_utils.Acme_Status_Order.as_string(self.acme_status_order_id)

    @reify
    def acme_order_type(self) -> str:
        return model_utils.AcmeOrderType.as_string(self.acme_order_type_id)

    @property
    def acme_order_processing_strategy(self) -> str:
        return model_utils.AcmeOrder_ProcessingStrategy.as_string(
            self.acme_order_processing_strategy_id
        )

    @reify
    def acme_order_processing_status(self) -> str:
        return model_utils.AcmeOrder_ProcessingStatus.as_string(
            self.acme_order_processing_status_id
        )

    @property
    def acme_authorization_ids(self) -> List[int]:
        return [i.acme_authorization_id for i in self.to_acme_authorizations]

    @property
    def acme_authorizations(self) -> List["AcmeAuthorization"]:
        authorizations = []
        for _to_auth in self.to_acme_authorizations:
            authorizations.append(_to_auth.acme_authorization)
        return authorizations

    @reify
    def acme_process_steps(self) -> Dict:
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
                assert isinstance(rval["authorizations"], list)
                rval["authorizations"].append(_auth_tuple)
                if _pending:
                    assert isinstance(rval["authorizations_remaining"], int)
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
    def acme_authorizations_pending(self) -> List["AcmeAuthorization"]:
        authorizations = []
        for _to_auth in self.to_acme_authorizations:
            if (
                _to_auth.acme_authorization.acme_status_authorization
                in model_utils.Acme_Status_Authorization.OPTIONS_POSSIBLY_PENDING
            ):
                authorizations.append(_to_auth.acme_authorization)
        return authorizations

    @property
    def authorizations_can_deactivate(self) -> List["AcmeAuthorization"]:
        authorizations = []
        for _to_auth in self.to_acme_authorizations:
            if (
                _to_auth.acme_authorization.acme_status_authorization
                in model_utils.Acme_Status_Authorization.OPTIONS_DEACTIVATE
            ):
                authorizations.append(_to_auth.acme_authorization)
        return authorizations

    @property
    def certificate_type(self) -> str:
        return model_utils.CertificateType.as_string(self.certificate_type_id)

    @property
    def domains_as_list(self) -> List[str]:
        domain_names = [
            to_d.domain.domain_name.lower() for to_d in self.unique_fqdn_set.to_domains
        ]
        domain_names = list(set(domain_names))
        domain_names = sorted(domain_names)
        return domain_names

    @property
    def domains_challenged(self) -> model_utils.DomainsChallenged:
        return self.uniquely_challenged_fqdn_set.domains_challenged

    @property
    def is_can_acme_server_sync(self) -> bool:
        # note: is there a better test?
        if not self.order_url:
            return False
        if self.acme_status_order in model_utils.Acme_Status_Order.OPTIONS_X_ACME_SYNC:
            return False
        return True

    @property
    def is_can_acme_server_deactivate_authorizations(self) -> bool:
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
    def is_can_acme_server_download_certificate(self) -> bool:
        """
        can we download a CertificateSigned from the AcmeServer?
        only works for VALID AcmeOrder if we do not have a CertificateSigned
        """
        if self.acme_status_order == "valid":
            if self.certificate_url:
                if not self.certificate_signed_id:
                    return True
        return False

    @property
    def is_can_acme_process(self) -> bool:
        # `process` will iterate authorizations and finalize
        if self.acme_status_order in model_utils.Acme_Status_Order.OPTIONS_PROCESS:
            return True
        return False

    @property
    def is_can_acme_finalize(self) -> bool:
        if self.acme_status_order in model_utils.Acme_Status_Order.OPTIONS_FINALIZE:
            return True
        return False

    @property
    def is_can_mark_invalid(self) -> bool:
        if (
            self.acme_status_order
            not in model_utils.Acme_Status_Order.OPTIONS_X_MARK_INVALID
        ):
            return True
        return False

    @property
    def is_can_retry(self) -> bool:
        if self.acme_status_order not in model_utils.Acme_Status_Order.OPTIONS_RETRY:
            return False
        return True

    @property
    def is_renewable_quick(self) -> bool:
        if self.renewal_configuration_id:
            return True
        return False

    @property
    def is_renewable_custom(self) -> bool:
        if self.renewal_configuration_id:
            return True
        return False

    @reify
    def private_key_deferred(self) -> str:
        return (
            model_utils.PrivateKeyDeferred.as_string(self.private_key_deferred_id)
            if self.private_key_deferred_id
            else ""
        )

    @reify
    def private_key_strategy__requested(self) -> str:
        return (
            model_utils.PrivateKeyStrategy.as_string(
                self.private_key_strategy_id__requested
            )
            if self.private_key_strategy_id__requested
            else ""
        )

    @reify
    def private_key_strategy__final(self) -> str:
        return (
            model_utils.PrivateKeyStrategy.as_string(
                self.private_key_strategy_id__final
            )
            if self.private_key_strategy_id__final
            else ""
        )

    @property
    def private_key_cycle(self) -> str:
        return model_utils.PrivateKeyCycle.as_string(self.private_key_cycle_id)

    @property
    def as_json(self) -> Dict:
        dbSession = sa_Session.object_session(self)
        if TYPE_CHECKING:
            assert dbSession
        request = dbSession.info.get("request")
        admin_url = request.admin_url if request else ""

        return {
            "id": self.id,
            "AcmeAccount": self.acme_account.as_json_minimal_extended,
            "PrivateKey": {
                "id": self.private_key_id,
                "key_pem_md5": (
                    self.private_key.key_pem_md5 if self.private_key_id else None
                ),
            },
            "RenewalConfiguration": self.renewal_configuration.as_json,
            # - -
            "acme_authorization_ids": self.acme_authorization_ids,
            "acme_status_order": self.acme_status_order,
            "acme_order_type": self.acme_order_type,
            "acme_order_processing_status": self.acme_order_processing_status,
            "acme_order_processing_strategy": self.acme_order_processing_strategy,
            "acme_process_steps": self.acme_process_steps,
            "certificate_request_id": self.certificate_request_id,
            "certificate_type": self.certificate_type,
            "certificate_signed_id": self.certificate_signed_id,
            "certificate_signed_id__replaces": self.certificate_signed_id__replaces,
            "domains_as_list": self.domains_as_list,
            "domains_challenged": self.domains_challenged,
            "finalize_url": self.finalize_url,
            "certificate_url": self.certificate_url,
            "is_processing": True if self.is_processing else False,
            "is_can_acme_process": self.is_can_acme_process,
            "is_can_mark_invalid": self.is_can_mark_invalid,
            "is_can_retry": self.is_can_retry,
            "is_renewable_custom": True if self.is_renewable_custom else False,
            "is_renewable_quick": True if self.is_renewable_quick else False,
            "is_can_acme_server_deactivate_authorizations": (
                True if self.is_can_acme_server_deactivate_authorizations else False
            ),
            "note": self.note,
            "order_url": self.order_url,
            "private_key_cycle": self.private_key_cycle,
            "private_key_strategy__requested": self.private_key_strategy__requested,
            "private_key_strategy__final": self.private_key_strategy__final,
            "profile": self.profile,
            "timestamp_created": self.timestamp_created_isoformat,
            "timestamp_expires": self.timestamp_expires_isoformat,
            "timestamp_finalized": self.timestamp_finalized_isoformat,
            "timestamp_updated": self.timestamp_updated_isoformat,
            "renewal_configuration_id": self.renewal_configuration_id,
            "replaces": self.replaces,
            "unique_fqdn_set_id": self.unique_fqdn_set_id,
            "uniquely_challenged_fqdn_set_id": self.uniquely_challenged_fqdn_set_id,
            "url_acme_server_sync": (
                "%s/acme-order/%s/acme-server/sync.json" % (admin_url, self.id)
                if self.is_can_acme_server_sync
                else None
            ),
            "url_acme_certificate_signed_download": (
                "%s/acme-order/%s/acme-server/download-certificate.json"
                % (admin_url, self.id)
                if self.is_can_acme_server_download_certificate
                else None
            ),
            "url_acme_process": (
                "%s/acme-order/%s/acme-process.json" % (admin_url, self.id)
                if self.is_can_acme_process
                else None
            ),
            "url_deactivate": (
                "%s/acme-order/%s/mark.json" % (admin_url, self.id)
                if self.is_processing
                else None
            ),
            "url_deactivate_authorizations": (
                "%s/acme-order/%s/acme-server/deactivate-authorizations.json"
                % (admin_url, self.id)
                if self.is_can_acme_server_deactivate_authorizations
                else None
            ),
        }


class AcmeOrderSubmission(Base):
    """
    Boulder (LetsEncrypt) may re-use the same AcmeOrder in certain situations.
    Usually this is to:
        * defend against buggy clients who submit multiple consecutive PENDING orders
        * turn an INVALID order for a given Account + Unique Set of Domains into "PENDING"
    """

    __tablename__ = "acme_order_submission"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    acme_order_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_order.id"), nullable=True
    )
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )

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
    consolidation with this data
        ``AcmeOrder2AcmeAuthorization``
            acme_order_id
            acme_authorization_id

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

    acme_order_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_order.id"), primary_key=True
    )
    acme_authorization_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_authorization.id"), primary_key=True
    )
    is_present_on_new_order: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=None
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


# ==============================================================================


class AcmeServer(Base, _Mixin_Timestamps_Pretty):
    """
    Represents an AcmeServer
    """

    __tablename__ = "acme_server"
    __table_args__ = (
        sa.CheckConstraint(
            "(protocol = 'acme-v2')",
            name="check_protocol",
        ),
        sa.Index(
            "uidx_acme_server_default",
            "is_default",
            unique=True,
        ),
    )

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    name: Mapped[str] = mapped_column(sa.Unicode(64), nullable=False, unique=True)
    directory: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False, unique=True)
    # the server is normalized from the `directory`
    # it is used to help figure out what server corresponds to an account
    server: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False, unique=True)
    is_default: Mapped[Optional[bool]] = mapped_column(  # legacy; unused
        sa.Boolean, nullable=True, default=None  # NONE for uidx
    )
    is_supports_ari__version: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(32), nullable=True, default=None
    )
    # LetsEncrypt now has unlimited pending autz
    is_unlimited_pending_authz: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=None
    )
    is_enabled: Mapped[Optional[bool]] = mapped_column(  # legacy; unused
        sa.Boolean, nullable=False, default=True
    )
    protocol: Mapped[str] = mapped_column(sa.Unicode(32), nullable=False)
    server_ca_cert_bundle: Mapped[Optional[str]] = mapped_column(
        sa.Text, nullable=True, default=None
    )
    profiles: Mapped[Optional[str]] = mapped_column(
        sa.Text, nullable=True, default=None
    )
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_accounts = sa_orm_relationship(
        "AcmeAccount",
        primaryjoin=("AcmeServer.id==AcmeAccount.acme_server_id"),
        order_by="AcmeAccount.id.desc()",
        uselist=True,
        back_populates="acme_server",
    )
    operations_object_events = sa_orm_relationship(
        "OperationsObjectEvent",
        primaryjoin="AcmeServer.id==OperationsObjectEvent.acme_server_id",
        back_populates="acme_server",
    )
    directory_latest = sa_orm_relationship(
        "AcmeServerConfiguration",
        primaryjoin=(
            "and_("
            "AcmeServer.id==AcmeServerConfiguration.acme_server_id,"
            "AcmeServerConfiguration.is_active.is_(True)"
            ")"
        ),
        uselist=False,
        viewonly=True,  # the `AcmeServerConfiguration.is_active` join complicates things
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def is_supports_ari(self) -> bool:
        return bool(self.is_supports_ari__version)

    def local_ca_bundle(
        self,
        ctx: "ApiContext",
        force_refresh: bool = False,
    ) -> Optional[str]:
        """
        requests may need this
        """
        if not self.server_ca_cert_bundle:
            return None

        data_dir: str
        if ctx.application_settings:
            data_dir = ctx.application_settings["data_dir"]
        else:
            request = ctx.dbSession.info.get("request")
            assert request
            data_dir = request.api_context.application_settings["data_dir"]

        assert ctx.config_uri
        _config_uri = ctx.config_uri
        config_uri = _config_uri.split("/")[-1]
        config_uri = config_uri.replace(".", "-")

        bundle_dir = "%s/_ACME_SERVER_BUNDLE" % data_dir
        if not os.path.exists(bundle_dir):
            os.mkdir(bundle_dir)

        bundle_file = "%s/%s-%s.pem" % (bundle_dir, config_uri, self.id)
        if not os.path.exists(bundle_file) or force_refresh:
            with open(bundle_file, "w") as fh:
                fh.write(self.server_ca_cert_bundle)

        return bundle_file

    @property
    def profiles_list(self) -> List[str]:
        if not self.profiles:
            return []
        return self.profiles.split(",")

    @property
    def url(self) -> str:
        return self.directory or ""

    @property
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            # - -
            "directory": self.directory,
            "directory_latest": (
                self.directory_latest.as_json_minimal if self.directory_latest else None
            ),
            # "is_default": self.is_default or False,    # legacy; unused
            # "is_enabled": self.is_enabled or False,    # legacy; unused
            "is_supports_ari__version": self.is_supports_ari__version,
            "is_unlimited_pending_authz": self.is_unlimited_pending_authz,
            "name": self.name,
            "profiles": self.profiles_list,
            "protocol": self.protocol,
            "server_ca_cert_bundle": self.server_ca_cert_bundle,
            "timestamp_created": self.timestamp_created_isoformat,
        }

    @property
    def as_json_minimal(self) -> Dict:
        return {
            "id": self.id,
            # - -
            "directory": self.directory,
        }


class AcmeServerConfiguration(Base, _Mixin_Timestamps_Pretty):
    __tablename__ = "acme_server_configuration"
    __table_args__ = (
        sa.Index(
            "uidx_acme_server_configuration",
            "acme_server_id",
            "is_active",
            unique=True,
        ),
    )

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    acme_server_id: Mapped[int] = mapped_column(
        sa.Integer,
        sa.ForeignKey("acme_server.id", use_alter=True),
        nullable=False,
    )
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    is_active: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=True
    )  # allow NULL because of the index
    directory: Mapped[str] = mapped_column(sa.Text, nullable=False)

    @property
    def directory_pretty(self):
        if not self.directory:
            return ""
        d_json = json.loads(self.directory)
        return pprint.pformat(d_json)

    @property
    def as_json_minimal(self):
        return {
            "timestamp_created": self.timestamp_created_isoformat,
            "directory": self.directory,
        }


# ==============================================================================


class AriCheck(Base, _Mixin_Timestamps_Pretty):
    __tablename__ = "ari_check"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    certificate_signed_id: Mapped[int] = mapped_column(
        sa.Integer,
        sa.ForeignKey("certificate_signed.id", use_alter=True),
        nullable=False,
    )
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    suggested_window_start: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=True, default=None
    )
    suggested_window_end: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=True, default=None
    )
    timestamp_retry_after: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=True, default=None
    )
    explanation_url: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(255), nullable=True, default=None
    )

    # originally intended to track success of the check
    ari_check_status: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean,
        nullable=False,
    )  # True: Success; False Failure

    # we only use this on errors
    raw_response: Mapped[str] = mapped_column(sa.Text, nullable=True)

    certificate_signed = sa_orm_relationship(
        "CertificateSigned",
        primaryjoin="AriCheck.certificate_signed_id==CertificateSigned.id",
        uselist=False,
        back_populates="ari_checks",
    )

    @property
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            # - -
            "ari_check_status": self.ari_check_status,
            "certificate_signed_id": self.certificate_signed_id,
            "raw_response": self.raw_response,
            "suggested_window_start": (
                self.suggested_window_start.isoformat()
                if self.suggested_window_start
                else None
            ),
            "suggested_window_end": (
                self.suggested_window_end.isoformat()
                if self.suggested_window_end
                else None
            ),
            "timestamp_retry_after": (
                self.timestamp_retry_after.isoformat()
                if self.timestamp_retry_after
                else None
            ),
            "timestamp_created": self.timestamp_created_isoformat,
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
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    display_name: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    discovery_type: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(255), nullable=True, default=None
    )

    # TODO: migrate this to an association table that tracks different trusted root stores
    is_trusted_root: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=None
    )  # this is just used to track if we know this cert is in trusted root stores.
    key_technology_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see .utils.KeyTechnology

    cert_pem: Mapped[str] = mapped_column(sa.Text, nullable=False, unique=True)
    cert_pem_md5: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(32), nullable=True, unique=True
    )
    spki_sha256: Mapped[str] = mapped_column(sa.Unicode(64), nullable=False)
    fingerprint_sha1: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)

    timestamp_not_before: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    timestamp_not_after: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    cert_subject: Mapped[str] = mapped_column(sa.Text, nullable=False)
    cert_issuer: Mapped[str] = mapped_column(sa.Text, nullable=False)

    # these are not guaranteed
    cert_issuer_uri: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True)
    cert_authority_key_identifier: Mapped[Optional[str]] = mapped_column(
        sa.Text, nullable=True
    )
    cert_issuer__reconciled: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=None
    )  # status, True or False
    cert_issuer__certificate_ca_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("certificate_ca.id"), nullable=True
    )  # who did we reconcile this to/
    reconciled_uris: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True)

    count_active_certificates: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0
    )  # internal tracking
    operations_event_id__created: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )  # internal tracking
    signed_by__certificate_ca_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("certificate_ca.id"), nullable=True
    )  # internal tracking
    cross_signed_by__certificate_ca_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("certificate_ca.id"), nullable=True
    )  # internal tracking

    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )

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

    @property
    def button_view(self) -> str:
        dbSession = sa_Session.object_session(self)
        if TYPE_CHECKING:
            assert dbSession
        request = dbSession.info.get("request")

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
                "admin_prefix": request.api_context.application_settings[
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
    def button_search_spki(self) -> str:
        dbSession = sa_Session.object_session(self)
        if TYPE_CHECKING:
            assert dbSession
        request = dbSession.info.get("request")

        if not request:
            return "<!-- ERROR. could not derive the `request` -->"

        button = (
            """<a class="btn btn-xs btn-info" href="%(admin_prefix)s/search?%(cert_spki_search)s">"""
            """<span class="glyphicon glyphicon-search" aria-hidden="true"></span>"""
            """</a>"""
            % {
                "admin_prefix": request.api_context.application_settings[
                    "admin_prefix"
                ],
                "cert_spki_search": self.cert_spki_search,
            }
        )
        return button

    @reify
    def cert_spki_search(self) -> str:
        return "type=spki&spki=%s&source=certificate_ca&certificate_ca.id=%s" % (
            self.spki_sha256,
            self.id,
        )

    @reify
    def cert_subject_search(self) -> str:
        return (
            "type=cert_subject&cert_subject=%s&source=certificate_ca&certificate_ca.id=%s"
            % (self.cert_subject, self.id)
        )

    @reify
    def cert_issuer_search(self) -> str:
        return (
            "type=cert_issuer&cert_issuer=%s&source=certificate_ca&certificate_ca.id=%s"
            % (self.cert_issuer, self.id)
        )

    @reify
    def fingerprint_sha1_preview(self) -> str:
        return "%s&hellip;" % (self.fingerprint_sha1__colon or "")[:8]

    @property
    def key_technology(self) -> Optional[str]:
        if self.key_technology_id is None:
            return None
        return model_utils.KeyTechnology.as_string(self.key_technology_id)

    @property
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            # - -
            "cert_pem_md5": self.cert_pem_md5,
            "cert_pem": self.cert_pem,
            "cert_subject": self.cert_subject,
            "cert_issuer": self.cert_issuer,
            "display_name": self.display_name,
            "fingerprint_sha1": self.fingerprint_sha1,
            "key_technology": self.key_technology,
            "spki_sha256": self.spki_sha256,
            "timestamp_created": self.timestamp_created_isoformat,
            "timestamp_not_after": self.timestamp_not_after_isoformat,
            "timestamp_not_before": self.timestamp_not_before_isoformat,
        }


class CertificateCAChain(Base, _Mixin_Timestamps_Pretty):
    """
    These are pre-assembled chains of CertificateCA objects.
    """

    __tablename__ = "certificate_ca_chain"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    display_name: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    discovery_type: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(255), nullable=True, default=None
    )
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )

    # this is the PEM encoding of the ENTIRE chain, not just element 0
    # while this could be assembled, for now it is being cached here
    chain_pem: Mapped[str] = mapped_column(sa.Text, nullable=False, unique=True)
    chain_pem_md5: Mapped[str] = mapped_column(
        sa.Unicode(32), nullable=False, unique=True
    )

    # how many items are in the chain?
    chain_length: Mapped[int] = mapped_column(sa.Integer, nullable=False)

    # this is the first item in the chain; what signs the CertificateSigned
    certificate_ca_0_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("certificate_ca.id"), nullable=False
    )
    # this is the last item in the chain; usually a leaf of a trusted root
    certificate_ca_n_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("certificate_ca.id"), nullable=False
    )
    # this is a comma(,) separated list of the involved CertificateCA ids
    # using a string here is not a normalized data storage, but is more useful and efficient
    certificate_ca_ids_string: Mapped[str] = mapped_column(
        sa.Unicode(255), nullable=False
    )

    operations_event_id__created: Mapped[int] = mapped_column(
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
    def button_view(self) -> str:
        dbSession = sa_Session.object_session(self)
        if TYPE_CHECKING:
            assert dbSession
        request = dbSession.info.get("request")

        if not request:
            return "<!-- ERROR. could not derive the `request` -->"

        button = (
            """<a class="label label-info" href="%(admin_prefix)s/certificate-ca-chain/%(id)s">"""
            """<span class="glyphicon glyphicon-file" aria-hidden="true"></span>"""
            """CertificateCAChain-%(id)s</a>"""
            % {
                "admin_prefix": request.api_context.application_settings[
                    "admin_prefix"
                ],
                "id": self.id,
            }
        )
        return button

    @property
    def button_compatible_search_view(self) -> str:
        dbSession = sa_Session.object_session(self)
        if TYPE_CHECKING:
            assert dbSession
        request = dbSession.info.get("request")

        if not request:
            return "<!-- ERROR. could not derive the `request` -->"

        button = (
            """<a class="label label-info" href="%(admin_prefix)s/certificate-ca-chain/%(id)s">"""
            """<span class="glyphicon glyphicon-file" aria-hidden="true"></span>"""
            """CertificateCAChain-%(id)s</a>"""
            % {
                "admin_prefix": request.api_context.application_settings[
                    "admin_prefix"
                ],
                "id": self.id,
            }
        )
        return button

    @reify
    def certificate_ca_ids(self) -> List[str]:
        _certificate_ca_ids = self.certificate_ca_ids_string.split(",")
        return _certificate_ca_ids

    @reify
    def certificate_cas_all(self) -> List["CertificateCA"]:
        # reify vs property, because this queries the database
        certificate_ca_ids = self.certificate_ca_ids
        dbSession = sa_Session.object_session(self)
        if TYPE_CHECKING:
            assert dbSession
        dbCertificateCAs = (
            dbSession.query(CertificateCA)
            .filter(CertificateCA.id.in_(certificate_ca_ids))
            .all()
        )
        return dbCertificateCAs

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            # - -
            "certificate_ca_ids": self.certificate_ca_ids,
            "certificate_cas": [i.as_json for i in self.certificate_cas_all],
            "chain_pem_md5": self.chain_pem_md5,
            "chain_pem": self.chain_pem,
            "display_name": self.display_name,
            "timestamp_created": self.timestamp_created_isoformat,
        }


# ==============================================================================


class CertificateCAPreferencePolicy(Base):
    """
    These are trusted "Certificate Authority" Certificates from LetsEncrypt that
    are used to sign server certificates.

    These are directly tied to a CertificateSigned and are needed to create a
    "fullchain" certificate for most deployments.
    """

    __tablename__ = "certificate_ca_preference_policy"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    name: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(64), nullable=True, unique=True
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    certificate_ca_preferences = sa_orm_relationship(
        "CertificateCAPreference",
        primaryjoin="CertificateCAPreferencePolicy.id==CertificateCAPreference.certificate_ca_preference_policy_id",
        order_by="CertificateCAPreference.slot_id.asc()",
        back_populates="certificate_ca_preference_policy",
    )

    @property
    def as_json(self):
        return {
            "id": self.id,
            # --
            "certificate_ca_preferences": [
                i.as_json_minimal for i in self.certificate_ca_preferences
            ],
            # --
            "name": self.name,
        }


class CertificateCAPreference(Base, _Mixin_Timestamps_Pretty):
    """
    These are trusted "Certificate Authority" Certificates from LetsEncrypt that
    are used to sign server certificates.

    These are directly tied to a CertificateSigned and are needed to create a
    "fullchain" certificate for most deployments.
    """

    __tablename__ = "certificate_ca_preference"
    __table_args__ = (
        sa.Index(
            "uidx_certificate_ca_preference_a",
            "certificate_ca_preference_policy_id",
            "slot_id",
            unique=True,
        ),
        sa.Index(
            "uidx_certificate_ca_preference_b",
            "certificate_ca_preference_policy_id",
            "certificate_ca_id",
            unique=True,
        ),
    )

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    certificate_ca_preference_policy_id: Mapped[int] = mapped_column(
        sa.Integer,
        sa.ForeignKey("certificate_ca_preference_policy.id"),
        nullable=False,
    )
    slot_id = mapped_column(sa.Integer, nullable=False)
    certificate_ca_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("certificate_ca.id"), nullable=False, unique=True
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    certificate_ca_preference_policy = sa_orm_relationship(
        "CertificateCAPreferencePolicy",
        primaryjoin="CertificateCAPreference.certificate_ca_preference_policy_id==CertificateCAPreferencePolicy.id",
        back_populates="certificate_ca_preferences",
        uselist=False,
    )
    certificate_ca = sa_orm_relationship(
        "CertificateCA",
        primaryjoin="CertificateCAPreference.certificate_ca_id==CertificateCA.id",
        uselist=False,
    )

    @property
    def as_json_minimal(self):
        return {
            "id": self.id,
            # --
            "slot_id": self.slot_id,
            "certificate_ca_id": self.certificate_ca_id,
        }


# ==============================================================================


class CertificateCAReconciliation(Base):
    __tablename__ = "certificate_ca_reconciliation"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    timestamp_operation: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    certificate_ca_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("certificate_ca.id"), nullable=False
    )
    result: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=None
    )  # True - success; False - failure
    certificate_ca_id__issuer__reconciled: Mapped[Optional[int]] = mapped_column(
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

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    certificate_request_source_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see .utils.CertificateRequestSource
    csr_pem: Mapped[str] = mapped_column(sa.Text, nullable=False)
    csr_pem_md5: Mapped[str] = mapped_column(sa.Unicode(32), nullable=False)
    spki_sha256: Mapped[str] = mapped_column(sa.Unicode(64), nullable=False)

    key_technology_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see .utils.KeyTechnology
    operations_event_id__created: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )
    private_key_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("private_key.id", use_alter=True), nullable=True
    )
    unique_fqdn_set_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("unique_fqdn_set.id"), nullable=False
    )
    discovery_type: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(255), nullable=True, default=None
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
    def certificate_request_source(self) -> str:
        return model_utils.CertificateRequestSource.as_string(
            self.certificate_request_source_id
        )

    @property
    def certificate_signed_id__latest(self) -> Optional[str]:
        if self.certificate_signed__latest:
            return self.certificate_signed__latest.id
        return None

    @reify
    def csr_spki_search(self) -> str:
        return (
            "type=spki&spki=%s&source=certificate_request&certificate_request.id=%s"
            % (self.spki_sha256, self.id)
        )

    @property
    def domains_as_string(self) -> str:
        domains = sorted(
            [to_d.domain.domain_name for to_d in self.unique_fqdn_set.to_domains]
        )
        return ", ".join(domains)

    @property
    def domains_as_list(self) -> List[str]:
        domain_names = [
            to_d.domain.domain_name.lower() for to_d in self.unique_fqdn_set.to_domains
        ]
        domain_names = list(set(domain_names))
        domain_names = sorted(domain_names)
        return domain_names

    @property
    def key_technology(self) -> Optional[str]:
        if self.key_technology_id is None:
            return None
        return model_utils.KeyTechnology.as_string(self.key_technology_id)

    @property
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            # - -
            "certificate_request_source": self.certificate_request_source,
            "csr_pem_md5": self.csr_pem_md5,
            "private_key_id": self.private_key_id,
            "spki_sha256": self.spki_sha256,
            "timestamp_created": self.timestamp_created_isoformat,
            "unique_fqdn_set_id": self.unique_fqdn_set_id,
        }

    @property
    def as_json_extended(self) -> Dict:
        return {
            "id": self.id,
            # - -
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
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    timestamp_not_before: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    timestamp_not_after: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    is_single_domain_cert: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=None
    )
    key_technology_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see .utils.KeyTechnology

    cert_pem: Mapped[str] = mapped_column(sa.Text, nullable=False, unique=True)
    cert_pem_md5: Mapped[str] = mapped_column(
        sa.Unicode(32), nullable=False, unique=True
    )
    spki_sha256: Mapped[str] = mapped_column(sa.Unicode(64), nullable=False)
    fingerprint_sha1: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    cert_subject: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    cert_issuer: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    # track the hours, because this may affect ARI
    duration_hours: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    is_active: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    is_deactivated: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=None
    )  # used to determine `is_active` toggling; if "True" then `is_active` can-not be toggled.
    is_revoked: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=None
    )  # used to determine is_active toggling. this will set 'is_deactivated' to True
    is_compromised_private_key: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=None
    )  # used to determine is_active toggling. this will set 'is_deactivated' to True
    unique_fqdn_set_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("unique_fqdn_set.id"), nullable=False
    )
    timestamp_revoked_upstream: Mapped[Optional[datetime.datetime]] = mapped_column(
        TZDateTime(timezone=True), nullable=True
    )  # if set, the cert was reported revoked upstream and this is FINAL

    cert_serial: Mapped[str] = mapped_column(
        sa.Unicode(255), nullable=False, unique=False
    )  # the serial is only unique within an acme-provider

    # acme_order_id__generated_by: Mapped[Optional[int]] = mapped_column(sa.Integer, sa.ForeignKey("acme_order.id"), nullable=True,)

    # this is the private key
    private_key_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("private_key.id", use_alter=True), nullable=False
    )

    # tracking
    # `use_alter=True` is needed for setup/drop
    certificate_request_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer,
        sa.ForeignKey("certificate_request.id", use_alter=True),
        nullable=True,
    )
    # utils.CertificateType.[RAW_IMPORTED, MANAGED_PRIMARY, MANAGED_BACKUP]
    # AcmeOrder.certificate_type_id MUST never change; CertificateSigned.certificate_type_id MAY change
    certificate_type_id: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    operations_event_id__created: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )
    discovery_type: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(255), nullable=True, default=None
    )
    # True if we parse the cert and detect a known ARI server
    is_ari_supported__cert: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=True, default=None
    )
    # True if we ordered the cert from a known ARI server
    is_ari_supported__order: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=True, default=None
    )
    ari_identifier: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(255), nullable=True, default=None
    )

    #
    # store the ari identifier, in case the old cert is not here
    # but also store the local ids, so we don't search for them
    # storage is cheap
    #
    ari_identifier__replaces: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(255), nullable=True, default=None
    )
    certificate_signed_id__replaces: Mapped[Optional[int]] = mapped_column(
        sa.Integer,
        sa.ForeignKey("certificate_signed.id"),
        nullable=True,
    )
    ari_identifier__replaced_by: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(255), nullable=True, default=None
    )
    certificate_signed_id__replaced_by: Mapped[Optional[int]] = mapped_column(
        sa.Integer,
        sa.ForeignKey("certificate_signed.id"),
        nullable=True,
    )
    #
    # end duplicated data
    #

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    # this relationship is based on the AcmeOrder, not the PrivateKey
    acme_account = sa_orm_relationship(
        AcmeAccount,
        primaryjoin="CertificateSigned.id==AcmeOrder.certificate_signed_id",
        secondary="join(AcmeOrder, AcmeAccount, AcmeOrder.acme_account_id==AcmeAccount.id)",
        uselist=False,
        viewonly=True,
    )
    acme_order = sa_orm_relationship(
        "AcmeOrder",
        primaryjoin="CertificateSigned.id==AcmeOrder.certificate_signed_id",
        uselist=False,
        back_populates="certificate_signed",
    )
    ari_checks = sa_orm_relationship(
        "AriCheck",
        primaryjoin="CertificateSigned.id==AriCheck.certificate_signed_id",
        back_populates="certificate_signed",
        uselist=True,
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

    @property
    def cert_spki_search(self) -> str:
        return "type=spki&spki=%s&source=certificate&certificate.id=%s" % (
            self.spki_sha256,
            self.id,
        )

    @property
    def cert_subject_search(self) -> str:
        return (
            "type=cert_subject&cert_subject=%s&source=certificate&certificate.id=%s"
            % (self.cert_subject, self.id)
        )

    @property
    def cert_issuer_search(self) -> str:
        return (
            "type=cert_issuer&cert_issuer=%s&source=certificate&certificate.id=%s"
            % (self.cert_issuer, self.id)
        )

    @property
    def cert_chain_pem(self) -> Optional[str]:
        if not self.certificate_ca_chain__preferred:
            return None
        return self.certificate_ca_chain__preferred.chain_pem

    @property
    def cert_fullchain_pem(self) -> Optional[str]:
        if not self.certificate_ca_chain__preferred:
            return None
        # certs are standardized to have a newline
        return "\n".join((self.cert_pem.strip(), self.cert_chain_pem))  # type: ignore[arg-type]

    @reify
    def certificate_ca_ids__upchain(self) -> List[int]:
        # this loops `ORM:certificate_signed_chains`
        # this is NOT in order of preference
        _ids = set([])
        for _to_certificate_ca_chain in self.certificate_signed_chains:
            _chain = _to_certificate_ca_chain.certificate_ca_chain
            _ids.add(_chain.certificate_ca_0_id)
        ids = list(_ids)
        return ids

    @reify
    def certificate_cas__upchain(self) -> List["CertificateCA"]:
        # this loops `ORM:certificate_signed_chains`
        # this is NOT in order of preference
        _cas = set([])
        for _to_certificate_ca_chain in self.certificate_signed_chains:
            _chain = _to_certificate_ca_chain.certificate_ca_chain
            _cas.add(_chain.certificate_ca_0)
        cas = list(_cas)
        return cas

    @reify
    def certificate_ca_chain_ids(self) -> List[int]:
        # this loops `ORM:certificate_signed_chains`
        # this is NOT in order of preference
        _ids = [i.certificate_ca_chain_id for i in self.certificate_signed_chains]
        return _ids

    @reify
    def certificate_ca_chain_id__preferred(self) -> Optional[int]:
        # this invokes `certificate_ca_chain__preferred`
        # which then loops `ORM:certificate_signed_chains`
        if self.certificate_ca_chain__preferred:
            return self.certificate_ca_chain__preferred.id
        return None

    @reify
    def certificate_ca_chain__preferred(self) -> Optional["CertificateCAChain"]:
        # this loops `ORM:certificate_signed_chains`
        if not self.certificate_signed_chains:
            return None
        try:
            dbSession = sa_Session.object_session(self)
            if TYPE_CHECKING:
                assert dbSession
            request = dbSession.info.get("request")

            # only search for a preference if they exist
            if request and request.dbCertificateCAPreferencePolicy:
                # TODO: first match or shortest match?
                # first match for now!
                # there are a lot of ways to compute this,
                # this is not efficient. this is just a quick pass
                preferred_ca_ids = [
                    i.certificate_ca_id
                    for i in request.dbCertificateCAPreferencePolicy.certificate_ca_preferences
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

        except Exception as exc:
            log.critical(exc)
        return None

    def custom_config_payload(
        self,
        certificate_ca_chain_id=None,
        id_only=False,
    ) -> Dict:
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
    def config_payload(self) -> Dict:
        return self.custom_config_payload(certificate_ca_chain_id=None, id_only=False)

    @property
    def config_payload_idonly(self) -> Dict:
        return self.custom_config_payload(certificate_ca_chain_id=None, id_only=True)

    @property
    def certificate_type(self) -> str:
        return model_utils.CertificateType.as_string(self.certificate_type_id)

    @property
    def domains_as_string(self) -> str:
        return self.unique_fqdn_set.domains_as_string

    @property
    def domains_as_list(self) -> List[str]:
        return self.unique_fqdn_set.domains_as_list

    @reify
    def expiring_days(self) -> Optional[int]:
        return (
            self.timestamp_not_after - datetime.datetime.now(datetime.timezone.utc)
        ).days

    @reify
    def expiring_days_label(self) -> str:
        if self.expiring_days <= 0:
            return "danger"
        elif self.expiring_days <= 30:
            return "warning"
        elif self.expiring_days > 30:
            return "success"
        return "danger"

    @property
    def fullchain(self) -> str:
        return "\n".join((self.cert_pem.strip(), (self.cert_chain_pem or "")))

    @property
    def is_can_renew_letsencrypt(self) -> bool:
        """only allow renew of LE certificates"""
        # if self.acme_account_id:
        #    return True
        return False

    def is_ari_check_timely(self, ctx: "ApiContext") -> bool:
        timestamp_max_expiry = self.is_ari_check_timely_expiry(ctx)
        if self.timestamp_not_after >= timestamp_max_expiry:
            return False
        return True

    def is_ari_check_timely_expiry(self, ctx: "ApiContext") -> datetime.datetime:
        # don't rely on ctx.timestamp, as it can be old
        NOW = datetime.datetime.now(datetime.timezone.utc)
        TIMEDELTA_clockdrift = datetime.timedelta(minutes=5)
        assert ctx.application_settings
        _minutes = ctx.application_settings.get("offset.ari_updates", 60)
        TIMEDELTA_runner_interval = datetime.timedelta(minutes=_minutes)

        # This is WILD
        # usually we SUBTRACT for searches and automatic renewals to give a safer buffer
        # here, we ADD the offset to give a wider buffer for on-demand
        timestamp_max_expiry = NOW + TIMEDELTA_clockdrift + TIMEDELTA_runner_interval
        return timestamp_max_expiry

    @property
    def is_ari_supported(self) -> bool:
        if self.is_ari_supported__cert or self.is_ari_supported__order:
            return True
        return False

    @property
    def key_technology(self) -> Optional[str]:
        if self.key_technology_id is None:
            return None
        return model_utils.KeyTechnology.as_string(self.key_technology_id)

    @property
    def renewal__private_key_strategy_id(self) -> int:
        if self.acme_order:
            _private_key_cycle = self.acme_order.private_key_cycle
            if _private_key_cycle != "account_default":
                _private_key_strategy = (
                    model_utils.PrivateKeyStrategy.from_private_key_cycle(
                        _private_key_cycle
                    )
                )
            else:
                _private_key_strategy = (
                    model_utils.PrivateKeyStrategy.from_private_key_cycle(
                        self.acme_order.acme_account.private_key_cycle
                    )
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
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            # - -
            # "acme_account_id": self.acme_account_id,
            "ari_check_latest_id": (
                self.ari_check__latest.id if self.ari_check__latest else None
            ),
            "ari_identifier": self.ari_identifier,
            "ari_identifier__replaced_by": self.ari_identifier__replaced_by,
            "ari_identifier__replaces": self.ari_identifier__replaces,
            "certificate_signed_id__replaced_by": self.certificate_signed_id__replaced_by,
            "certificate_signed_id__replaces": self.certificate_signed_id__replaces,
            "certificate_type": self.certificate_type,
            "certificate_ca_chain_id__preferred": self.certificate_ca_chain_id__preferred,
            "certificate_ca_chain_ids": self.certificate_ca_chain_ids,
            "certificate_ca_ids__upchain": self.certificate_ca_ids__upchain,
            "cert_pem": self.cert_pem,
            "cert_pem_md5": self.cert_pem_md5,
            "cert_subject": self.cert_subject,
            "cert_issuer": self.cert_issuer,
            "cert_serial": self.cert_serial,
            "domains_as_list": self.domains_as_list,
            "duration_hours": self.duration_hours,
            "fingerprint_sha1": self.fingerprint_sha1,
            "is_ari_supported": self.is_ari_supported,
            "is_active": True if self.is_active else False,
            "is_deactivated": True if self.is_deactivated else False,
            "is_revoked": True if self.is_revoked else False,
            "is_compromised_private_key": (
                True if self.is_compromised_private_key else False
            ),
            "key_technology": self.key_technology,
            "private_key_id": self.private_key_id,
            "spki_sha256": self.spki_sha256,
            "timestamp_not_after": self.timestamp_not_after_isoformat,
            "timestamp_not_before": self.timestamp_not_before_isoformat,
            "timestamp_revoked_upstream": self.timestamp_revoked_upstream_isoformat,
            "unique_fqdn_set_id": self.unique_fqdn_set_id,
        }

    @property
    def as_json_replaces_candidate(self) -> Dict:
        return {
            "id": self.id,
            "ari_identifier": self.ari_identifier,
            "cert_pem_md5": self.cert_pem_md5,
            "spki_sha256": self.spki_sha256,
            "timestamp_not_after": self.timestamp_not_after_isoformat,
            "timestamp_not_before": self.timestamp_not_before_isoformat,
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
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    certificate_signed_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("certificate_signed.id"), nullable=False
    )
    certificate_ca_chain_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("certificate_ca_chain.id"), nullable=False
    )
    is_upstream_default: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=None
    )

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
            "(private_key_id IS NOT NULL OR certificate_signed_id IS NOT NULL)",
            name="check_pkey_andor_certs",
        ),
    )

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    private_key_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("private_key.id"), nullable=True
    )
    certificate_signed_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("certificate_signed.id"), nullable=True
    )
    coverage_assurance_event_type_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # `model_utils.CoverageAssuranceEventType`
    coverage_assurance_event_status_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # `model_utils.CoverageAssuranceEventStatus`
    coverage_assurance_resolution_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # `model_utils.CoverageAssuranceResolution`
    coverage_assurance_event_id__parent: Mapped[Optional[int]] = mapped_column(
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

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def coverage_assurance_event_type(self) -> str:
        return model_utils.CoverageAssuranceEventType.as_string(
            self.coverage_assurance_event_type_id
        )

    @property
    def coverage_assurance_event_status(self) -> str:
        return model_utils.CoverageAssuranceEventStatus.as_string(
            self.coverage_assurance_event_status_id
        )

    @property
    def coverage_assurance_resolution(self) -> str:
        return model_utils.CoverageAssuranceResolution.as_string(
            self.coverage_assurance_resolution_id
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def as_json(self) -> Dict:
        payload = {
            "id": self.id,
            # - -
            "certificate_signed_id": self.private_key_id,
            "coverage_assurance_event_type": self.coverage_assurance_event_type,
            "coverage_assurance_event_status": self.coverage_assurance_event_status,
            "coverage_assurance_resolution": self.coverage_assurance_resolution,
            "coverage_assurance_event_id__parent": self.coverage_assurance_event_id__parent,
            "private_key_id": self.private_key_id,
            "timestamp_created": self.timestamp_created_isoformat,
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

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    domain_name: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    registered: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    suffix: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)

    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )

    certificate_signed_id__latest_single: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("certificate_signed.id"), nullable=True
    )
    certificate_signed_id__latest_multi: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("certificate_signed.id"), nullable=True
    )
    operations_event_id__created: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )

    discovery_type: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(255), nullable=True, default=None
    )
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def registered_domain(self):
        return "%s.%s" % (self.registered, self.suffix)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_authorizations = sa_orm_relationship(
        "AcmeAuthorization",
        primaryjoin="Domain.id==AcmeAuthorization.domain_id",
        order_by="AcmeAuthorization.id.desc()",
        uselist=True,
        back_populates="domain",
    )
    acme_authorization_potentials = sa_orm_relationship(
        "AcmeAuthorizationPotential",
        primaryjoin="Domain.id==AcmeAuthorizationPotential.domain_id",
        order_by="AcmeAuthorizationPotential.id.desc()",
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
        viewonly=True,  # the `AcmeDnsServerAccount.is_active` join complicates things
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
    to_fqdns = sa_orm_relationship(
        "UniqueFQDNSet2Domain",
        primaryjoin="Domain.id==UniqueFQDNSet2Domain.domain_id",
        back_populates="domain",
    )
    to_fqdns_uniquely_challenged = sa_orm_relationship(
        "UniquelyChallengedFQDNSet2Domain",
        primaryjoin="Domain.id==UniquelyChallengedFQDNSet2Domain.domain_id",
        back_populates="domain",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def acme_challenge_domain_name(self) -> str:
        # note: the cname source should end with a .
        return "_acme-challenge.%s." % self.domain_name

    @property
    def has_active_certificates(self) -> bool:
        return (
            True
            if (
                self.certificate_signed_id__latest_single
                or self.certificate_signed_id__latest_multi
            )
            else False
        )

    @property
    def as_json(self) -> Dict:
        payload = {
            "id": self.id,
            # - -
            "acme_challenge_domain_name": self.acme_challenge_domain_name,
            "certificate__latest_multi": {},
            "certificate__latest_single": {},
            "certificate_signeds__single_primary_5": [],
            "certificate_signeds__single_backup_5": [],
            "domain_name": self.domain_name,
        }
        if self.certificate_signed_id__latest_multi:
            payload["certificate__latest_multi"] = {
                "id": self.certificate_signed_id__latest_multi,
                "timestamp_not_after": self.certificate_signed__latest_multi.timestamp_not_after_isoformat,
                "expiring_days": self.certificate_signed__latest_multi.expiring_days,
                "is_active": self.certificate_signed__latest_multi.is_active,
            }
        if self.certificate_signed_id__latest_single:
            payload["certificate__latest_single"] = {
                "id": self.certificate_signed_id__latest_single,
                "timestamp_not_after": self.certificate_signed__latest_single.timestamp_not_after_isoformat,
                "expiring_days": self.certificate_signed__latest_single.expiring_days,
                "is_active": self.certificate_signed__latest_single.is_active,
            }

        if self.certificate_signeds__single_primary_5:
            payload["certificate_signeds__single_primary_5"] = [
                {
                    "id": i.id,
                    "timestamp_not_after": i.timestamp_not_after_isoformat,
                    "expiring_days": i.expiring_days,
                    "is_active": i.is_active,
                }
                for i in self.certificate_signeds__single_primary_5
            ]
        if self.certificate_signeds__single_backup_5:
            payload["certificate_signeds__single_backup_5"] = [
                {
                    "id": i.id,
                    "timestamp_not_after": i.timestamp_not_after_isoformat,
                    "expiring_days": i.expiring_days,
                    "is_active": i.is_active,
                }
                for i in self.certificate_signeds__single_backup_5
            ]
        return payload

    @property
    def as_json__acme_dns_server_accounts_5(self) -> Dict:
        """
        show minimal info here
        """
        rval = {}
        for acc in self.acme_dns_server_accounts__5:
            rval[acc.id] = {
                "id": acc.id,
                "cname_source": acc.cname_source,
                "cname_target": acc.cname_target,
            }
        return rval

    def as_json_config(self, id_only=False):
        """
        this is slightly different
        * everything is lowercase
        * id is a string
        """
        rval = {
            "Domain": {
                "id": str(self.id),
                "domain_name": self.domain_name,
            },
            # - -
            "certificate_signed__latest_single": None,
            "certificate_signed__latest_multi": None,
        }
        if self.certificate_signed_id__latest_single:
            if id_only:
                rval["certificate_signed__latest_single"] = (
                    self.certificate_signed__latest_single.config_payload_idonly
                )
            else:
                rval["certificate_signed__latest_single"] = (
                    self.certificate_signed__latest_single.config_payload
                )
        if self.certificate_signed_id__latest_multi:
            if id_only:
                rval["certificate_signed__latest_multi"] = (
                    self.certificate_signed__latest_multi.config_payload_idonly
                )
            else:
                rval["certificate_signed__latest_multi"] = (
                    self.certificate_signed__latest_multi.config_payload
                )
        return rval


# ==============================================================================


class DomainAutocert(Base, _Mixin_Timestamps_Pretty):
    """
    Track autocerts of a domain specifically, because the process should 'block'
    """

    __tablename__ = "domain_autocert"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    domain_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("domain.id"), nullable=True
    )
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    timestamp_finished: Mapped[Optional[datetime.datetime]] = mapped_column(
        TZDateTime(timezone=True), nullable=True
    )
    is_successful: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=None
    )
    acme_order_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_order.id"), nullable=True
    )

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
    def as_json(self) -> Dict:
        payload = {
            "id": self.id,
            "AcmeOrder": {"id": self.acme_order_id} if self.acme_order_id else None,
            "Domain": {
                "id": self.domain_id,
                "domain_name": self.domain.domain_name,
            },
            # - -
            "is_successful": self.is_successful,
            "timestamp_created": self.timestamp_created_isoformat,
            "timestamp_finished": self.timestamp_finished_isoformat,
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

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    domain_name: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)

    @property
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            "domain_name": self.domain_name,
        }


# ==============================================================================


class EnrollmentFactory(Base, _Mixin_AcmeAccount_Effective):

    __table_args__ = (
        sa.CheckConstraint(
            "("
            "(acme_account_id__backup IS NOT NULL AND private_key_technology_id__backup IS NOT NULL AND private_key_cycle_id__backup IS NOT NULL)"
            " OR "
            "(acme_account_id__backup IS NULL AND private_key_technology_id__backup IS NULL AND private_key_cycle_id__backup IS NULL)"
            ")",
            name="check_ef_backup_account",
        ),
    )

    __tablename__ = "enrollment_factory"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    name: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False, unique=True)

    label_template: Mapped[Optional[str]] = mapped_column(sa.Unicode(64), nullable=True)

    domain_template_http01: Mapped[Optional[str]] = mapped_column(
        sa.Text, nullable=True, default=None
    )
    domain_template_dns01: Mapped[Optional[str]] = mapped_column(
        sa.Text, nullable=True, default=None
    )
    is_export_filesystem_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see .utils.OptionsOnOff

    # for consumers
    note: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True, default=None)

    # Primary Cert
    acme_account_id__primary: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_account.id"), nullable=False
    )
    private_key_technology_id__primary: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see .utils.KeyTechnology
    private_key_cycle_id__primary: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see .utils.PrivateKeyCycle
    acme_profile__primary: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(64), nullable=True
    )

    # Backup Cert
    acme_account_id__backup: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_account.id"), nullable=True
    )
    private_key_technology_id__backup: Mapped[Optional[int]] = mapped_column(
        sa.Integer, nullable=True
    )  # see .utils.KeyTechnology
    private_key_cycle_id__backup: Mapped[Optional[int]] = mapped_column(
        sa.Integer, nullable=True
    )  # see .utils.PrivateKeyCycle
    acme_profile__backup: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(64), nullable=True
    )

    acme_account__primary = sa_orm_relationship(
        "AcmeAccount",
        primaryjoin="EnrollmentFactory.acme_account_id__primary==AcmeAccount.id",
        uselist=False,
        back_populates="enrollment_factorys__primary",
    )
    acme_account__backup = sa_orm_relationship(
        "AcmeAccount",
        primaryjoin="EnrollmentFactory.acme_account_id__backup==AcmeAccount.id",
        uselist=False,
        back_populates="enrollment_factorys__backup",
    )
    operations_object_events = sa_orm_relationship(
        "OperationsObjectEvent",
        primaryjoin="EnrollmentFactory.id==OperationsObjectEvent.enrollment_factory_id",
        back_populates="enrollment_factory",
    )
    renewal_configurations = sa_orm_relationship(
        "RenewalConfiguration",
        primaryjoin="EnrollmentFactory.id==RenewalConfiguration.enrollment_factory_id__via",
        back_populates="enrollment_factory__via",
    )

    @property
    def is_export_filesystem(self) -> str:
        return model_utils.OptionsOnOff.as_string(self.is_export_filesystem_id)

    @property
    def private_key_technology__primary(self) -> str:
        return model_utils.KeyTechnology.as_string(
            self.private_key_technology_id__primary
        )

    @property
    def private_key_technology__backup(self) -> Optional[str]:
        if self.private_key_technology_id__backup is None:
            return None
        return model_utils.KeyTechnology.as_string(
            self.private_key_technology_id__backup
        )

    @property
    def private_key_cycle__primary(self) -> str:
        return model_utils.PrivateKeyCycle.as_string(self.private_key_cycle_id__primary)

    @property
    def private_key_cycle__backup(self) -> Optional[str]:
        if self.private_key_cycle_id__backup is None:
            return None
        return model_utils.PrivateKeyCycle.as_string(self.private_key_cycle_id__backup)

    @property
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            # - -
            "name": self.name,
            "note": self.note,
            "label_template": self.label_template,
            "domain_template_http01": self.domain_template_http01,
            "domain_template_dns01": self.domain_template_dns01,
            "acme_account_id__primary": self.acme_account_id__primary,
            "acme_account_id__backup": self.acme_account_id__backup,
            "acme_profile__primary": self.acme_profile__primary,
            "acme_profile__primary__effective": self.acme_profile__primary__effective,
            "acme_profile__backup": self.acme_profile__backup,
            "acme_profile__backup__effective": self.acme_profile__backup__effective,
            "private_key_technology__primary": self.private_key_technology__primary,
            "private_key_technology__primary__effective": self.private_key_technology__primary__effective,
            "private_key_technology__backup": self.private_key_technology__backup,
            "private_key_technology__backup__effective": self.private_key_technology__backup__effective,
            "private_key_cycle__primary": self.private_key_cycle__primary,
            "private_key_cycle__primary__effective": self.private_key_cycle__primary__effective,
            "private_key_cycle__backup": self.private_key_cycle__backup,
            "private_key_cycle__backup__effective": self.private_key_cycle__backup__effective,
        }

    @property
    def as_json_docs(self) -> Dict:
        rval = self.as_json
        rval["AcmeAccounts"] = {
            "primary": (
                self.acme_account__primary.as_json_minimal
                if self.acme_account__primary
                else None
            ),
            "backup": (
                self.acme_account__backup.as_json_minimal
                if self.acme_account__backup
                else None
            ),
        }
        return rval


# ==============================================================================


class Notification(Base, _Mixin_Timestamps_Pretty):
    __tablename__ = "notification"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    notification_type_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # references NotificationType
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    message: Mapped[str] = mapped_column(sa.Text, nullable=False)

    @property
    def notification_type(self) -> str:
        return model_utils.NotificationType.as_string(self.notification_type_id)

    @property
    def as_json(self):
        return {
            "id": self.id,
            "notification_type_id": self.notification_type,
            "timestamp_created": self.timestamp_created_isoformat,
            "is_active": self.is_active,
            "message": self.message,
        }


class OperationsEvent(Base, model_utils._mixin_OperationsEventType):
    """
    Certain events are tracked for bookkeeping
    """

    __tablename__ = "operations_event"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    operations_event_type_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # references OperationsEventType
    timestamp_event: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    event_payload: Mapped[str] = mapped_column(sa.Text, nullable=False)
    operations_event_id__child_of: Mapped[Optional[int]] = mapped_column(
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

    _event_payload_json: Optional[Dict] = None

    @property
    def event_payload_json(self) -> Dict:
        if self._event_payload_json is None:
            self._event_payload_json = json.loads(self.event_payload)
        return self._event_payload_json

    def set_event_payload(self, payload_dict) -> None:
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
            " CASE WHEN acme_dns_server_id IS NOT NULL THEN 1 ELSE 0 END "
            " + "
            " CASE WHEN acme_order_id IS NOT NULL THEN 1 ELSE 0 END "
            " + "
            " CASE WHEN acme_server_id IS NOT NULL THEN 1 ELSE 0 END "
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
            " CASE WHEN enrollment_factory_id IS NOT NULL THEN 1 ELSE 0 END "
            " + "
            " CASE WHEN private_key_id IS NOT NULL THEN 1 ELSE 0 END "
            " + "
            " CASE WHEN renewal_configuration_id IS NOT NULL THEN 1 ELSE 0 END "
            " + "
            " CASE WHEN unique_fqdn_set_id IS NOT NULL THEN 1 ELSE 0 END "
            " + "
            " CASE WHEN uniquely_challenged_fqdn_set_id IS NOT NULL THEN 1 ELSE 0 END "
            " ) = 1",
            name="check1",
        ),
    )

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    operations_event_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=True
    )
    operations_object_event_status_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # references OperationsObjectEventStatus

    acme_account_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_account.id"), nullable=True
    )
    acme_account_key_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_account_key.id"), nullable=True
    )
    acme_dns_server_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_dns_server.id"), nullable=True
    )
    acme_order_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_order.id"), nullable=True
    )
    acme_server_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_server.id"), nullable=True
    )
    certificate_ca_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("certificate_ca.id"), nullable=True
    )
    certificate_ca_chain_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("certificate_ca_chain.id"), nullable=True
    )
    certificate_request_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("certificate_request.id"), nullable=True
    )
    certificate_signed_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("certificate_signed.id"), nullable=True
    )
    coverage_assurance_event_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("coverage_assurance_event.id"), nullable=True
    )
    domain_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("domain.id"), nullable=True
    )
    enrollment_factory_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("enrollment_factory.id"), nullable=True
    )
    private_key_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("private_key.id"), nullable=True
    )
    renewal_configuration_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("renewal_configuration.id"), nullable=True
    )
    unique_fqdn_set_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("unique_fqdn_set.id"), nullable=True
    )
    uniquely_challenged_fqdn_set_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("uniquely_challenged_fqdn_set.id"), nullable=True
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
    acme_server = sa_orm_relationship(
        "AcmeServer",
        primaryjoin="OperationsObjectEvent.acme_server_id==AcmeServer.id",
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
    enrollment_factory = sa_orm_relationship(
        "EnrollmentFactory",
        primaryjoin="OperationsObjectEvent.enrollment_factory_id==EnrollmentFactory.id",
        uselist=False,
        back_populates="operations_object_events",
    )
    private_key = sa_orm_relationship(
        "PrivateKey",
        primaryjoin="OperationsObjectEvent.private_key_id==PrivateKey.id",
        uselist=False,
        back_populates="operations_object_events",
    )
    unique_fqdn_set = sa_orm_relationship(
        "UniqueFQDNSet",
        primaryjoin="OperationsObjectEvent.unique_fqdn_set_id==UniqueFQDNSet.id",
        uselist=False,
        back_populates="operations_object_events",
    )
    uniquely_challenged_fqdn_set = sa_orm_relationship(
        "UniquelyChallengedFQDNSet",
        primaryjoin="OperationsObjectEvent.uniquely_challenged_fqdn_set_id==UniquelyChallengedFQDNSet.id",
        uselist=False,
        back_populates="operations_object_events",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def event_status_text(self) -> str:
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
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    key_technology_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see .utils.KeyTechnology
    key_pem: Mapped[str] = mapped_column(sa.Text, nullable=False)
    key_pem_md5: Mapped[str] = mapped_column(sa.Unicode(32), nullable=False)
    spki_sha256: Mapped[str] = mapped_column(sa.Unicode(64), nullable=False)

    count_active_certificates: Mapped[int] = mapped_column(
        sa.Integer,
        nullable=False,
        default=0,
    )
    is_active: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    is_compromised: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=None
    )
    count_acme_orders: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0
    )
    count_certificate_signeds: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0
    )
    timestamp_last_certificate_request: Mapped[Optional[datetime.datetime]] = (
        mapped_column(TZDateTime(timezone=True), nullable=True)
    )
    timestamp_last_certificate_issue: Mapped[Optional[datetime.datetime]] = (
        mapped_column(TZDateTime(timezone=True), nullable=True)
    )
    operations_event_id__created: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )
    private_key_source_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see .utils.PrivateKeySource
    private_key_type_id: Mapped[int] = mapped_column(
        sa.Integer,
        nullable=False,
    )  # see .utils.PrivateKeyType
    acme_account_id__owner: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_account.id"), nullable=True
    )  # lock a PrivateKey to an AcmeAccount
    private_key_id__replaces: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("private_key.id"), nullable=True
    )  # if this key replaces a compromised PrivateKey, note it.
    renewal_configuration_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer,
        sa.ForeignKey("renewal_configuration.id", use_alter=True),
        nullable=True,
    )  # the key might be scoped to a renewal_configuration, like single_use__reuse_1_year
    discovery_type: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(255), nullable=True, default=None
    )

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
    renewal_configuration = sa_orm_relationship(
        "RenewalConfiguration",
        primaryjoin="PrivateKey.renewal_configuration_id==RenewalConfiguration.id",
        back_populates="private_key_reuse",
        uselist=False,
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def autogenerated_calendar_repr(self) -> str:
        if not self.is_autogenerated_calendar:
            return ""
        if self.private_key_type in model_utils.PrivateKeyType._options_calendar_weekly:
            return "%s.%s" % self.timestamp_created.isocalendar()[0:2]
        # daily
        return "%s.%s.%s" % self.timestamp_created.isocalendar()[0:3]

    @property
    def can_key_sign(self) -> bool:
        if self.is_compromised or not self.is_active or (self.id == 0):
            return False
        return True

    @property
    def is_autogenerated_calendar(self) -> bool:
        if self.private_key_type in model_utils.PrivateKeyType._options_calendar:
            return True
        return False

    @property
    def is_key_usable(self) -> bool:
        if self.is_compromised or not self.is_active:
            return False
        return True

    @property
    def is_placeholder(self) -> bool:
        if self.id == 0:
            return True
        return False

    @property
    def key_spki_search(self) -> str:
        return "type=spki&spki=%s&source=private_key&private_key.id=%s" % (
            self.spki_sha256,
            self.id,
        )

    @property
    def key_pem_sample(self) -> str:
        # strip the pem, because the last line is whitespace after "-----END RSA PRIVATE KEY-----"
        try:
            pem_lines = self.key_pem.strip().split("\n")
            return "%s...%s" % (pem_lines[1][0:5], pem_lines[-2][-5:])
        except Exception as exc:  # noqa: F841
            # it's possible to have no lines if this is the placeholder key
            return "..."

    @reify
    def key_technology(self) -> Optional[str]:
        if self.key_technology_id is None:
            return None
        return model_utils.KeyTechnology.as_string(self.key_technology_id)

    @reify
    def private_key_source(self) -> str:
        return model_utils.PrivateKeySource.as_string(self.private_key_source_id)

    @reify
    def private_key_type(self) -> str:
        return model_utils.PrivateKeyType.as_string(self.private_key_type_id)

    @property
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            # - -
            "autogenerated_calendar_repr": self.autogenerated_calendar_repr,
            "private_key_source": self.private_key_source,
            "private_key_type": self.private_key_type,
            "private_key_id__replaces": self.private_key_id__replaces,
            "is_active": True if self.is_active else False,
            "is_compromised": True if self.is_compromised else False,
            "key_pem_md5": self.key_pem_md5,
            "key_pem": self.key_pem,
            "key_technology": self.key_technology,
            "spki_sha256": self.spki_sha256,
            "timestamp_created": self.timestamp_created_isoformat,
        }


# ==============================================================================


# ==============================================================================


# ==============================================================================


class RemoteIpAddress(Base, _Mixin_Timestamps_Pretty):
    """
    tracking remote ips, we should only see our tests and the letsencrypt service
    """

    __tablename__ = "remote_ip_address"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    remote_ip_address: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )

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


class RenewalConfiguration(
    Base, _Mixin_AcmeAccount_Effective, _Mixin_Timestamps_Pretty
):
    """
    This will be the basis for our renewables
    """

    __table_args__ = (
        sa.CheckConstraint(
            "("
            "(acme_account_id__backup IS NOT NULL AND private_key_technology_id__backup IS NOT NULL AND private_key_cycle_id__backup IS NOT NULL)"
            " OR "
            "(acme_account_id__backup IS NULL AND private_key_technology_id__backup IS NULL AND private_key_cycle_id__backup IS NULL)"
            ")",
            name="check_rc_backup_account",
        ),
    )

    __tablename__ = "renewal_configuration"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)

    label: Mapped[Optional[str]] = mapped_column(sa.Unicode(64), nullable=True)

    # this should always be true; maybe one day it will be a toggle
    is_save_alternate_chains: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=True
    )
    is_export_filesystem_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see .utils.OptionsOnOff

    # core
    uniquely_challenged_fqdn_set_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("uniquely_challenged_fqdn_set.id"), nullable=False
    )
    unique_fqdn_set_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("unique_fqdn_set.id"), nullable=False
    )
    enrollment_factory_id__via: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("enrollment_factory.id"), nullable=True
    )
    system_configuration_id__via: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("system_configuration.id"), nullable=True
    )
    note: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True)
    operations_event_id__created: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )

    # Primary Cert
    acme_account_id__primary: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_account.id"), nullable=False
    )
    private_key_cycle_id__primary: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see .utils.PrivateKeyCycle
    private_key_technology_id__primary: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see .utils.KeyTechnology
    acme_profile__primary: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(64), nullable=True
    )

    # Backup Cert
    acme_account_id__backup: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_account.id"), nullable=True, default=None
    )
    # see .utils.PrivateKeyCycle
    private_key_cycle_id__backup: Mapped[Optional[int]] = mapped_column(
        sa.Integer, nullable=True, default=None
    )
    # see .utils.KeyTechnology
    private_key_technology_id__backup: Mapped[Optional[int]] = mapped_column(
        sa.Integer, nullable=True, default=None
    )
    acme_profile__backup: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(64), nullable=True, default=None
    )

    acme_account__primary = sa_orm_relationship(
        "AcmeAccount",
        primaryjoin="RenewalConfiguration.acme_account_id__primary==AcmeAccount.id",
        uselist=False,
        back_populates="renewal_configurations__primary",
    )
    acme_account__backup = sa_orm_relationship(
        "AcmeAccount",
        primaryjoin="RenewalConfiguration.acme_account_id__backup==AcmeAccount.id",
        uselist=False,
        back_populates="renewal_configurations__backup",
    )
    acme_orders = sa.orm.relationship(
        "AcmeOrder",
        primaryjoin="RenewalConfiguration.id==AcmeOrder.renewal_configuration_id",
        back_populates="renewal_configuration",
        uselist=True,
    )
    enrollment_factory__via = sa_orm_relationship(
        "EnrollmentFactory",
        primaryjoin="RenewalConfiguration.enrollment_factory_id__via==EnrollmentFactory.id",
        uselist=False,
        back_populates="renewal_configurations",
    )
    # only used for reused key cycles
    private_key_reuse = sa_orm_relationship(
        "PrivateKey",
        primaryjoin="RenewalConfiguration.id==PrivateKey.renewal_configuration_id",
        back_populates="renewal_configuration",
        uselist=False,
    )
    system_configuration__via = sa_orm_relationship(
        "SystemConfiguration",
        primaryjoin="RenewalConfiguration.system_configuration_id__via==SystemConfiguration.id",
        uselist=False,
        back_populates="renewal_configurations",
    )
    uniquely_challenged_fqdn_set = sa_orm_relationship(
        "UniquelyChallengedFQDNSet",
        primaryjoin="RenewalConfiguration.uniquely_challenged_fqdn_set_id==UniquelyChallengedFQDNSet.id",
        uselist=False,
        back_populates="renewal_configurations",
    )
    unique_fqdn_set = sa_orm_relationship(
        "UniqueFQDNSet",
        primaryjoin="RenewalConfiguration.unique_fqdn_set_id==UniqueFQDNSet.id",
        uselist=False,
        back_populates="renewal_configurations",
    )

    _domains_challenged: Optional[model_utils.DomainsChallenged] = None

    @property
    def domains_as_list(self) -> List[str]:
        domain_names = [
            to_d.domain.domain_name.lower() for to_d in self.unique_fqdn_set.to_domains
        ]
        domain_names = list(set(domain_names))
        domain_names = sorted(domain_names)
        return domain_names

    def domains_challenged_liststr(self, acme_challenge_type: str) -> str:
        domain_names = self.domains_challenged[acme_challenge_type] or []
        domain_names = list(set(domain_names))
        domain_names = sorted(domain_names)
        _domain_names = ", ".join(domain_names)
        return _domain_names

    @property
    def domains_challenged(self) -> model_utils.DomainsChallenged:
        if self._domains_challenged is None:
            _domains_challenged = model_utils.DomainsChallenged()
            for _specified in self.uniquely_challenged_fqdn_set.to_domains:
                _domain_name = _specified.domain.domain_name
                _acme_challenge_type = _specified.acme_challenge_type
                if _domains_challenged[_acme_challenge_type] is None:
                    _domains_challenged[_acme_challenge_type] = []
                _domains_challenged[_acme_challenge_type].append(_domain_name)
            self._domains_challenged = _domains_challenged
        return self._domains_challenged

    @property
    def is_export_filesystem(self) -> str:
        return model_utils.OptionsOnOff.as_string(self.is_export_filesystem_id)

    @property
    def private_key_technology__primary(self) -> str:
        return model_utils.KeyTechnology.as_string(
            self.private_key_technology_id__primary
        )

    @property
    def private_key_cycle__primary(self) -> str:
        return model_utils.PrivateKeyCycle.as_string(self.private_key_cycle_id__primary)

    @property
    def private_key_technology__backup(self) -> Optional[str]:
        if self.private_key_technology_id__backup is None:
            return None
        return model_utils.KeyTechnology.as_string(
            self.private_key_technology_id__backup
        )

    @property
    def private_key_cycle__backup(self) -> Optional[str]:
        if self.private_key_cycle_id__backup is None:
            return None
        return model_utils.PrivateKeyCycle.as_string(self.private_key_cycle_id__backup)

    @property
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            # - -
            "CertificateSigneds_5_primary": [
                i.as_json_replaces_candidate
                for i in self.certificate_signeds__primary__5
            ],
            "CertificateSigneds_5_backup": [
                i.as_json_replaces_candidate
                for i in self.certificate_signeds__backup__5
            ],
            "AcmeChallenge_hints": {
                "dns-01": self.uniquely_challenged_fqdn_set.as_json__dns01,
            },
            # - -
            "acme_account_id__primary": self.acme_account_id__primary,
            "acme_account_id__backup": self.acme_account_id__backup,
            "acme_profile__primary": self.acme_profile__primary,
            "acme_profile__primary__effective": self.acme_profile__primary__effective,
            "acme_profile__backup": self.acme_profile__backup,
            "acme_profile__backup__effective": self.acme_profile__backup__effective,
            "domains_challenged": self.domains_challenged,
            "is_active": self.is_active,
            "label": self.label,
            "note": self.note,
            "private_key_cycle__primary": self.private_key_cycle__primary,
            "private_key_cycle__primary__effective": self.private_key_cycle__primary__effective,
            "private_key_cycle__backup": self.private_key_cycle__backup,
            "private_key_cycle__backup__effective": self.private_key_cycle__backup__effective,
            "private_key_technology__primary": self.private_key_technology__primary,
            "private_key_technology__primary__effective": self.private_key_technology__primary__effective,
            "private_key_technology__backup": self.private_key_technology__backup,
            "private_key_technology__backup__effective": self.private_key_technology__backup__effective,
            "unique_fqdn_set_id": self.unique_fqdn_set_id,
            "uniquely_challenged_fqdn_set_id": self.uniquely_challenged_fqdn_set_id,
        }

    @property
    def as_json_docs(self) -> Dict:
        rval = self.as_json
        rval["AcmeAccounts"] = {
            "primary": (
                self.acme_account__primary.as_json_minimal
                if self.acme_account__primary
                else None
            ),
            "backup": (
                self.acme_account__backup.as_json_minimal
                if self.acme_account__backup
                else None
            ),
        }
        return rval


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

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    name: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    root_store_versions = sa_orm_relationship(
        "RootStoreVersion",
        primaryjoin="RootStore.id==RootStoreVersion.root_store_id",
        back_populates="root_store",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            # - -
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

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    root_store_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("root_store.id"), nullable=False
    )
    version_string: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )

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
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            # - -
            "name": self.root_store.name,
            "version_string": self.version_string,
        }


class RootStoreVersion_2_CertificateCA(Base, _Mixin_Timestamps_Pretty):
    __tablename__ = "root_store_version_2_certificate_ca"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    root_store_version_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("root_store_version.id"), nullable=False
    )
    certificate_ca_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("certificate_ca.id"), nullable=False
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    certificate_ca = sa_orm_relationship(
        "CertificateCA",
        primaryjoin="RootStoreVersion_2_CertificateCA.certificate_ca_id==CertificateCA.id",
        uselist=False,
        back_populates="to_root_store_versions",
    )
    root_store_version = sa_orm_relationship(
        "RootStoreVersion",
        primaryjoin="RootStoreVersion_2_CertificateCA.root_store_version_id==RootStoreVersion.id",
        uselist=False,
        back_populates="to_certificate_cas",
    )


# ==============================================================================


class SystemConfiguration(Base, _Mixin_AcmeAccount_Effective):

    __tablename__ = "system_configuration"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    name: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False, unique=True)
    is_configured: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=True, default=False
    )

    # Primary Cert
    acme_account_id__primary: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_account.id"), nullable=False
    )
    private_key_technology_id__primary: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see .utils.KeyTechnology
    private_key_cycle_id__primary: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # see .utils.PrivateKeyCycle
    acme_profile__primary: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(64), nullable=True
    )

    # Backup Cert
    acme_account_id__backup: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("acme_account.id"), nullable=True
    )
    private_key_technology_id__backup: Mapped[Optional[int]] = mapped_column(
        sa.Integer,
        nullable=True,
        default=None,
    )  # see .utils.KeyTechnology
    private_key_cycle_id__backup: Mapped[Optional[int]] = mapped_column(
        sa.Integer,
        nullable=True,
        default=None,
    )  # see .utils.PrivateKeyCycle
    acme_profile__backup: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(64),
        nullable=True,
        default=None,
    )

    acme_account__primary = sa_orm_relationship(
        "AcmeAccount",
        primaryjoin="SystemConfiguration.acme_account_id__primary==AcmeAccount.id",
        uselist=False,
        back_populates="system_configurations__primary",
    )
    acme_account__backup = sa_orm_relationship(
        "AcmeAccount",
        primaryjoin="SystemConfiguration.acme_account_id__backup==AcmeAccount.id",
        uselist=False,
        back_populates="system_configurations__backup",
    )
    renewal_configurations = sa_orm_relationship(
        "RenewalConfiguration",
        primaryjoin="SystemConfiguration.id==RenewalConfiguration.system_configuration_id__via",
        back_populates="system_configuration__via",
    )

    @property
    def private_key_technology__primary(self) -> str:
        return model_utils.KeyTechnology.as_string(
            self.private_key_technology_id__primary
        )

    @property
    def private_key_technology__backup(self) -> Optional[str]:
        if self.private_key_technology_id__backup is None:
            return None
        return model_utils.KeyTechnology.as_string(
            self.private_key_technology_id__backup
        )

    @property
    def private_key_cycle__primary(self) -> str:
        return model_utils.PrivateKeyCycle.as_string(self.private_key_cycle_id__primary)

    @property
    def private_key_cycle__backup(self) -> Optional[str]:
        if self.private_key_cycle_id__backup is None:
            return None
        return model_utils.PrivateKeyCycle.as_string(self.private_key_cycle_id__backup)

    @property
    def slug(self) -> Union[str, int]:
        return self.name or self.id

    @property
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            # - -
            "acme_account_id__primary": self.acme_account_id__primary,
            "acme_account_id__backup": self.acme_account_id__backup,
            "acme_profile__primary": self.acme_profile__primary,
            "acme_profile__primary__effective": self.acme_profile__primary__effective,
            "acme_profile__backup": self.acme_profile__backup,
            "acme_profile__backup__effective": self.acme_profile__backup__effective,
            "is_configured": self.is_configured,
            "private_key_technology__primary": self.private_key_technology__primary,
            "private_key_technology__primary__effective": self.private_key_technology__primary__effective,
            "private_key_technology__backup": self.private_key_technology__backup,
            "private_key_technology__backup__effective": self.private_key_technology__backup__effective,
            "private_key_cycle__primary": self.private_key_cycle__primary,
            "private_key_cycle__primary__effective": self.private_key_cycle__primary__effective,
            "private_key_cycle__backup": self.private_key_cycle__backup,
            "private_key_cycle__backup__effective": self.private_key_cycle__backup__effective,
        }

    @property
    def as_json_docs(self) -> Dict:
        rval = self.as_json
        rval["AcmeAccounts"] = {
            "primary": (
                self.acme_account__primary.as_json_minimal
                if self.acme_account__primary
                else None
            ),
            "backup": (
                self.acme_account__backup.as_json_minimal
                if self.acme_account__backup
                else None
            ),
        }
        return rval


class RoutineExecution(Base, _Mixin_Timestamps_Pretty):
    __tablename__ = "routine_execution"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    routine_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # model_utils.Routine
    timestamp_start: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    timestamp_end: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    count_records_processed: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    count_records_success: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    count_records_fail: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    duration_seconds: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    average_speed: Mapped[float] = mapped_column(sa.Float, nullable=False)
    routine_execution_id__via: Mapped[Optional[int]] = mapped_column(
        sa.Integer, sa.ForeignKey("routine_execution.id"), nullable=True
    )

    @property
    def routine(self) -> str:
        return model_utils.Routine.as_string(self.routine_id)

    @property
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            # - -
            "routine_id": self.routine_id,
            "timestamp_start": self.timestamp_start_isoformat,
            "timestamp_end": self.timestamp_end_isoformat,
            "count_records_processed": self.count_records_processed,
            "duration_seconds": self.duration_seconds,
            "average_speed": self.average_speed,
            "routine_execution_id__via": self.routine_execution_id__via,
        }


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
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    domain_ids_string: Mapped[str] = mapped_column(sa.Text, nullable=False, unique=True)
    count_domains: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    operations_event_id__created: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )
    discovery_type: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(255), nullable=True, default=None
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
    renewal_configurations = sa_orm_relationship(
        "RenewalConfiguration",
        primaryjoin="UniqueFQDNSet.id==RenewalConfiguration.unique_fqdn_set_id",
        back_populates="unique_fqdn_set",
    )
    to_domains = sa_orm_relationship(
        "UniqueFQDNSet2Domain",
        primaryjoin="UniqueFQDNSet.id==UniqueFQDNSet2Domain.unique_fqdn_set_id",
        back_populates="unique_fqdn_set",
    )
    uniquely_challenged_fqdn_sets = sa_orm_relationship(
        "UniquelyChallengedFQDNSet",
        primaryjoin="UniqueFQDNSet.id==UniquelyChallengedFQDNSet.unique_fqdn_set_id",
        back_populates="unique_fqdn_set",
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def domains(self) -> List["Domain"]:
        return [to_d.domain for to_d in self.to_domains]

    @property
    def domains_as_string(self) -> str:
        domains = sorted([to_d.domain.domain_name for to_d in self.to_domains])
        return ", ".join(domains)

    @property
    def domains_as_list(self) -> List[str]:
        domain_names = [to_d.domain.domain_name.lower() for to_d in self.to_domains]
        domain_names = list(set(domain_names))
        domain_names = sorted(domain_names)
        return domain_names

    @property
    def domain_objects(self) -> Dict[str, "Domain"]:
        domain_objects = {
            to_d.domain.domain_name.lower(): to_d.domain for to_d in self.to_domains
        }
        return domain_objects

    @property
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            # - -
            "count_domains": self.count_domains,
            "domains_as_list": self.domains_as_list,
            "timestamp_created": self.timestamp_created_isoformat,
        }


# ==============================================================================


class UniqueFQDNSet2Domain(Base):
    """
    association table
    """

    # note: RATELIMIT.FQDN

    __tablename__ = "unique_fqdn_set_2_domain"
    unique_fqdn_set_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("unique_fqdn_set.id"), primary_key=True
    )
    domain_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("domain.id"), primary_key=True
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    domain = sa_orm_relationship(
        "Domain",
        primaryjoin="UniqueFQDNSet2Domain.domain_id==Domain.id",
        uselist=False,
    )
    unique_fqdn_set = sa_orm_relationship(
        "UniqueFQDNSet",
        primaryjoin="UniqueFQDNSet2Domain.unique_fqdn_set_id==UniqueFQDNSet.id",
        uselist=False,
        back_populates="to_domains",
    )


# ==============================================================================


class UniquelyChallengedFQDNSet(Base, _Mixin_Timestamps_Pretty):
    __tablename__ = "uniquely_challenged_fqdn_set"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    unique_fqdn_set_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("unique_fqdn_set.id"), nullable=False
    )
    domain_challenges_serialized: Mapped[str] = mapped_column(
        sa.Text, nullable=False, unique=True
    )
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        TZDateTime(timezone=True), nullable=False
    )
    operations_event_id__created: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("operations_event.id"), nullable=False
    )
    discovery_type: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(255), nullable=True, default=None
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    acme_orders = sa_orm_relationship(
        "AcmeOrder",
        primaryjoin="UniquelyChallengedFQDNSet.id==AcmeOrder.uniquely_challenged_fqdn_set_id",
        back_populates="uniquely_challenged_fqdn_set",
    )
    operations_object_events = sa_orm_relationship(
        "OperationsObjectEvent",
        primaryjoin="UniquelyChallengedFQDNSet.id==OperationsObjectEvent.uniquely_challenged_fqdn_set_id",
        back_populates="uniquely_challenged_fqdn_set",
    )
    renewal_configurations = sa_orm_relationship(
        "RenewalConfiguration",
        primaryjoin="UniquelyChallengedFQDNSet.id==RenewalConfiguration.uniquely_challenged_fqdn_set_id",
        back_populates="uniquely_challenged_fqdn_set",
    )
    to_domains = sa_orm_relationship(
        "UniquelyChallengedFQDNSet2Domain",
        primaryjoin="UniquelyChallengedFQDNSet.id==UniquelyChallengedFQDNSet2Domain.uniquely_challenged_fqdn_set_id",
        back_populates="uniquely_challenged_fqdn_set",
    )
    to_domains__dns_01 = sa_orm_relationship(
        "UniquelyChallengedFQDNSet2Domain",
        primaryjoin=(
            "and_("
            "UniquelyChallengedFQDNSet.id==UniquelyChallengedFQDNSet2Domain.uniquely_challenged_fqdn_set_id,"
            "UniquelyChallengedFQDNSet2Domain.acme_challenge_type_id==%s"
            ")" % model_utils.AcmeChallengeType.dns_01
        ),
        viewonly=True,
    )
    to_domains__http_01 = sa_orm_relationship(
        "UniquelyChallengedFQDNSet2Domain",
        primaryjoin=(
            "and_("
            "UniquelyChallengedFQDNSet.id==UniquelyChallengedFQDNSet2Domain.uniquely_challenged_fqdn_set_id,"
            "UniquelyChallengedFQDNSet2Domain.acme_challenge_type_id==%s"
            ")" % model_utils.AcmeChallengeType.http_01
        ),
        viewonly=True,
    )
    unique_fqdn_set = sa_orm_relationship(
        "UniqueFQDNSet",
        primaryjoin="UniquelyChallengedFQDNSet.unique_fqdn_set_id==UniqueFQDNSet.id",
        back_populates="uniquely_challenged_fqdn_sets",
        uselist=False,
    )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    _domains_mapping__id: Optional[Dict[int, Domain]] = None

    def _load_domains(self):
        if self._domains_mapping__id is None:
            _domains_mapping__id = {}
            for to_d in self.to_domains:
                _domains_mapping__id[to_d.domain.id] = to_d.domain
            self._domains_mapping__id = _domains_mapping__id

    def _deserialize_domain_ids(self) -> Dict:
        rval: Dict[str, List[int]] = {}
        _chall2ids = self.domain_challenges_serialized.split(";")
        for _chall2id in _chall2ids:
            chall, _domain_ids = _chall2id.split(":")
            domain_ids = [int(i) for i in _domain_ids.split(",")]
            rval[chall] = domain_ids
        return rval

    @property
    def domain_objects(self) -> Dict[str, List["Domain"]]:
        self._load_domains()
        assert self._domains_mapping__id is not None
        _deserialized = self._deserialize_domain_ids()
        rval: Dict[str, List["Domain"]] = {}
        for chall in sorted(_deserialized.keys()):
            rval[chall] = []
            for id_ in _deserialized[chall]:
                rval[chall].append(self._domains_mapping__id[id_])
        return rval

    @property
    def domain_names(self) -> Dict[str, List[str]]:
        self._load_domains()
        assert self._domains_mapping__id is not None
        _deserialized = self._deserialize_domain_ids()
        rval: Dict[str, List[str]] = {}
        for chall in sorted(_deserialized.keys()):
            rval[chall] = []
            for id_ in _deserialized[chall]:
                rval[chall].append(self._domains_mapping__id[id_].domain_name)
            rval[chall] = sorted(rval[chall])
        return rval

    @property
    def domains_challenged(self) -> model_utils.DomainsChallenged:
        domains_challenged = model_utils.DomainsChallenged()
        for to_d in self.to_domains:
            _domain_name = to_d.domain.domain_name
            _acme_challenge_type = to_d.acme_challenge_type
            if domains_challenged[_acme_challenge_type] is None:
                domains_challenged[_acme_challenge_type] = []
            domains_challenged[_acme_challenge_type].append(_domain_name)
        return domains_challenged

    @property
    def as_json(self) -> Dict:
        return {
            "id": self.id,
            # - -
            "discovery_type": self.discovery_type,
            "domain_challenges_serialized": self.domain_challenges_serialized,
            "timestamp_created": self.timestamp_created_isoformat,
            "unique_fqdn_set_id": self.unique_fqdn_set_id,
            # - -
            "as_json__dns01": self.as_json__dns01,
        }

    @property
    def as_json__dns01(self) -> Dict:
        rval = {}
        for to_domain in self.to_domains:
            if to_domain.acme_challenge_type_id == model_utils.AcmeChallengeType.dns_01:
                rval[to_domain.domain.domain_name] = {
                    "id": to_domain.domain.id,
                    "domain_name": to_domain.domain.domain_name,
                    "acme_dns_server_accounts_5": to_domain.domain.as_json__acme_dns_server_accounts_5,
                }

        return rval


class UniquelyChallengedFQDNSet2Domain(Base):
    """
    association table
    """

    # note: RATELIMIT.FQDN

    __tablename__ = "uniquely_challenged_fqdn_set_2_domain"
    uniquely_challenged_fqdn_set_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("uniquely_challenged_fqdn_set.id"), primary_key=True
    )
    domain_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("domain.id"), primary_key=True
    )
    acme_challenge_type_id: Mapped[int] = mapped_column(
        sa.Integer, nullable=False
    )  # `model_utils.AcmeChallengeType`

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def acme_challenge_type(self) -> Optional[str]:
        if self.acme_challenge_type_id:
            return model_utils.AcmeChallengeType.as_string(self.acme_challenge_type_id)
        return None

    domain = sa_orm_relationship(
        "Domain",
        primaryjoin="UniquelyChallengedFQDNSet2Domain.domain_id==Domain.id",
        uselist=False,
    )
    uniquely_challenged_fqdn_set = sa_orm_relationship(
        "UniquelyChallengedFQDNSet",
        primaryjoin="UniquelyChallengedFQDNSet2Domain.uniquely_challenged_fqdn_set_id==UniquelyChallengedFQDNSet.id",
        uselist=False,
        back_populates="to_domains",
    )

    @property
    def as_json(self) -> Dict:
        return {
            "acme_challenge_type": self.acme_challenge_type,
            "domain_id": self.domain_id,
            "uniquely_challenged_fqdn_set_id": self.uniquely_challenged_fqdn_set_id,
        }


# ==============================================================================

__all__ = (
    "AcmeAccount",
    "AcmeAccount_2_TermsOfService",
    "AcmeAccountKey",
    "AcmeServer",
    "AcmeServerConfiguration",
    "AcmeAuthorization",
    "AcmeAuthorizationPotential",
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
    "AriCheck",
    "CertificateCA",
    "CertificateCAChain",
    "CertificateCAPreference",
    "CertificateCAPreferencePolicy",
    "CertificateCAReconciliation",
    "CertificateRequest",
    "CertificateSigned",
    "CertificateSignedChain",
    "CoverageAssuranceEvent",
    "Domain",
    "DomainAutocert",
    "DomainBlocklisted",
    "EnrollmentFactory",
    "SystemConfiguration",
    "Notification",
    "OperationsEvent",
    "OperationsObjectEvent",
    "PrivateKey",
    "RemoteIpAddress",
    "RenewalConfiguration",
    "RootStore",
    "RootStoreVersion",
    "RootStoreVersion_2_CertificateCA",
    "RoutineExecution",
    "UniquelyChallengedFQDNSet",
    "UniquelyChallengedFQDNSet2Domain",
    "UniqueFQDNSet",
    "UniqueFQDNSet2Domain",
)
