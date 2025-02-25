# stdlib
import datetime
from typing import Optional
from typing import TYPE_CHECKING

# pypi
import cert_utils
from sqlalchemy.orm import Mapped

# local
from .. import utils as model_utils

if TYPE_CHECKING:
    from .objects import AcmeAccount


# ==============================================================================


class _Mixin_AcmeAccount_Effective(object):

    if TYPE_CHECKING:
        acme_account__backup: Mapped[Optional["AcmeAccount"]]
        acme_account_id__backup: Mapped[Optional[int]]
        acme_account_id: Mapped[int]
        acme_account: Mapped[Optional["AcmeAccount"]]
        acme_profile__backup: Mapped[Optional[str]]
        acme_profile: Mapped[Optional[str]]
        key_technology_id__backup: Mapped[int]
        key_technology_id: Mapped[int]
        private_key_cycle_id__backup: Mapped[int]
        private_key_cycle_id: Mapped[int]

    @property
    def key_technology__effective(self) -> Optional[str]:
        if self.key_technology_id == model_utils.KeyTechnology.ACCOUNT_DEFAULT:
            if not self.acme_account:
                return None
            return self.acme_account.order_default_private_key_technology
        return model_utils.KeyTechnology.as_string(self.key_technology_id)

    @property
    def key_technology_id__effective(self) -> Optional[int]:
        if self.key_technology_id == model_utils.KeyTechnology.ACCOUNT_DEFAULT:
            if not self.acme_account:
                return None
            return self.acme_account.order_default_private_key_technology_id
        return self.key_technology_id

    @property
    def key_technology__backup__effective(self) -> Optional[str]:
        if self.key_technology_id__backup == model_utils.KeyTechnology.ACCOUNT_DEFAULT:
            if not self.acme_account__backup:
                return None
            return self.acme_account__backup.order_default_private_key_technology
        return model_utils.KeyTechnology.as_string(self.key_technology_id__backup)

    @property
    def key_technology_id__backup__effective(self) -> Optional[int]:
        if self.key_technology_id__backup == model_utils.KeyTechnology.ACCOUNT_DEFAULT:
            if not self.acme_account__backup:
                return None
            return self.acme_account__backup.order_default_private_key_technology_id
        return self.key_technology_id__backup

    @property
    def private_key_cycle__effective(self) -> Optional[str]:
        if self.private_key_cycle_id == model_utils.PrivateKeyCycle.ACCOUNT_DEFAULT:
            if not self.acme_account:
                return None
            return self.acme_account.order_default_private_key_cycle
        return model_utils.PrivateKeyCycle.as_string(self.private_key_cycle_id)

    @property
    def private_key_cycle_id__effective(self) -> Optional[int]:
        if self.private_key_cycle_id == model_utils.PrivateKeyCycle.ACCOUNT_DEFAULT:
            if not self.acme_account:
                return None
            return self.acme_account.order_default_private_key_cycle_id
        return self.private_key_cycle_id

    @property
    def private_key_cycle__backup__effective(self) -> Optional[str]:
        if (
            self.private_key_cycle_id__backup
            == model_utils.PrivateKeyCycle.ACCOUNT_DEFAULT
        ):
            if not self.acme_account__backup:
                return None
            return self.acme_account__backup.order_default_private_key_cycle
        return model_utils.PrivateKeyCycle.as_string(self.private_key_cycle_id__backup)

    @property
    def private_key_cycle_id__backup__effective(self) -> Optional[int]:
        if (
            self.private_key_cycle_id__backup
            == model_utils.PrivateKeyCycle.ACCOUNT_DEFAULT
        ):
            if not self.acme_account__backup:
                return None
            return self.acme_account__backup.order_default_private_key_cycle_id
        return self.private_key_cycle_id__backup

    @property
    def acme_profile__effective(self) -> Optional[str]:
        if self.acme_profile == "*ACCOUNT_DEFAULT*":
            if not self.acme_account:
                return None
            return self.acme_account.order_default_acme_profile
        return self.acme_profile

    @property
    def acme_profile__backup__effective(self) -> Optional[str]:
        if self.acme_profile__backup == "*ACCOUNT_DEFAULT*":
            if not self.acme_account__backup:
                return None
            return self.acme_account__backup.order_default_acme_profile
        return self.acme_profile__backup


class _Mixin_Hex_Pretty(object):
    # While it would be nice to have `Mapped` typing on these,
    # it can create issues as SqlAlchemy thinks all fields are columns and
    # will try to utilize them in sql operations
    if TYPE_CHECKING:
        cert_authority_key_identifier: Mapped[Optional[str]]
        fingerprint_sha1: Mapped[str]
        spki_sha256: Mapped[str]

    @property
    def cert_authority_key_identifier__colon(self) -> str:
        if not self.cert_authority_key_identifier:
            return ""
        return cert_utils.utils.hex_with_colons(self.cert_authority_key_identifier)

    @property
    def fingerprint_sha1__colon(self) -> str:
        if self.fingerprint_sha1:
            return cert_utils.utils.hex_with_colons(self.fingerprint_sha1)
        return ""

    @property
    def spki_sha256__colon(self) -> str:
        return cert_utils.utils.hex_with_colons(self.spki_sha256)


class _Mixin_Timestamps_Pretty(object):
    # While it would be nice to have `Mapped` typing on these,
    # it can create issues as SqlAlchemy thinks all fields are columns and
    # will try to utilize them in sql operations
    if TYPE_CHECKING:
        timestamp_created: Mapped[datetime.datetime]
        timestamp_event: Mapped[Optional[datetime.datetime]]
        timestamp_expires: Mapped[Optional[datetime.datetime]]
        timestamp_finalized: Mapped[Optional[datetime.datetime]]
        timestamp_finished: Mapped[Optional[datetime.datetime]]
        timestamp_not_after: Mapped[Optional[datetime.datetime]]
        timestamp_not_before: Mapped[Optional[datetime.datetime]]
        timestamp_polled: Mapped[Optional[datetime.datetime]]
        timestamp_processed: Mapped[Optional[datetime.datetime]]
        timestamp_process_attempt: Mapped[Optional[datetime.datetime]]
        timestamp_revoked_upstream: Mapped[Optional[datetime.datetime]]
        timestamp_updated: Mapped[Optional[datetime.datetime]]

    @property
    def timestamp_created_isoformat(self) -> Optional[str]:
        if self.timestamp_created:
            return self.timestamp_created.isoformat()
        return None

    @property
    def timestamp_event_isoformat(self) -> Optional[str]:
        if self.timestamp_event:
            return self.timestamp_event.isoformat()
        return None

    @property
    def timestamp_expires_isoformat(self) -> Optional[str]:
        if self.timestamp_expires:
            return self.timestamp_expires.isoformat()
        return None

    @property
    def timestamp_finalized_isoformat(self) -> Optional[str]:
        if self.timestamp_finalized:
            return self.timestamp_finalized.isoformat()
        return None

    @property
    def timestamp_finished_isoformat(self) -> Optional[str]:
        if self.timestamp_finished:
            return self.timestamp_finished.isoformat()
        return None

    @property
    def timestamp_not_after_isoformat(self) -> Optional[str]:
        if self.timestamp_not_after:
            return self.timestamp_not_after.isoformat()
        return None

    @property
    def timestamp_not_before_isoformat(self) -> Optional[str]:
        if self.timestamp_not_before:
            return self.timestamp_not_before.isoformat()
        return None

    @property
    def timestamp_polled_isoformat(self) -> Optional[str]:
        if self.timestamp_polled:
            return self.timestamp_polled.isoformat()
        return None

    @property
    def timestamp_processed_isoformat(self) -> Optional[str]:
        if self.timestamp_processed:
            return self.timestamp_processed.isoformat()
        return None

    @property
    def timestamp_process_attempt_isoformat(self) -> Optional[str]:
        if self.timestamp_process_attempt:
            return self.timestamp_process_attempt.isoformat()
        return None

    @property
    def timestamp_revoked_upstream_isoformat(self) -> Optional[str]:
        if self.timestamp_revoked_upstream:
            return self.timestamp_revoked_upstream.isoformat()
        return None

    @property
    def timestamp_updated_isoformat(self) -> Optional[str]:
        if self.timestamp_updated:
            return self.timestamp_updated.isoformat()
        return None


# ==============================================================================


__all__ = (
    "_Mixin_AcmeAccount_Effective",
    "_Mixin_Hex_Pretty",
    "_Mixin_Timestamps_Pretty",
)
