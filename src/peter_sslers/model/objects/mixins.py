# stdlib
import datetime
from typing import Optional

# pypi
import cert_utils

# ==============================================================================


class _Mixin_Hex_Pretty(object):
    # While it would be nice to have `Mapped` typing on these,
    # it can create issues as SqlAlchemy thinks all fields are columns and
    # will try to utilize them in sql operations
    """
    cert_authority_key_identifier: Optional[str]
    fingerprint_sha1: str
    spki_sha256: str
    """

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
    """
    timestamp_created: datetime.datetime
    timestamp_event: Optional[datetime.datetime]
    timestamp_expires: Optional[datetime.datetime]
    timestamp_finalized: Optional[datetime.datetime]
    timestamp_finished: Optional[datetime.datetime]
    timestamp_not_after: Optional[datetime.datetime]
    timestamp_not_before: Optional[datetime.datetime]
    timestamp_polled: Optional[datetime.datetime]
    timestamp_processed: Optional[datetime.datetime]
    timestamp_process_attempt: Optional[datetime.datetime]
    timestamp_revoked_upstream: Optional[datetime.datetime]
    timestamp_updated: Optional[datetime.datetime]
    """

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
    "_Mixin_Hex_Pretty",
    "_Mixin_Timestamps_Pretty",
)
