# local
from ...lib import utils as lib_utils

# ==============================================================================


class _Mixin_Hex_Pretty(object):
    @property
    def cert_authority_key_identifier__colon(self):
        return lib_utils.hex_with_colons(self.cert_authority_key_identifier)

    @property
    def fingerprint_sha1__colon(self):
        if self.fingerprint_sha1:
            return lib_utils.hex_with_colons(self.fingerprint_sha1)
        return ""

    @property
    def spki_sha256__colon(self):
        return lib_utils.hex_with_colons(self.spki_sha256)


class _Mixin_Timestamps_Pretty(object):
    @property
    def timestamp_created_isoformat(self):
        if self.timestamp_created:
            return self.timestamp_created.isoformat()
        return None

    @property
    def timestamp_event_isoformat(self):
        if self.timestamp_event:
            return self.timestamp_event.isoformat()
        return None

    @property
    def timestamp_expires_isoformat(self):
        if self.timestamp_expires:
            return self.timestamp_expires.isoformat()
        return None

    @property
    def timestamp_finalized_isoformat(self):
        if self.timestamp_finalized:
            return self.timestamp_finalized.isoformat()
        return None

    @property
    def timestamp_finished_isoformat(self):
        if self.timestamp_finished:
            return self.timestamp_finished.isoformat()
        return None

    @property
    def timestamp_not_after_isoformat(self):
        if self.timestamp_not_after:
            return self.timestamp_not_after.isoformat()
        return None

    @property
    def timestamp_not_before_isoformat(self):
        if self.timestamp_not_before:
            return self.timestamp_not_before.isoformat()
        return None

    @property
    def timestamp_polled_isoformat(self):
        if self.timestamp_polled:
            return self.timestamp_polled.isoformat()
        return None

    @property
    def timestamp_processed_isoformat(self):
        if self.timestamp_processed:
            return self.timestamp_processed.isoformat()
        return None

    @property
    def timestamp_process_attempt_isoformat(self):
        if self.timestamp_process_attempt:
            return self.timestamp_process_attempt.isoformat()
        return None

    @property
    def timestamp_revoked_upstream_isoformat(self):
        if self.timestamp_revoked_upstream:
            return self.timestamp_revoked_upstream.isoformat()
        return None

    @property
    def timestamp_updated_isoformat(self):
        if self.timestamp_updated:
            return self.timestamp_updated.isoformat()
        return None


# ==============================================================================


__all__ = (
    "_Mixin_Hex_Pretty",
    "_Mixin_Timestamps_Pretty",
)
