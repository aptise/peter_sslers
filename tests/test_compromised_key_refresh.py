from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from peter_sslers.lib import events


@pytest.mark.parametrize("count", [0, 1, 24])
def test_key_compromise_refreshes_all_affected_sets_once(monkeypatch, count):
    fqdn_sets = {identity: SimpleNamespace(id=identity) for identity in (1, 2)}
    certificates = [SimpleNamespace(
        id=identity, unique_fqdn_set_id=1 + identity % 2,
        unique_fqdn_set=fqdn_sets[1 + identity % 2], acme_order=None,
        is_active=True,
    ) for identity in range(count)]
    monkeypatch.setattr(events.lib.db.get, "get__X509Certificate__by_PrivateKeyId__count", Mock(return_value=count))
    pages = Mock(side_effect=[certificates[:20], certificates[20:]])
    monkeypatch.setattr(events.lib.db.get, "get__X509Certificate__by_PrivateKeyId__paginated", pages)
    mark = Mock()
    monkeypatch.setattr(events.db_update, "update_X509Certificate__mark_compromised", mark)
    monkeypatch.setattr(events.db_create, "create__CoverageAssuranceEvent", Mock(return_value=SimpleNamespace(id=1)))
    refresh = Mock()
    monkeypatch.setattr(events.db_actions, "operations_update_recents__domains", refresh)
    context = SimpleNamespace(dbSession=Mock())
    event = SimpleNamespace(id=1, event_payload_json={}, set_event_payload=Mock())
    events.PrivateKey_compromised(context, SimpleNamespace(id=1), event)
    assert mark.call_count == count
    assert refresh.call_count == (1 if count else 0)
    if count:
        sets = list(refresh.call_args.kwargs["dbUniqueFQDNSets"])
        assert {item.id for item in sets} == {item.unique_fqdn_set_id for item in certificates}
        assert event.set_event_payload.call_args.args[0]["x509_certificates.revoked"]["active"] == list(range(count))
    if count > 20:
        assert [call.kwargs["offset"] for call in pages.call_args_list] == [0, 20]
