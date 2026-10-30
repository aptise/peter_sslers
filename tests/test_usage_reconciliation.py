import pytest
import sqlalchemy as sa

from peter_sslers.lib.db.actions import _reconcile_usage_counts
from peter_sslers.model.objects import PrivateKey, X509Certificate
from .test_certificate_expiry import context


@pytest.fixture
def usage_context(context):
    session = context.dbSession
    PrivateKey.__table__.create(session.get_bind())
    for identity in (1, 2):
        session.execute(sa.insert(PrivateKey).values(
            id=identity, timestamp_created=context.timestamp, key_technology_id=4,
            key_pem="key", key_pem_md5=str(identity), spki_sha256="spki",
            operations_event_id__created=1, private_key_source_id=1, private_key_type_id=1,
            count_active_certificates=99, count_x509_certificates=99, count_acme_orders=99,
        ))
    for statement in (
        "CREATE TABLE acme_account (id INTEGER PRIMARY KEY, count_acme_orders INTEGER, count_x509_certificates INTEGER)",
        "INSERT INTO acme_account VALUES (11,99,99),(12,99,99),(13,99,99)",
        "CREATE TABLE acme_order (id INTEGER PRIMARY KEY, private_key_id INTEGER, acme_account_id INTEGER, x509_certificate_id INTEGER)",
        "INSERT INTO acme_order VALUES (1,1,11,1),(2,1,11,1),(3,2,12,NULL)",
        "CREATE TABLE x509_certificate_trusted (id INTEGER PRIMARY KEY, count_active_certificates INTEGER)",
        "INSERT INTO x509_certificate_trusted VALUES (21,99),(22,99),(23,99)",
        "CREATE TABLE x509_certificate_trust_chain (id INTEGER PRIMARY KEY, x509_certificate_trusted_0_id INTEGER)",
        "INSERT INTO x509_certificate_trust_chain VALUES (100,21),(101,21),(200,22)",
        "CREATE TABLE x509_certificate_chain (x509_certificate_id INTEGER, x509_certificate_trust_chain_id INTEGER)",
        "INSERT INTO x509_certificate_chain VALUES (1,100),(1,101),(4,100),(2,200),(3,200)",
    ):
        session.execute(sa.text(statement))
    session.commit()
    return context


def test_reconciliation_counts_distinct_active_certificates_and_refreshes_loaded_keys(usage_context):
    session = usage_context.dbSession
    key = session.get(PrivateKey, 1)
    assert key.count_active_certificates == 99
    _reconcile_usage_counts(usage_context)
    assert (key.count_active_certificates, key.count_x509_certificates, key.count_acme_orders) == (4, 5, 2)
    unused_key = session.get(PrivateKey, 2)
    assert (unused_key.count_active_certificates, unused_key.count_x509_certificates, unused_key.count_acme_orders) == (0, 0, 1)
    assert session.execute(sa.text("SELECT id,count_active_certificates FROM x509_certificate_trusted ORDER BY id")).all() == [(21,1),(22,2),(23,0)]
    assert session.execute(sa.text("SELECT id,count_acme_orders,count_x509_certificates FROM acme_account ORDER BY id")).all() == [(11,2,1),(12,1,0),(13,0,0)]


def test_reconciliation_flushes_pending_deactivation_and_preserves_rollback(usage_context):
    session = usage_context.dbSession
    session.get(X509Certificate, 1).is_active = False
    _reconcile_usage_counts(usage_context)
    assert session.get(PrivateKey, 1).count_active_certificates == 3
    assert session.execute(sa.text("SELECT count_active_certificates FROM x509_certificate_trusted WHERE id=21")).scalar_one() == 0
    session.rollback()
    assert session.get(X509Certificate, 1).is_active is True
    assert session.get(PrivateKey, 1).count_active_certificates == 99


def test_reconciliation_drives_active_key_selection_and_is_repeatable(usage_context):
    from peter_sslers.lib.db import get

    session = usage_context.dbSession
    _reconcile_usage_counts(usage_context)
    assert [key.id for key in get.get__PrivateKey__paginated(usage_context, active_usage_only=True)] == [1]
    session.execute(sa.update(X509Certificate).values(is_active=False))
    for _ in range(2):
        _reconcile_usage_counts(usage_context)
        assert get.get__PrivateKey__paginated(usage_context, active_usage_only=True) == []
        assert session.execute(sa.text("SELECT count_active_certificates FROM x509_certificate_trusted ORDER BY id")).scalars().all() == [0, 0, 0]
        assert session.get(PrivateKey, 1).count_x509_certificates == 5


def test_global_refresh_updates_pointers_and_usage_in_one_transaction(usage_context, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock
    from peter_sslers.lib.db import actions
    from peter_sslers.model.objects import Domain, UniqueFQDNSet2Domain

    session = usage_context.dbSession
    UniqueFQDNSet2Domain.__table__.create(session.get_bind())
    session.execute(sa.insert(UniqueFQDNSet2Domain).values(unique_fqdn_set_id=1, domain_id=1))
    session.execute(sa.update(X509Certificate).values(is_single_domain_cert=True))
    session.commit()
    domain = session.get(Domain, 1)
    assert domain.x509_certificate_id__latest_single == 1
    event = SimpleNamespace(id=1)
    monkeypatch.setattr(actions, "log__OperationsEvent", Mock(return_value=event))
    assert actions.operations_update_recents__global(usage_context) is event
    assert domain.x509_certificate_id__latest_single == 3
    assert session.get(PrivateKey, 1).count_active_certificates == 4
    session.rollback()
    assert domain.x509_certificate_id__latest_single == 1
    assert session.get(PrivateKey, 1).count_active_certificates == 99
