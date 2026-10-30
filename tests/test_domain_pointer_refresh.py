from __future__ import annotations

from typing import TYPE_CHECKING
from typing import cast

from ._typing import require_row


from types import SimpleNamespace
from typing import List
from typing import Optional
from typing import Tuple
from unittest.mock import Mock

import pytest
import sqlalchemy as sa

from peter_sslers.lib.db import actions
from peter_sslers.model.objects import Domain
from peter_sslers.model.objects import UniqueFQDNSet
from peter_sslers.model.objects import UniqueFQDNSet2Domain
from peter_sslers.model.objects import X509Certificate

from .test_certificate_expiry import context

if TYPE_CHECKING:
    from peter_sslers.lib.context import ApiContext


@pytest.fixture
def refresh_context(
    context: ApiContext, monkeypatch: pytest.MonkeyPatch
) -> Tuple[ApiContext, Mock]:
    session = context.dbSession
    UniqueFQDNSet2Domain.__table__.create(session.get_bind())
    # Each certificate belongs to its own domain; later tests add overlap.
    for identity in range(1, 6):
        session.execute(
            sa.update(X509Certificate)
            .where(X509Certificate.id == identity)
            .values(
                unique_fqdn_set_id=identity,
                is_single_domain_cert=True,
            )
        )
        session.execute(
            sa.insert(UniqueFQDNSet2Domain).values(
                unique_fqdn_set_id=identity, domain_id=identity
            )
        )
    session.commit()
    logger = Mock(return_value=SimpleNamespace(id=1))
    monkeypatch.setattr(actions, "log__OperationsEvent", logger)
    return context, logger


def test_refresh_consumes_generators_once_and_logs_all_affected_domains(
    refresh_context: Tuple[ApiContext, Mock],
) -> None:
    context, logger = refresh_context
    domain = require_row(context.dbSession.get(Domain, 1))
    fqdn_set = cast(UniqueFQDNSet, SimpleNamespace(id=1, domains=[domain]))
    actions.operations_update_recents__domains(
        context, dbUniqueFQDNSets=(item for item in [fqdn_set])
    )
    assert domain.x509_certificate_id__latest_single == 1
    assert logger.call_args.args[2]["domain.ids"] == [1]
    assert logger.call_args.args[2]["unique_fqdn_set.ids"] == [1]


def test_revocation_refresh_clears_loaded_pointer_and_relationship(
    refresh_context: Tuple[ApiContext, Mock],
) -> None:
    context, _ = refresh_context
    domain = require_row(context.dbSession.get(Domain, 1))
    assert domain.x509_certificate__latest_single.id == 1
    context.dbSession.execute(
        sa.update(X509Certificate)
        .where(X509Certificate.id == 1)
        .values(is_active=False)
    )
    actions.operations_update_recents__domains(context, dbDomains=[domain])
    assert domain.x509_certificate_id__latest_single is None
    assert domain.x509_certificate__latest_single is None
    # Another domain must retain its own certificate.
    assert (
        require_row(context.dbSession.get(Domain, 2)).x509_certificate_id__latest_single
        == 2
    )


def test_refresh_prefers_later_expiry_then_larger_id_and_selects_per_domain(
    refresh_context: Tuple[ApiContext, Mock],
) -> None:
    context, _ = refresh_context
    session = context.dbSession
    # Certificate 2 and 3 also cover domain 1, with 3 having later expiry.
    session.execute(
        sa.insert(UniqueFQDNSet2Domain),
        [
            {"unique_fqdn_set_id": 2, "domain_id": 1},
            {"unique_fqdn_set_id": 3, "domain_id": 1},
        ],
    )
    domain = require_row(session.get(Domain, 1))
    actions.operations_update_recents__domains(
        context, dbDomains=[domain, require_row(session.get(Domain, 2))]
    )
    assert domain.x509_certificate_id__latest_single == 3
    assert require_row(session.get(Domain, 2)).x509_certificate_id__latest_single == 2
    expiry = require_row(session.get(X509Certificate, 3)).timestamp_not_after
    session.execute(
        sa.update(X509Certificate)
        .where(X509Certificate.id == 2)
        .values(timestamp_not_after=expiry)
    )
    actions.operations_update_recents__domains(context, dbDomains=[domain])
    assert domain.x509_certificate_id__latest_single == 3
    session.execute(
        sa.update(X509Certificate)
        .where(X509Certificate.id == 3)
        .values(is_active=False)
    )
    actions.operations_update_recents__domains(context, dbDomains=[domain])
    assert domain.x509_certificate_id__latest_single == 2


def test_refresh_keeps_single_and_multi_slots_separate(
    refresh_context: Tuple[ApiContext, Mock],
) -> None:
    context, _ = refresh_context
    session = context.dbSession
    session.execute(
        sa.update(X509Certificate)
        .where(X509Certificate.id == 1)
        .values(is_single_domain_cert=False)
    )
    domain = require_row(session.get(Domain, 1))
    actions.operations_update_recents__domains(context, dbDomains=[domain])
    assert domain.x509_certificate_id__latest_single is None
    assert domain.x509_certificate_id__latest_multi == 1


def test_global_pointer_refresh_sees_pending_state_and_updates_loaded_objects(
    refresh_context: Tuple[ApiContext, Mock],
) -> None:
    context, _ = refresh_context
    session = context.dbSession
    domains = [require_row(session.get(Domain, identity)) for identity in range(1, 6)]
    assert domains[0].x509_certificate__latest_single.id == 1
    require_row(session.get(X509Certificate, 1)).is_active = False
    actions._refresh_domain_certificate_pointers(context)
    assert domains[0].x509_certificate_id__latest_single is None
    assert domains[0].x509_certificate__latest_single is None
    assert domains[1].x509_certificate_id__latest_single == 2
    assert domains[3].x509_certificate_id__latest_single is None
    # Refresh must leave commit control with the caller.
    session.rollback()
    assert require_row(session.get(X509Certificate, 1)).is_active is True
    assert domains[0].x509_certificate_id__latest_single == 1


def test_duplicate_inputs_are_deduplicated_in_event(
    refresh_context: Tuple[ApiContext, Mock],
) -> None:
    context, logger = refresh_context
    domain = require_row(context.dbSession.get(Domain, 1))
    fqdn_set = cast(UniqueFQDNSet, SimpleNamespace(id=1, domains=[domain]))
    actions.operations_update_recents__domains(
        context,
        dbDomains=(item for item in [domain, domain]),
        dbUniqueFQDNSets=(item for item in [fqdn_set, fqdn_set]),
    )
    assert logger.call_args.args[2]["domain.ids"] == [1]
    assert logger.call_args.args[2]["unique_fqdn_set.ids"] == [1]


@pytest.mark.parametrize("domains, sets", [([], []), (None, None)])
def test_empty_refresh_is_rejected(
    refresh_context: Tuple[ApiContext, Mock],
    domains: Optional[List[Domain]],
    sets: Optional[List[UniqueFQDNSet]],
) -> None:
    context, _ = refresh_context
    with pytest.raises(ValueError, match="must submit"):
        actions.operations_update_recents__domains(
            context, dbDomains=domains, dbUniqueFQDNSets=sets
        )
