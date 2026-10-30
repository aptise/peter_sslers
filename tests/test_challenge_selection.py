"""A DNS-only order must skip an absent HTTP challenge list."""

from types import SimpleNamespace
from typing import cast
from typing import TYPE_CHECKING

import pytest

from peter_sslers.model import utils

if TYPE_CHECKING:
    from peter_sslers.lib.context import ApiContext
    from peter_sslers.model.objects import AcmeOrder


@pytest.mark.parametrize("challenge", ["http-01", "dns-01"])
@pytest.mark.parametrize("strategy", [1, 2, 3])
def test_single_challenge_type_skips_other_unset_list(
    challenge: str, strategy: int
) -> None:
    domains = utils.DomainsChallenged()
    domains[challenge] = ["audit.example.com"]
    context = cast("ApiContext", SimpleNamespace())
    order = cast(
        "AcmeOrder",
        SimpleNamespace(
            renewal_configuration=SimpleNamespace(
                acme_challenge_duplicate_strategy_id__effective=strategy,
            ),
            acme_order_id__retry_of=None,
        ),
    )
    assert domains.domain_to_challenge_type_id(
        context, "audit.example.com", order
    ) == utils.AcmeChallenge_Type.from_string(challenge)
    assert domains.domain_to_challenge_type_id(
        context, "audit.example.com"
    ) == utils.AcmeChallenge_Type.from_string(challenge)


def test_unknown_domain_has_a_clear_error_instead_of_iterating_none() -> None:
    with pytest.raises(ValueError, match="domain is not challenged"):
        utils.DomainsChallenged().domain_to_challenge_type_id(
            cast("ApiContext", SimpleNamespace()),
            "missing.example.com",
        )
