"""Conservative selection of a same-order alternative before CA validation."""

from typing import Optional
from typing import TYPE_CHECKING

from ..model import utils

if TYPE_CHECKING:
    from .context import ApiContext
    from ..model.objects import AcmeAuthorization
    from ..model.objects import AcmeChallenge
    from ..model.objects import AcmeOrder


def dns_precheck_alternative(
    ctx: "ApiContext",
    order: "AcmeOrder",
    authorization: "AcmeAuthorization",
    challenge: "AcmeChallenge",
) -> Optional["AcmeChallenge"]:
    """Permit one HTTP-to-DNS fallback only under explicit policy and configuration."""
    if (
        challenge.acme_challenge_type != "http-01"
        or challenge.acme_authorization_id != authorization.id
    ):
        return None
    if authorization.acme_status_authorization != "pending":
        return None
    if challenge.acme_status_challenge not in ("pending", "*discovered*"):
        return None
    configuration = order.renewal_configuration
    if configuration is None:
        return None
    if (
        configuration.acme_challenge_duplicate_strategy_id__effective
        != utils.AcmeChallenge_DuplicateStrategy.http_01__dns_01
    ):
        return None
    enabled = (
        (ctx.application_settings.get("precheck_acme_challenges", ()) or ())
        if ctx.application_settings
        else ()
    )
    if not {"http-01", "dns-01"}.issubset(enabled):
        return None
    domain = authorization.domain
    names = order.domains_challenged
    if any(
        domain.domain_name not in (names.get(kind) or ())
        for kind in ("http-01", "dns-01")
    ):
        return None
    account = domain.acme_dns_server_account__active
    if (
        account is None
        or not account.is_active
        or account.acme_dns_server is None
        or not account.acme_dns_server.is_active
    ):
        return None
    alternative = authorization.acme_challenge_dns_01
    if (
        alternative is None
        or not alternative.challenge_url
        or alternative.acme_authorization_id != authorization.id
        or alternative.acme_status_challenge not in ("pending", "*discovered*")
    ):
        return None
    return alternative
