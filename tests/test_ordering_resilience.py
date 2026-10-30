"""Bounded precheck failover and distinct requested/reported replacement metadata."""

from __future__ import annotations

import copy
from dataclasses import dataclass
import datetime
from types import SimpleNamespace
from typing import cast
from typing import Dict
from typing import List
from typing import Optional
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from sqlalchemy.orm import Session

from peter_sslers.lib import acme_v2
from peter_sslers.lib import errors
from peter_sslers.lib.challenge_fallback import dns_precheck_alternative
from peter_sslers.lib.db import actions_acme
from peter_sslers.lib.db import create
from peter_sslers.model import utils
from peter_sslers.model.objects import AcmeAccount
from peter_sslers.model.objects import AcmeEventLog
from peter_sslers.model.objects import PrivateKey

if TYPE_CHECKING:
    from peter_sslers.lib.context import ApiContext
    from peter_sslers.model.objects import AcmeAuthorization
    from peter_sslers.model.objects import AcmeChallenge
    from peter_sslers.model.objects import AcmeOrder
    from peter_sslers.model.objects import RenewalConfiguration
    from peter_sslers.model.objects import UniqueFQDNSet


@dataclass
class FallbackCase:
    """Typed boundary for a minimal order/authorization policy fixture."""

    user: acme_v2.AuthenticatedUser
    ctx: ApiContext
    order: AcmeOrder
    authorization: AcmeAuthorization
    http: AcmeChallenge
    dns: AcmeChallenge
    prepare: Mock


@pytest.fixture
def fallback() -> FallbackCase:
    names = utils.DomainsChallenged()
    names["http-01"] = ["example.com"]
    names["dns-01"] = ["example.com"]
    http = cast(
        "AcmeChallenge",
        SimpleNamespace(
            id=1,
            acme_challenge_type="http-01",
            acme_status_challenge="pending",
            acme_authorization_id=1,
            challenge_url="https://ca.example/http",
        ),
    )
    dns = cast(
        "AcmeChallenge",
        SimpleNamespace(
            id=2,
            acme_challenge_type="dns-01",
            acme_status_challenge="pending",
            acme_authorization_id=1,
            challenge_url="https://ca.example/dns",
        ),
    )
    authorization = cast(
        "AcmeAuthorization",
        SimpleNamespace(
            id=1,
            acme_status_authorization="pending",
            acme_challenge_http_01=http,
            acme_challenge_dns_01=dns,
            domain=SimpleNamespace(
                domain_name="example.com",
                acme_dns_server_account__active=SimpleNamespace(
                    is_active=True, acme_dns_server=SimpleNamespace(is_active=True)
                ),
            ),
        ),
    )
    order = cast(
        "AcmeOrder",
        SimpleNamespace(
            domains_challenged=names,
            renewal_configuration=SimpleNamespace(
                acme_challenge_duplicate_strategy_id__effective=2
            ),
        ),
    )
    ctx = cast(
        "ApiContext",
        SimpleNamespace(
            application_settings={
                "precheck_acme_challenges": ("http-01", "dns-01"),
                "log.acme": False,
            }
        ),
    )
    user = object.__new__(acme_v2.AuthenticatedUser)
    prepare = Mock(
        side_effect=[errors.AcmeChallengePrecheckError("local proof failed"), True]
    )
    setattr(user, "prepare_acme_challenge", prepare)
    return FallbackCase(user, ctx, order, authorization, http, dns, prepare)


def test_precheck_failover_is_bounded_and_keeps_the_same_order(
    fallback: FallbackCase,
) -> None:
    result = fallback.user.prepare_order_challenge(
        fallback.ctx,
        fallback.order,
        fallback.authorization,
        fallback.http,
        transaction_commit=True,
    )
    assert result is fallback.dns
    assert [call.args[2] for call in fallback.prepare.call_args_list] == [
        fallback.http,
        fallback.dns,
    ]


@pytest.mark.parametrize(
    "block",
    [
        "configuration",
        "server_missing",
        "strategy",
        "prechecks",
        "domain",
        "credentials",
        "server",
        "authorization",
        "http_status",
        "dns_status",
        "dns_owner",
        "dns_missing",
    ],
)
def test_fallback_requires_every_safety_condition(
    fallback: FallbackCase, block: str
) -> None:
    if block == "configuration":
        setattr(fallback.order, "renewal_configuration", None)
    elif block == "server_missing":
        setattr(
            fallback.authorization.domain.acme_dns_server_account__active,
            "acme_dns_server",
            None,
        )
    elif block == "strategy":
        setattr(
            fallback.order.renewal_configuration,
            "acme_challenge_duplicate_strategy_id__effective",
            1,
        )
    elif block == "prechecks":
        assert fallback.ctx.application_settings is not None
        fallback.ctx.application_settings["precheck_acme_challenges"] = ("http-01",)
    elif block == "domain":
        fallback.order.domains_challenged["dns-01"] = None
    elif block == "credentials":
        setattr(fallback.authorization.domain, "acme_dns_server_account__active", None)
    elif block == "server":
        fallback.authorization.domain.acme_dns_server_account__active.acme_dns_server.is_active = (
            False
        )
    elif block == "authorization":
        setattr(fallback.authorization, "acme_status_authorization", "invalid")
    elif block == "http_status":
        setattr(fallback.http, "acme_status_challenge", "processing")
    elif block == "dns_status":
        setattr(fallback.dns, "acme_status_challenge", "invalid")
    elif block == "dns_owner":
        fallback.dns.acme_authorization_id = 9
    else:
        setattr(fallback.authorization, "acme_challenge_dns_01", None)
    assert (
        dns_precheck_alternative(
            fallback.ctx, fallback.order, fallback.authorization, fallback.http
        )
        is None
    )
    with pytest.raises(errors.AcmeChallengePrecheckError):
        fallback.user.prepare_order_challenge(
            fallback.ctx,
            fallback.order,
            fallback.authorization,
            fallback.http,
            transaction_commit=True,
        )
    assert fallback.prepare.call_count == 1


@pytest.mark.parametrize(
    "failure", [RuntimeError("bug"), errors.DomainVerificationError("setup")]
)
def test_non_precheck_errors_do_not_select_another_challenge(
    fallback: FallbackCase, failure: Exception
) -> None:
    fallback.prepare.side_effect = failure
    with pytest.raises(type(failure)):
        fallback.user.prepare_order_challenge(
            fallback.ctx,
            fallback.order,
            fallback.authorization,
            fallback.http,
            transaction_commit=True,
        )
    assert fallback.prepare.call_count == 1


def test_failed_dns_precheck_stops_without_repeating(fallback: FallbackCase) -> None:
    fallback.prepare.side_effect = [
        errors.AcmeChallengePrecheckError("http"),
        errors.DomainVerificationError("dns"),
    ]
    with pytest.raises(errors.DomainVerificationError, match="dns"):
        fallback.user.prepare_order_challenge(
            fallback.ctx,
            fallback.order,
            fallback.authorization,
            fallback.http,
            transaction_commit=True,
        )
    assert fallback.prepare.call_count == 2


def test_authorization_processing_triggers_only_the_prechecked_dns_alternative(
    fallback: FallbackCase,
) -> None:
    document = {
        "status": "pending",
        "identifier": {"value": "example.com"},
        "challenges": [
            {"type": "http-01", "url": fallback.http.challenge_url},
            {"type": "dns-01", "url": fallback.dns.challenge_url},
        ],
    }
    setattr(
        fallback.user, "_send_signed_request", Mock(return_value=(200, document, {}))
    )
    trigger = Mock()
    setattr(fallback.user, "acme_challenge_trigger", trigger)
    assert fallback.user.acme_authorization_process_url(
        fallback.ctx,
        "https://ca.example/auth",
        Mock(return_value=fallback.authorization),
        Mock(),
        Mock(),
        Mock(),
        dbAcmeAuthorization=fallback.authorization,
        dbAcmeOrder=fallback.order,
        acme_challenge_type_id__preferred=utils.AcmeChallenge_Type.http_01,
        transaction_commit=True,
    )
    assert trigger.call_args.kwargs["dbAcmeChallenge"] is fallback.dns
    assert fallback.prepare.call_count == 2


@pytest.fixture
def ordering_user(monkeypatch: pytest.MonkeyPatch) -> acme_v2.AuthenticatedUser:
    user = object.__new__(acme_v2.AuthenticatedUser)
    user.acmeAccount = AcmeAccount(id=1, acme_server_id=1)
    user.acme_directory = {"newOrder": "https://ca.example/order"}
    user.supports_ari = True
    for name in (
        "get__RateLimited__by__acmeAccountId",
        "get__RateLimited__by__acmeServerId",
        "get__RateLimited__by__acmeServerId_uniqueFqdnSetId",
    ):
        monkeypatch.setattr(acme_v2.db_get, name, Mock(return_value=None))
    return user


@pytest.mark.parametrize("replacement", ["original-request", ""])
def test_rejected_replaces_is_removed_from_exactly_one_retry(
    ordering_user: acme_v2.AuthenticatedUser,
    replacement: str,
) -> None:
    payloads: List[Dict[str, object]] = []

    def send(
        kind: str, url: str, payload: Dict[str, object]
    ) -> tuple[int, Dict[str, object], Dict[str, str]]:
        payloads.append(copy.deepcopy(payload))
        if len(payloads) == 1:
            raise errors.AcmeServerError(
                400, url, {"type": "malformed", "detail": "bad replaces"}, {}
            )
        return 201, {"status": "pending"}, {"Location": "https://ca.example/order/1"}

    setattr(ordering_user, "_send_signed_request", send)
    ctx = cast("ApiContext", SimpleNamespace(application_settings={"log.acme": False}))
    ordering_user.acme_order_new(
        ctx,
        ["example.com"],
        cast("UniqueFQDNSet", SimpleNamespace(id=1)),
        transaction_commit=True,
        profile="custom",
        replaces=replacement,
    )
    assert len(payloads) == 2
    assert payloads[0]["replaces"] == replacement
    assert "replaces" not in payloads[1]
    assert payloads[1]["profile"] == "custom"
    assert payloads[0]["identifiers"] == payloads[1]["identifiers"]


@pytest.mark.parametrize("reported", [None, "original-request", "canonical-response"])
def test_factory_keeps_requested_replaces_separate_from_server_report(
    monkeypatch: pytest.MonkeyPatch,
    reported: Optional[str],
) -> None:
    for name in (
        "validate_domain_names",
        "create__AcmeOrderSubmission",
        "create__AcmeAuthorizationPotential",
    ):
        monkeypatch.setattr(create, name, Mock())
    monkeypatch.setattr(
        create._get, "get__X509Certificate__by_ariIdentifier", Mock(return_value=None)
    )
    names = utils.DomainsChallenged()
    names["http-01"] = ["example.com"]
    ctx = cast(
        "ApiContext",
        SimpleNamespace(
            dbSession=Mock(spec=Session),
            timestamp=datetime.datetime.now(datetime.timezone.utc),
            pyramid_transaction_commit=Mock(),
        ),
    )
    document: Dict[str, object] = {"status": "pending"}
    if reported is not None:
        document["replaces"] = reported
    order = create.create__AcmeOrder(
        ctx,
        document,
        1,
        1,
        1,
        names,
        "https://ca.example/order/1",
        utils.X509CertificateType.MANAGED_PRIMARY,
        AcmeAccount(id=1),
        cast(
            "UniqueFQDNSet",
            SimpleNamespace(
                id=1, domain_objects={"example.com": SimpleNamespace(id=1)}
            ),
        ),
        AcmeEventLog(id=1),
        cast(
            "RenewalConfiguration",
            SimpleNamespace(id=1, uniquely_challenged_fqdn_set_id=1),
        ),
        PrivateKey(id=1),
        utils.PrivateKey_Cycle.from_string("single_use"),
        1,
        0,
        transaction_commit=True,
        replaces_requested="original-request",
    )
    assert order.replaces__requested == "original-request"
    assert order.replaces == reported


def test_real_http_proof_failure_retains_precheck_classification(
    fallback: FallbackCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setattr(fallback.ctx, "request", SimpleNamespace())
    setattr(fallback.http, "token", "token")
    setattr(fallback.http, "keyauthorization", "expected")
    setattr(fallback.user, "accountKeyData", SimpleNamespace())
    monkeypatch.setattr(
        acme_v2, "create_challenge_keyauthorization", Mock(return_value="expected")
    )
    monkeypatch.setattr(
        acme_v2, "_check_http01_response", Mock(side_effect=OSError("offline"))
    )
    with pytest.raises(errors.AcmeChallengePrecheckError):
        fallback.user._prepare_acme_challenge__http01(
            fallback.ctx, fallback.authorization, fallback.http, transaction_commit=True
        )


def test_successful_http_precheck_does_not_attempt_dns(fallback: FallbackCase) -> None:
    fallback.prepare.side_effect = None
    fallback.prepare.return_value = True
    assert (
        fallback.user.prepare_order_challenge(
            fallback.ctx,
            fallback.order,
            fallback.authorization,
            fallback.http,
            transaction_commit=True,
        )
        is fallback.http
    )
    assert fallback.prepare.call_count == 1


def test_retry_failure_propagates_without_a_third_submission(
    ordering_user: acme_v2.AuthenticatedUser,
) -> None:
    send = Mock(
        side_effect=[
            errors.AcmeServerError(
                400, "https://ca.example/order", {"type": "malformed"}, {}
            ),
            RuntimeError("second attempt failed"),
        ]
    )
    setattr(ordering_user, "_send_signed_request", send)
    with pytest.raises(RuntimeError, match="second attempt"):
        ordering_user.acme_order_new(
            cast(
                "ApiContext", SimpleNamespace(application_settings={"log.acme": False})
            ),
            ["example.com"],
            cast("UniqueFQDNSet", SimpleNamespace(id=1)),
            transaction_commit=True,
            replaces="original-request",
        )
    assert send.call_count == 2


def test_rate_limits_do_not_trigger_replaces_retry(
    ordering_user: acme_v2.AuthenticatedUser,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = Mock()
    monkeypatch.setattr(acme_v2.db_create, "create__RateLimited", record)
    ctx = cast("ApiContext", SimpleNamespace(pyramid_transaction_commit=Mock()))
    send = Mock(
        side_effect=errors.AcmeServerError(429, "https://ca.example/order", {}, {})
    )
    setattr(ordering_user, "_send_signed_request", send)
    with pytest.raises(errors.AcmeServerError):
        ordering_user.acme_order_new(
            ctx,
            ["example.com"],
            cast("UniqueFQDNSet", SimpleNamespace(id=1)),
            transaction_commit=True,
            replaces="original-request",
        )
    assert send.call_count == 1
    record.assert_called_once()


@pytest.mark.parametrize("automatic", [False, True])
def test_continuation_uses_dns_but_manual_trigger_does_not_fail_over(
    fallback: FallbackCase,
    monkeypatch: pytest.MonkeyPatch,
    automatic: bool,
) -> None:
    setattr(fallback.http, "is_can_acme_server_trigger", True)
    setattr(fallback.http, "acme_authorization", fallback.authorization)
    setattr(fallback.authorization, "acme_order_created", fallback.order)
    setattr(
        fallback.order,
        "acme_order_processing_status_id",
        list(utils.AcmeOrder_ProcessingStatus.IDS_CAN_PROCESS_CHALLENGES)[0],
    )
    setattr(
        fallback.authorization,
        "to_acme_orders",
        [SimpleNamespace(acme_order=fallback.order)],
    )
    setattr(fallback.ctx, "timestamp", datetime.datetime.now(datetime.timezone.utc))
    setattr(fallback.user, "acmeLogger", Mock())
    trigger = Mock(return_value={"status": "valid"})
    setattr(fallback.user, "acme_challenge_trigger", trigger)
    audit = Mock()
    update = Mock()
    monkeypatch.setattr(
        actions_acme, "_audit_AcmeChallenge_against_server_response", audit
    )
    monkeypatch.setattr(actions_acme, "update_AcmeChallenge_status", update)
    monkeypatch.setattr(actions_acme, "updated_AcmeOrder_ProcessingStatus", Mock())
    if automatic:
        assert actions_acme.do__AcmeV2_AcmeChallenge__acme_server_trigger(
            fallback.ctx,
            fallback.http,
            fallback.user,
            transaction_commit=True,
            precheck_fallback_order=fallback.order,
        )
        assert trigger.call_args.kwargs["dbAcmeChallenge"] is fallback.dns
        assert audit.call_args.args[1] is fallback.dns
        assert update.call_args.args[1] is fallback.dns
    else:
        with pytest.raises(errors.AcmeChallengePrecheckError):
            actions_acme.do__AcmeV2_AcmeChallenge__acme_server_trigger(
                fallback.ctx, fallback.http, fallback.user, transaction_commit=True
            )
        trigger.assert_not_called()
        assert fallback.prepare.call_count == 1
