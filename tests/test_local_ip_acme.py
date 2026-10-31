"""Real local Pebble issuance for IPv4, IPv6 and mixed identifier certificates."""

import os
from unittest import skipUnless
from unittest.mock import patch

import tldextract

from peter_sslers.lib.db import actions_acme
from . import _utils


@skipUnless(
    os.environ.get("SSL_RUN_LOCAL_ACME_INTEGRATION") == "1",
    "local ACME integration is opt-in",
)
class LocalIpAcmeTests(_utils.AppTest):
    def test_ip_and_mixed_issuance(self) -> None:
        """Keep CA startup small; alternate chains are covered in other suites."""
        with patch.dict(
            _utils.PEBBLE_ENV,
            {"PEBBLE_CHAIN_LENGTH": "1", "PEBBLE_ALTERNATE_ROOTS": "0"},
        ):
            self._issue_ip_and_mixed()

    @_utils.under_pebble
    def _issue_ip_and_mixed(self) -> None:
        """Exercise real orders/CSRs/certificates; Pebble skips network validation.

        These addresses are never contacted: Pebble's ALWAYS_VALID test mode
        isolates issuance from ownership or routing of the requested IPs.
        """
        scenarios = [
            ["8.8.8.8"],
            ["2001:4860:4860::8888"],
            [
                "8.8.8.8",
                "1.1.1.1",
                "2001:4860:4860::8888",
                "2606:4700:4700::1111",
                "ip-a.audit.example.com",
                "ip-b.audit.example.org",
            ],
            ["10.0.0.1", "fd00::1"],
        ]
        with patch.object(
            tldextract,
            "extract",
            tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None),
        ):
            _utils.do__AcmeServers_sync__api(self, sync_backup=False)
            _utils.ensure_AcmeAccount_auth(testCase=self)
            assert self.ctx.application_settings is not None
            with patch.dict(
                self.ctx.application_settings, {"precheck_acme_challenges": ()}
            ):
                for index, names in enumerate(scenarios):
                    if index == 3:
                        from peter_sslers.lib.db import get

                        server = get.get__AcmeServer__by_name(self.ctx, "pebble")
                        assert server is not None
                        server.require_public_ip = False
                        self.ctx.pyramid_transaction_commit()
                    order = _utils.make_one__AcmeOrder__api(
                        self,
                        domain_names_http01=",".join(names),
                        processing_strategy="create_order",
                    )
                    for _ in range(8):
                        actions_acme.do__AcmeV2_AcmeOrder__process(
                            self.ctx, order, transaction_commit=True
                        )
                        self.ctx.pyramid_transaction_commit()
                        if order.x509_certificate_id is not None:
                            break
                    self.ctx.dbSession.expire_all()
                    assert order.acme_status_order == "valid"
                    assert order.x509_certificate is not None
                    assert order.x509_certificate_request is not None
                    expected = sorted(names)
                    assert order.domains_as_list == expected
                    assert order.x509_certificate.domains_as_list == expected
                    assert order.x509_certificate.identifiers == order.identifiers
                    assert (
                        order.x509_certificate_request.identifiers == order.identifiers
                    )
