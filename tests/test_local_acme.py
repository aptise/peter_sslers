"""Strict CA validation against a loopback challenge server, without public DNS."""

import os
from pathlib import Path
import tempfile
from unittest import skipUnless
from unittest.mock import patch

import tldextract

from peter_sslers.lib import acme_v2
from peter_sslers.lib import errors
from peter_sslers.lib.acmedns import AcmeDnsCredentials
from peter_sslers.lib.db import actions_acme
from peter_sslers.lib.db import create
from peter_sslers.lib.db import get
from peter_sslers.lib.db import getcreate
from . import _utils
from ._local_dns import local_http_dns
from .test_local_acmedns import local_acmedns


@skipUnless(
    os.environ.get("SSL_RUN_LOCAL_ACME_INTEGRATION") == "1",
    "local ACME integration is opt-in",
)
class LocalAcmeTests(_utils.AppTestWSGI):
    def test_strict_http01_and_interrupted_certificate_download(self) -> None:
        with local_http_dns(), patch.dict(
            os.environ, {"SSL_PEBBLE_DNS_SERVER": "127.0.0.1:18554"}
        ):
            self._strict_http01()

    @_utils.under_pebble_strict
    def _strict_http01(self) -> None:
        # Use the bundled public suffix snapshot; no download during local tests.
        with patch.object(
            tldextract,
            "extract",
            tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None),
        ):
            _utils.do__AcmeServers_sync__api(self, sync_backup=False)
            _utils.ensure_AcmeAccount_auth(testCase=self)
            order = _utils.make_one__AcmeOrder__api(
                self,
                domain_names_http01="strict-http.audit.example.com",
                processing_strategy="create_order",
            )
            with patch.object(
                acme_v2.AuthenticatedUser,
                "download_certificate",
                side_effect=OSError("injected interrupted download"),
            ):
                try:
                    for _ in range(5):
                        actions_acme.do__AcmeV2_AcmeOrder__process(
                            self.ctx, order, transaction_commit=True
                        )
                        self.ctx.pyramid_transaction_commit()
                        if order.acme_status_order == "valid":
                            break
                except OSError:
                    pass
            self.ctx.dbSession.expire_all()
            assert order.acme_status_order == "valid"
            assert order.certificate_url
            assert order.x509_certificate_id is None
            # Recover using the same public service operation the reconciler uses.
            actions_acme.do__AcmeV2_AcmeOrder__download_certificate(
                self.ctx, order, transaction_commit=True
            )
            self.ctx.dbSession.expire_all()
            assert order.x509_certificate_id is not None
            assert order.x509_certificate.private_key_id == order.private_key_id
            invalid = _utils.make_one__AcmeOrder__api(
                self,
                domain_names_http01="invalid-http.audit.example.com",
                processing_strategy="create_order",
            )
            for _ in range(5):
                try:
                    actions_acme.do__AcmeV2_AcmeOrder__process(
                        self.ctx, invalid, transaction_commit=True
                    )
                except errors.AcmeServerError:
                    break
                if invalid.acme_status_order == "invalid":
                    break
            actions_acme.do__AcmeV2_AcmeOrder__acme_server_sync(
                self.ctx, invalid, transaction_commit=True
            )
            assert invalid.acme_status_order == "invalid"
            assert invalid.x509_certificate_id is None

    def test_strict_dns01_with_real_acmedns(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sslers-local-dns-") as directory:
            with local_acmedns(Path(directory)) as client:
                credentials = client.register_account(["127.0.0.1/32"])
                aliases = {
                    "_acme-challenge.strict-dns.audit.example.com.": credentials[
                        "fulldomain"
                    ]
                }
                with local_http_dns(
                    aliases=aliases,
                    authoritative_port=int(
                        os.environ.get("SSL_LOCAL_ACME_DNS_PORT", "18553")
                    ),
                ), patch.dict(os.environ, {"SSL_PEBBLE_DNS_SERVER": "127.0.0.1:18554"}):
                    self._strict_dns01(client.acmedns_url, credentials)

    @_utils.under_pebble_strict
    def _strict_dns01(self, api_url: str, credentials: "AcmeDnsCredentials") -> None:
        with patch.object(
            tldextract,
            "extract",
            tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None),
        ):
            _utils.do__AcmeServers_sync__api(self, sync_backup=False)
            _utils.ensure_AcmeAccount_auth(testCase=self)
            domain, _ = getcreate.getcreate__Domain__by_domainName(
                self.ctx, "strict-dns.audit.example.com"
            )
            server = get.get__AcmeDnsServer__GlobalDefault(self.ctx)
            assert server is not None
            server.api_url = api_url
            server.domain = "audit.example.com"
            create.create__AcmeDnsServerAccount(
                self.ctx,
                server,
                domain,
                credentials["username"],
                credentials["password"],
                credentials["fulldomain"],
                credentials["subdomain"],
                credentials["allowfrom"],
            )
            self.ctx.pyramid_transaction_commit()
            order = _utils.make_one__AcmeOrder__api(
                self,
                domain_names_dns01="strict-dns.audit.example.com",
                processing_strategy="create_order",
            )
            for _ in range(5):
                actions_acme.do__AcmeV2_AcmeOrder__process(
                    self.ctx, order, transaction_commit=True
                )
                self.ctx.pyramid_transaction_commit()
                if order.acme_status_order == "valid":
                    break
            self.ctx.dbSession.expire_all()
            assert order.acme_status_order == "valid"
            assert order.x509_certificate_id is not None
