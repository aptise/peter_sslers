# stdlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyramid.config import Configurator

# ==============================================================================


def includeme(config: "Configurator") -> None:
    enable_views_admin = config.registry.settings["application_settings"][
        "enable_views_admin"
    ]
    enable_views_public = config.registry.settings["application_settings"][
        "enable_views_public"
    ]

    # pyramid_route_7 lets us default repeatable macros for our routes
    config.include("pyramid_route_7")
    config.add_route_7_kvpattern("id", r"\d+")
    config.add_route_7_kvpattern("page", r"\d+")

    # public
    if enable_views_public:
        # public url
        config.add_route_7(
            "public_challenge", "/.well-known/acme-challenge/{challenge}"
        )
        config.add_route_7("public_whoami", "/.well-known/public/whoami")

        config.scan("peter_sslers.web.views_public")

    # admin
    if enable_views_admin:
        route_prefix = config.registry.settings["application_settings"].get(
            "admin_prefix"
        )
        config.include(_admin_views, route_prefix=route_prefix)
        config.add_route_7("admin", route_prefix)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _admin_views(config: "Configurator") -> None:
    config.add_static_view("/static", "static", cache_max_age=3600)

    config.add_route_7("admin", "")
    config.add_route_7("admin:whoami", "/whoami")
    config.add_route_7("admin:help", "/help")
    config.add_route_7("admin:search", "/search")
    config.add_route_7("admin:settings", "/settings")

    # !!!: AcmeAccounts
    # AcmeAccounts are the LetsEncrypt accounts
    config.add_route_7(
        "admin:acme_accounts",
        "/acme-accounts",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_accounts_paginated",
        "/acme-accounts/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_account:upload",
        "/acme-account/upload",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_account:new",
        "/acme-account/new",
        jsonify=True,
    )

    # !!!: AcmeAccount - Focus
    config.add_route_7(
        "admin:acme_account:focus",
        "/acme-account/{@id}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_account:focus:edit",
        "/acme-account/{@id}/edit",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_account:focus:parse|json", "/acme-account/{@id}/parse.json"
    )
    config.add_route_7(
        "admin:acme_account:focus:raw",
        "/acme-account/{@id}/key.{format:(key|pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_authorizations",
        "/acme-account/{@id}/acme-authorizations",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_authorizations_paginated",
        "/acme-account/{@id}/acme-authorizations/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_account_keys",
        "/acme-account/{@id}/acme-account-keys",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_account_keys_paginated",
        "/acme-account/{@id}/acme-account-keys/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_orders",
        "/acme-account/{@id}/acme-orders",
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_orders_paginated",
        "/acme-account/{@id}/acme-orders/{@page}",
    )
    config.add_route_7(
        "admin:acme_account:focus:certificate_signeds",
        "/acme-account/{@id}/certificate-signeds",
    )
    config.add_route_7(
        "admin:acme_account:focus:certificate_signeds_paginated",
        "/acme-account/{@id}/certificate-signeds/{@page}",
    )
    config.add_route_7(
        "admin:acme_account:focus:private_keys",
        "/acme-account/{@id}/private-keys",
    )
    config.add_route_7(
        "admin:acme_account:focus:private_keys_paginated",
        "/acme-account/{@id}/private-keys/{@page}",
    )
    config.add_route_7(
        "admin:acme_account:focus:renewal_configurations",
        "/acme-account/{@id}/renewal-configurations",
    )
    config.add_route_7(
        "admin:acme_account:focus:renewal_configurations_paginated",
        "/acme-account/{@id}/renewal-configurations/{@page}",
    )
    config.add_route_7(
        "admin:acme_account:focus:renewal_configurations_backup",
        "/acme-account/{@id}/renewal-configurations-backup",
    )
    config.add_route_7(
        "admin:acme_account:focus:renewal_configurations_backup_paginated",
        "/acme-account/{@id}/renewal-configurations-backup/{@page}",
    )
    config.add_route_7(
        "admin:acme_account:focus:terms_of_service",
        "/acme-account/{@id}/terms-of-service",
    )
    config.add_route_7(
        "admin:acme_account:focus:terms_of_service_paginated",
        "/acme-account/{@id}/terms-of-service/{@page}",
    )
    config.add_route_7(
        "admin:acme_account:focus:mark",
        "/acme-account/{@id}/mark",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_server:authenticate",
        "/acme-account/{@id}/acme-server/authenticate",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_server:check",
        "/acme-account/{@id}/acme-server/check",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_server:deactivate_pending_authorizations",
        "/acme-account/{@id}/acme-server/deactivate-pending-authorizations",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_server:deactivate",
        "/acme-account/{@id}/acme-server/deactivate",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_server:key_change",
        "/acme-account/{@id}/acme-server/key-change",
        jsonify=True,
    )

    # !!!: AcmeAuthorizations
    config.add_route_7(
        "admin:acme_authorizations",
        "/acme-authorizations",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_authorizations_paginated",
        "/acme-authorizations/{@page}",
        jsonify=True,
    )

    config.add_route_7(
        "admin:acme_authorization:focus",
        "/acme-authorization/{@id}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_authorization:focus:acme_orders",
        "/acme-authorization/{@id}/acme-orders",
    )
    config.add_route_7(
        "admin:acme_authorization:focus:acme_orders_paginated",
        "/acme-authorization/{@id}/acme-orders/{@page}",
    )
    config.add_route_7(
        "admin:acme_authorization:focus:acme_challenges",
        "/acme-authorization/{@id}/acme-challenges",
    )
    config.add_route_7(
        "admin:acme_authorization:focus:acme_challenges_paginated",
        "/acme-authorization/{@id}/acme-challenges/{@page}",
    )
    config.add_route_7(
        "admin:acme_authorization:focus:acme_server:deactivate",
        "/acme-authorization/{@id}/acme-server/deactivate",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_authorization:focus:acme_server:sync",
        "/acme-authorization/{@id}/acme-server/sync",
        jsonify=True,
    )

    # !!!: AcmeAuthorizationPotenials
    config.add_route_7(
        "admin:acme_authorization_potentials",
        "/acme-authz-potentials",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_authorization_potentials_paginated",
        "/acme-authz-potentials/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_authorization_potential:focus",
        "/acme-authz-potential/{@id}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_authorization_potential:focus:delete",
        "/acme-authz-potential/{@id}/delete",
        jsonify=True,
    )

    # !!!: AcmeChallenge
    config.add_route_7(
        "admin:acme_challenges",
        "/acme-challenges",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_challenges_paginated",
        "/acme-challenges/{@page}",
        jsonify=True,
    )

    config.add_route_7(
        "admin:acme_challenge:focus",
        "/acme-challenge/{@id}",
        jsonify=True,
    )

    config.add_route_7(
        "admin:acme_challenge:focus:acme_server:sync",
        "/acme-challenge/{@id}/acme-server/sync",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_challenge:focus:acme_server:trigger",
        "/acme-challenge/{@id}/acme-server/trigger",
        jsonify=True,
    )

    # !!!: AcmeChallenge Poll
    config.add_route_7(
        "admin:acme_challenge_polls",
        "/acme-challenge-polls",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_challenge_polls_paginated",
        "/acme-challenge-polls/{@page}",
        jsonify=True,
    )

    # !!!: AcmeChallengeUnknown Poll
    config.add_route_7(
        "admin:acme_challenge_unknown_polls",
        "/acme-challenge-unknown-polls",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_challenge_unknown_polls_paginated",
        "/acme-challenge-unknown-polls/{@page}",
        jsonify=True,
    )

    # !!!: AcmeDnsServer
    config.add_route_7(
        "admin:acme_dns_server:new",
        "/acme-dns-server/new",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_dns_servers",
        "/acme-dns-servers",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_dns_servers_paginated",
        "/acme-dns-servers/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_dns_server:focus",
        "/acme-dns-server/{@id}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:mark",
        "/acme-dns-server/{@id}/mark",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:check",
        "/acme-dns-server/{@id}/check",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:edit",
        "/acme-dns-server/{@id}/edit",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:ensure_domains",
        "/acme-dns-server/{@id}/ensure-domains",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:ensure_domains_results",
        "/acme-dns-server/{@id}/ensure-domains-results",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:import_domain",
        "/acme-dns-server/{@id}/import-domain",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:acme_dns_server_accounts",
        "/acme-dns-server/{@id}/acme-dns-server-accounts",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:acme_dns_server_accounts_paginated",
        "/acme-dns-server/{@id}/acme-dns-server-accounts/{@page}",
        jsonify=True,
    )

    # !!!: AcmeDnsServer Accounts
    config.add_route_7(
        "admin:acme_dns_server_accounts",
        "/acme-dns-server-accounts",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_dns_server_accounts_paginated",
        "/acme-dns-server-accounts/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_dns_server_account:focus",
        "/acme-dns-server-account/{@id}",
        jsonify=True,
    )

    # !!!: AcmeEventLog
    config.add_route_7(
        "admin:acme_event_log",
        "/acme-event-logs",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_event_log_paginated",
        "/acme-event-logs/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_event_log:focus",
        "/acme-event-log/{@id}",
        jsonify=True,
    )

    # !!!: AcmeOrder
    config.add_route_7(
        "admin:acme_orders",
        "/acme-orders",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_orders:all",
        "/acme-orders/all",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_orders:all_paginated",
        "/acme-orders/all/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_orders:active",
        "/acme-orders/active",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_orders:active_paginated",
        "/acme-orders/active/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_orders:finished",
        "/acme-orders/finished",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_orders:finished_paginated",
        "/acme-orders/finished/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_orders:active:acme_server:sync",
        "/acme-orders/active/acme-server/sync",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_order:focus",
        "/acme-order/{@id}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_order:focus:audit",
        "/acme-order/{@id}/audit",
        jsonify=True,
    )

    config.add_route_7(
        "admin:acme_order:focus:acme_event_logs", "/acme-order/{@id}/acme-event-logs"
    )
    config.add_route_7(
        "admin:acme_order:focus:acme_event_logs_paginated",
        "/acme-order/{@id}/acme-event-logs/{@page}",
    )

    config.add_route_7(
        "admin:acme_order:focus:acme_process",
        "/acme-order/{@id}/acme-process",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_order:focus:acme_finalize",
        "/acme-order/{@id}/acme-finalize",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_order:focus:acme_server:sync",
        "/acme-order/{@id}/acme-server/sync",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_order:focus:acme_server:sync_authorizations",
        "/acme-order/{@id}/acme-server/sync-authorizations",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_order:focus:acme_server:deactivate_authorizations",
        "/acme-order/{@id}/acme-server/deactivate-authorizations",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_order:focus:acme_server:download_certificate",
        "/acme-order/{@id}/acme-server/download-certificate",
        jsonify=True,
    )

    config.add_route_7(
        "admin:acme_order:focus:mark",
        "/acme-order/{@id}/mark",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_order:focus:retry",
        "/acme-order/{@id}/retry",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_order:new:freeform",
        "/acme-order/new/freeform",
        jsonify=True,
    )

    # !!!: AcmeServer
    # this is just letsencrypt endpoints
    config.add_route_7(
        "admin:acme_servers",
        "/acme-servers",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_server:focus",
        "/acme-server/{@id}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_server:focus:acme_accounts",
        "/acme-server/{@id}/acme-accounts",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_server:focus:acme_accounts__paginated",
        "/acme-server/{@id}/acme-accounts/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_server:focus:check_support",
        "/acme-server/{@id}/check-support",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_server:focus:mark",
        "/acme-server/{@id}/mark",
        jsonify=True,
    )

    # !!!: Admin API Items
    config.add_route_7("admin:api", "/api")
    config.add_route_7(
        "admin:api:domain:certificate-if-needed", "/api/domain/certificate-if-needed"
    )
    config.add_route_7(
        "admin:api:domain:autocert",
        "/api/domain/autocert",
        jsonify=True,
    )

    # -
    config.add_route_7(
        "admin:api:deactivate_expired",
        "/api/deactivate-expired",
        jsonify=True,
    )

    # -
    config.add_route_7(
        "admin:api:nginx:cache_flush",
        "/api/nginx/cache-flush",
        jsonify=True,
    )
    config.add_route_7(
        "admin:api:redis:prime",
        "/api/redis/prime",
        jsonify=True,
    )
    config.add_route_7("admin:api:nginx:status|json", "/api/nginx/status.json")

    config.add_route_7(
        "admin:api:update_recents",
        "/api/update-recents",
        jsonify=True,
    )

    config.add_route_7(
        "admin:api:reconcile_cas",
        "/api/reconcile-cas",
        jsonify=True,
    )

    config.add_route_7(
        "admin:api:version",
        "/api/version",
        jsonify=True,
    )

    # !!!: AriCheck
    # config.add_route_7("admin:ari_check", "/ari-check", jsonify=True,)
    config.add_route_7(
        "admin:ari_check:focus",
        "/ari-check/{@id}",
        jsonify=True,
    )

    config.add_route_7(
        "admin:ari_checks",
        "/ari-checks",
        jsonify=True,
    )

    config.add_route_7(
        "admin:ari_checks:all",
        "/ari-checks/all",
        jsonify=True,
    )
    config.add_route_7(
        "admin:ari_checks:all_paginated",
        "/ari-checks/all/{@page}",
        jsonify=True,
    )

    config.add_route_7(
        "admin:ari_checks:cert_latest",
        "/ari-checks/cert-latest",
        jsonify=True,
    )
    config.add_route_7(
        "admin:ari_checks:cert_latest_paginated",
        "/ari-checks/cert-latest/{@page}",
        jsonify=True,
    )

    config.add_route_7(
        "admin:ari_checks:cert_latest_overdue",
        "/ari-checks/cert-latest-overdue",
        jsonify=True,
    )
    config.add_route_7(
        "admin:ari_checks:cert_latest_overdue_paginated",
        "/ari-checks/cert-latest-overdue/{@page}",
        jsonify=True,
    )

    # !!!: CertificateCAs (Certificate Authority)
    config.add_route_7(
        "admin:certificate_cas",
        "/certificate-cas",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_cas_paginated",
        "/certificate-cas/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_cas:preferred",
        "/certificate-cas/preferred",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_cas:preferred:add",
        "/certificate-cas/preferred/add",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_cas:preferred:delete",
        "/certificate-cas/preferred/delete",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_cas:preferred:prioritize",
        "/certificate-cas/preferred/prioritize",
        jsonify=True,
    )

    config.add_route_7(
        "admin:certificate_ca:focus",
        "/certificate-ca/{@id}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_ca:focus:parse|json", "/certificate-ca/{@id}/parse.json"
    )
    config.add_route_7(
        "admin:certificate_ca:focus:raw",
        "/certificate-ca/{@id}/cert.{format:(cer|crt|der|pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:certificate_ca:focus:certificate_signeds",
        "/certificate-ca/{@id}/certificate-signeds",
    )
    config.add_route_7(
        "admin:certificate_ca:focus:certificate_signeds_paginated",
        "/certificate-ca/{@id}/certificate-signeds/{@page}",
    )
    config.add_route_7(
        "admin:certificate_ca:focus:certificate_signeds_alt",
        "/certificate-ca/{@id}/certificate-signeds-alt",
    )
    config.add_route_7(
        "admin:certificate_ca:focus:certificate_signeds_alt_paginated",
        "/certificate-ca/{@id}/certificate-signeds-alt/{@page}",
    )
    config.add_route_7(
        "admin:certificate_ca:focus:certificate_ca_chains_0",
        "/certificate-ca/{@id}/certificate-ca-chains-0",
    )
    config.add_route_7(
        "admin:certificate_ca:focus:certificate_ca_chains_0_paginated",
        "/certificate-ca/{@id}/certificate-ca-chains-0/{@page}",
    )
    config.add_route_7(
        "admin:certificate_ca:focus:certificate_ca_chains_n",
        "/certificate-ca/{@id}/certificate-ca-chains-n",
    )
    config.add_route_7(
        "admin:certificate_ca:focus:certificate_ca_chains_n_paginated",
        "/certificate-ca/{@id}/certificate-ca-chains-n/{@page}",
    )
    config.add_route_7(
        "admin:certificate_ca:upload_cert",
        "/certificate-ca/upload-cert",
        jsonify=True,
    )

    # !!!: CertificateCAChains (Certificate Authority)
    config.add_route_7(
        "admin:certificate_ca_chains",
        "/certificate-ca-chains",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_ca_chains_paginated",
        "/certificate-ca-chains/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_ca_chain:focus",
        "/certificate-ca-chain/{@id}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_ca_chain:focus:raw",
        "/certificate-ca-chain/{@id}/chain.{format:(pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:certificate_ca_chain:upload_chain",
        "/certificate-ca-chain/upload-chain",
        jsonify=True,
    )

    # !!!: Certificate Requests
    config.add_route_7(
        "admin:certificate_requests",
        "/certificate-requests",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_requests_paginated",
        "/certificate-requests/{@page}",
        jsonify=True,
    )

    # !!!: Certificate Request - Focus
    config.add_route_7(
        "admin:certificate_request:focus",
        "/certificate-request/{@id}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_request:focus:acme_orders",
        "/certificate-request/{@id}/acme-orders",
    )
    config.add_route_7(
        "admin:certificate_request:focus:acme_orders_paginated",
        "/certificate-request/{@id}/acme-orders/{@page}",
    )
    config.add_route_7(
        "admin:certificate_request:focus:raw",
        "/certificate-request/{@id}/csr.{format:(csr|pem|pem.txt)}",
    )

    # !!!: CertificateSigneds
    config.add_route_7(
        "admin:certificate_signeds",
        "/certificate-signeds",
        jsonify=True,
    )

    config.add_route_7(
        "admin:certificate_signeds:all",
        "/certificate-signeds/all",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_signeds:all_paginated",
        "/certificate-signeds/all/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_signeds:active",
        "/certificate-signeds/active",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_signeds:active_paginated",
        "/certificate-signeds/active/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_signeds:active_expired",
        "/certificate-signeds/active-expired",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_signeds:active_expired_paginated",
        "/certificate-signeds/active-expired/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_signeds:expiring",
        "/certificate-signeds/expiring",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_signeds:expiring_paginated",
        "/certificate-signeds/expiring/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_signeds:inactive",
        "/certificate-signeds/inactive",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_signeds:inactive_paginated",
        "/certificate-signeds/inactive/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_signeds:inactive_unexpired",
        "/certificate-signeds/inactive-unexpired",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_signeds:inactive_unexpired_paginated",
        "/certificate-signeds/inactive-unexpired/{@page}",
        jsonify=True,
    )

    config.add_route_7(
        "admin:certificate_signeds:search",
        "/certificate-signeds/search",
        jsonify=True,
    )

    # !!!: CertificateSigned - Focus
    config.add_route_7(
        "admin:certificate_signed:focus",
        "/certificate-signed/{@id}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_signed:focus:config|json",
        "/certificate-signed/{@id}/config.json",
    )
    config.add_route_7(
        "admin:certificate_signed:focus:config|zip",
        "/certificate-signed/{@id}/config.zip",
    )
    config.add_route_7(
        "admin:certificate_signed:focus:parse|json",
        "/certificate-signed/{@id}/parse.json",
    )
    config.add_route_7(
        "admin:certificate_signed:focus:cert:raw",
        "/certificate-signed/{@id}/cert.{format:(cer|crt|der|pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:certificate_signed:focus:chain:raw",
        "/certificate-signed/{@id}/chain.{format:(pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:certificate_signed:focus:fullchain:raw",
        "/certificate-signed/{@id}/fullchain.{format:(pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:certificate_signed:focus:privatekey:raw",
        "/certificate-signed/{@id}/privkey.{format:(key|pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:certificate_signed:focus:ari_check",
        r"/certificate-signed/{@id}/ari-check",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_signed:focus:ari_check_history",
        r"/certificate-signed/{@id}/ari-check-history",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_signed:focus:ari_check_history__paginated",
        r"/certificate-signed/{@id}/ari-check-history/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_signed:focus:nginx_cache_expire",
        r"/certificate-signed/{@id}/nginx-cache-expire",
        jsonify=True,
    )
    # via ca-cert routes
    config.add_route_7(
        "admin:certificate_signed:focus:via_certificate_ca_chain:config|json",
        "/certificate-signed/{@id}/via-certificate-ca-chain/{id_cachain}/config.json",
    )
    config.add_route_7(
        "admin:certificate_signed:focus:via_certificate_ca_chain:config|zip",
        "/certificate-signed/{@id}/via-certificate-ca-chain/{id_cachain}/config.zip",
    )
    config.add_route_7(
        "admin:certificate_signed:focus:via_certificate_ca_chain:chain:raw",
        "/certificate-signed/{@id}/via-certificate-ca-chain/{id_cachain}/chain.{format:(cer|crt|der|pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:certificate_signed:focus:via_certificate_ca_chain:fullchain:raw",
        "/certificate-signed/{@id}/via-certificate-ca-chain/{id_cachain}/fullchain.{format:(pem|pem.txt)}",
    )
    # end via ca-cert

    config.add_route_7(
        "admin:certificate_signed:upload",
        "/certificate-signed/upload",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_signed:focus:mark",
        "/certificate-signed/{@id}/mark",
        jsonify=True,
    )

    # !!!: CoverageAssuranceEvents
    config.add_route_7("admin:coverage_assurance_events", "/coverage-assurance-events")
    config.add_route_7(
        "admin:coverage_assurance_events:all",
        "/coverage-assurance-events/all",
        jsonify=True,
    )
    config.add_route_7(
        "admin:coverage_assurance_events:all_paginated",
        "/coverage-assurance-events/all/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:coverage_assurance_events:unresolved",
        "/coverage-assurance-events/unresolved",
        jsonify=True,
    )
    config.add_route_7(
        "admin:coverage_assurance_events:unresolved_paginated",
        "/coverage-assurance-events/unresolved/{@page}",
        jsonify=True,
    )

    # !!!: CoverageAssuranceEvent - Focus
    config.add_route_7(
        "admin:coverage_assurance_event:focus",
        "/coverage-assurance-event/{@id}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:coverage_assurance_event:focus:children",
        "/coverage-assurance-event/{@id}/children",
        jsonify=True,
    )
    config.add_route_7(
        "admin:coverage_assurance_event:focus:mark",
        "/coverage-assurance-event/{@id}/mark",
        jsonify=True,
    )

    # !!!: Domains
    config.add_route_7(
        "admin:domains",
        "/domains",
        jsonify=True,
    )
    config.add_route_7(
        "admin:domains_paginated",
        "/domains/{@page}",
        jsonify=True,
    )

    config.add_route_7(
        "admin:domains:challenged",
        "/domains/challenged",
        jsonify=True,
    )

    config.add_route_7(
        "admin:domains:challenged_paginated",
        "/domains/challenged/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:domains:authz_potential",
        "/domains/authz-potential",
        jsonify=True,
    )
    config.add_route_7(
        "admin:domains:authz_potential_paginated",
        "/domains/authz-potential/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:domains:expiring",
        "/domains/expiring",
        jsonify=True,
    )
    config.add_route_7(
        "admin:domains:expiring_paginated",
        "/domains/expiring/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:domains:search",
        "/domains/search",
        jsonify=True,
    )
    config.add_route_7(
        "admin:domain:new",
        "/domain/new",
        jsonify=True,
    )

    # !!!: Domain Focus
    # json first otherwise we think it's the extension
    config.add_route_7(
        "admin:domain:focus",
        "/domain/{domain_identifier}",
        jsonify=True,
    )

    config.add_route_7(
        "admin:domain:focus:config|json", "/domain/{domain_identifier}/config.json"
    )
    config.add_route_7(
        "admin:domain:focus:calendar|json", "/domain/{domain_identifier}/calendar.json"
    )
    config.add_route_7(
        "admin:domain:focus:update_recents",
        "/domain/{domain_identifier}/update-recents",
        jsonify=True,
    )
    config.add_route_7(
        "admin:domain:focus:acme_authorizations",
        "/domain/{domain_identifier}/acme-authorizations",
    )
    config.add_route_7(
        "admin:domain:focus:acme_authorizations_paginated",
        "/domain/{domain_identifier}/acme-authorizations/{@page}",
    )
    config.add_route_7(
        "admin:domain:focus:acme_authorization_potentials",
        "/domain/{domain_identifier}/acme-authz-potentials",
    )
    config.add_route_7(
        "admin:domain:focus:acme_authorization_potentials_paginated",
        "/domain/{domain_identifier}/acme-authz-potentials/{@page}",
    )
    config.add_route_7(
        "admin:domain:focus:acme_challenges",
        "/domain/{domain_identifier}/acme-challenges",
    )
    config.add_route_7(
        "admin:domain:focus:acme_challenges_paginated",
        "/domain/{domain_identifier}/acme-challenges/{@page}",
    )
    config.add_route_7(
        "admin:domain:focus:acme_orders", "/domain/{domain_identifier}/acme-orders"
    )
    config.add_route_7(
        "admin:domain:focus:acme_orders_paginated",
        "/domain/{domain_identifier}/acme-orders/{@page}",
    )
    config.add_route_7(
        "admin:domain:focus:domain_autocerts",
        "/domain/{domain_identifier}/domain-autocerts",
    )
    config.add_route_7(
        "admin:domain:focus:domain_autocerts_paginated",
        "/domain/{domain_identifier}/domain-autocerts/{@page}",
    )

    config.add_route_7(
        "admin:domain:focus:certificate_signeds",
        "/domain/{domain_identifier}/certificate-signeds",
    )
    config.add_route_7(
        "admin:domain:focus:certificate_signeds_paginated",
        "/domain/{domain_identifier}/certificate-signeds/{@page}",
    )
    # -
    config.add_route_7(
        "admin:domain:focus:certificate_signeds:all",
        "/domain/{domain_identifier}/certificate-signeds/all",
        jsonify=True,
    )
    config.add_route_7(
        "admin:domain:focus:certificate_signeds:all_paginated",
        "/domain/{domain_identifier}/certificate-signeds/all/{@page}",
        jsonify=True,
    )

    config.add_route_7(
        "admin:domain:focus:certificate_signeds:single",
        "/domain/{domain_identifier}/certificate-signeds/single",
        jsonify=True,
    )
    config.add_route_7(
        "admin:domain:focus:certificate_signeds:single_paginated",
        "/domain/{domain_identifier}/certificate-signeds/single/{@page}",
        jsonify=True,
    )
    # -
    config.add_route_7(
        "admin:domain:focus:certificate_signeds:multi",
        "/domain/{domain_identifier}/certificate-signeds/multi",
        jsonify=True,
    )
    config.add_route_7(
        "admin:domain:focus:certificate_signeds:multi_paginated",
        "/domain/{domain_identifier}/certificate-signeds/multi/{@page}",
        jsonify=True,
    )

    config.add_route_7(
        "admin:domain:focus:certificate_requests",
        "/domain/{domain_identifier}/certificate-requests",
    )
    config.add_route_7(
        "admin:domain:focus:certificate_requests_paginated",
        "/domain/{domain_identifier}/certificate-requests/{@page}",
    )
    config.add_route_7(
        "admin:domain:focus:unique_fqdn_sets",
        "/domain/{domain_identifier}/unique-fqdn-sets",
    )
    config.add_route_7(
        "admin:domain:focus:unique_fqdn_sets_paginated",
        "/domain/{domain_identifier}/unique-fqdn-sets/{@page}",
    )
    config.add_route_7(
        "admin:domain:focus:uniquely_challenged_fqdn_sets",
        "/domain/{domain_identifier}/uniquely-challenged-fqdn-sets",
    )
    config.add_route_7(
        "admin:domain:focus:uniquely_challenged_fqdn_sets_paginated",
        "/domain/{domain_identifier}/uniquely-challenged-fqdn-sets/{@page}",
    )
    config.add_route_7(
        "admin:domain:focus:nginx_cache_expire",
        "/domain/{domain_identifier}/nginx-cache-expire",
        jsonify=True,
    )
    config.add_route_7(
        "admin:domain:focus:acme_dns_server_accounts",
        "/domain/{domain_identifier}/acme-dns-server-accounts",
        jsonify=True,
    )
    config.add_route_7(
        "admin:domain:focus:acme_dns_server:new",
        "/domain/{domain_identifier}/acme-dns-server/new",
        jsonify=True,
    )

    # !!!: DomainAutocerts
    config.add_route_7(
        "admin:domain_autocerts",
        "/domain-autocerts",
        jsonify=True,
    )

    config.add_route_7(
        "admin:domain_autocerts_paginated",
        "/domain-autocerts/{@page}",
        jsonify=True,
    )

    # !!!: DomainBlocklist
    config.add_route_7(
        "admin:domains_blocklisted",
        "/domains-blocklisted",
        jsonify=True,
    )

    config.add_route_7(
        "admin:domains_blocklisted_paginated",
        "/domains-blocklisted/{@page}",
        jsonify=True,
    )

    # !!!: Operations & Sync Events
    config.add_route_7("admin:operations", "/operations")
    # -
    config.add_route_7("admin:operations:log", "/operations/log")
    config.add_route_7("admin:operations:log_paginated", "/operations/log/{@page}")
    config.add_route_7("admin:operations:log:focus", "/operations/log/item/{@id}")
    # -
    config.add_route_7("admin:operations:object_log", "/operations/object-log")
    config.add_route_7(
        "admin:operations:object_log_paginated", "/operations/object-log/{@page}"
    )
    config.add_route_7(
        "admin:operations:object_log:focus", "/operations/object-log/item/{@id}"
    )
    # -
    config.add_route_7("admin:operations:nginx", "/operations/nginx")
    config.add_route_7("admin:operations:nginx_paginated", "/operations/nginx/{@page}")
    # -
    config.add_route_7("admin:operations:redis", "/operations/redis")
    config.add_route_7("admin:operations:redis_paginated", "/operations/redis/{@page}")

    # !!!: Private Keys
    # used to sign CertificateSigneds
    config.add_route_7(
        "admin:private_keys",
        "/private-keys",
        jsonify=True,
    )

    config.add_route_7(
        "admin:private_keys_paginated",
        "/private-keys/{@page}",
        jsonify=True,
    )

    # !!!: Private Key - Focus
    config.add_route_7(
        "admin:private_key:focus",
        "/private-key/{@id}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:private_key:focus:parse|json", "/private-key/{@id}/parse.json"
    )
    config.add_route_7(
        "admin:private_key:focus:raw",
        "/private-key/{@id}/key.{format:(key|pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:private_key:focus:certificate_requests",
        "/private-key/{@id}/certificate-requests",
    )
    config.add_route_7(
        "admin:private_key:focus:certificate_requests_paginated",
        "/private-key/{@id}/certificate-requests/{@page}",
    )
    config.add_route_7(
        "admin:private_key:focus:certificate_signeds",
        "/private-key/{@id}/certificate-signeds",
    )
    config.add_route_7(
        "admin:private_key:focus:certificate_signeds_paginated",
        "/private-key/{@id}/certificate-signeds/{@page}",
    )
    config.add_route_7(
        "admin:private_key:focus:mark",
        "/private-key/{@id}/mark",
        jsonify=True,
    )

    # !!!: Private Key - New
    config.add_route_7(
        "admin:private_key:new",
        "/private-key/new",
        jsonify=True,
    )

    config.add_route_7(
        "admin:private_key:upload",
        "/private-key/upload",
        jsonify=True,
    )

    # !!!: Renewal Configurations
    config.add_route_7(
        "admin:renewal_configurations",
        "/renewal-configurations",
        jsonify=True,
    )

    config.add_route_7(
        "admin:renewal_configurations:all",
        "/renewal-configurations/all",
        jsonify=True,
    )
    config.add_route_7(
        "admin:renewal_configurations:all_paginated",
        "/renewal-configurations/all/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:renewal_configurations:active",
        "/renewal-configurations/active",
        jsonify=True,
    )
    config.add_route_7(
        "admin:renewal_configurations:active_paginated",
        "/renewal-configurations/active/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:renewal_configurations:disabled",
        "/renewal-configurations/disabled",
        jsonify=True,
    )
    config.add_route_7(
        "admin:renewal_configurations:disabled_paginated",
        "/renewal-configurations/disabled/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:renewal_configuration:new",
        "/renewal-configuration/new",
        jsonify=True,
    )

    config.add_route_7(
        "admin:renewal_configuration:focus",
        "/renewal-configuration/{@id}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:renewal_configuration:focus:acme_orders",
        "/renewal-configuration/{@id}/acme-orders",
        jsonify=True,
    )
    config.add_route_7(
        "admin:renewal_configuration:focus:acme_orders_paginated",
        "/renewal-configuration/{@id}/acme-orders/{@page}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:renewal_configuration:focus:certificate_signeds",
        "/renewal-configuration/{@id}/certificate-signeds",
        jsonify=True,
    )
    config.add_route_7(
        "admin:renewal_configuration:focus:certificate_signeds_paginated",
        "/renewal-configuration/{@id}/certificate-signeds/{@page}",
        jsonify=True,
    )

    config.add_route_7(
        "admin:renewal_configuration:focus:mark",
        "/renewal-configuration/{@id}/mark",
        jsonify=True,
    )
    config.add_route_7(
        "admin:renewal_configuration:focus:new_order",
        "/renewal-configuration/{@id}/new-order",
        jsonify=True,
    )
    config.add_route_7(
        "admin:renewal_configuration:focus:new_configuration",
        "/renewal-configuration/{@id}/new-configuration",
        jsonify=True,
    )

    # !!!: Root Stores
    config.add_route_7(
        "admin:root_stores",
        "/root-stores",
        jsonify=True,
    )

    config.add_route_7(
        "admin:root_stores_paginated",
        "/root-stores/{@page}",
        jsonify=True,
    )

    # !!!: Root Store - Focus
    config.add_route_7(
        "admin:root_store:focus",
        "/root-store/{@id}",
        jsonify=True,
    )

    # !!!: Root Store Version - Focus
    config.add_route_7(
        "admin:root_store_version:focus",
        "/root-store-version/{@id}",
        jsonify=True,
    )

    # !!!: Unique FQDN Sets
    # tied to Certs and Ratelimits
    config.add_route_7(
        "admin:unique_fqdn_sets",
        "/unique-fqdn-sets",
        jsonify=True,
    )

    config.add_route_7(
        "admin:unique_fqdn_sets_paginated",
        "/unique-fqdn-sets/{@page}",
        jsonify=True,
    )

    # !!!: Unique FQDN Set - Focus
    config.add_route_7(
        "admin:unique_fqdn_set:focus",
        "/unique-fqdn-set/{@id}",
        jsonify=True,
    )

    config.add_route_7(
        "admin:unique_fqdn_set:focus:calendar|json",
        "/unique-fqdn-set/{@id}/calendar.json",
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:update_recents",
        "/unique-fqdn-set/{id}/update-recents",
        jsonify=True,
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:acme_orders",
        "/unique-fqdn-set/{@id}/acme-orders",
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:acme_orders_paginated",
        "/unique-fqdn-set/{@id}/acme-orders/{@page}",
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:certificate_requests",
        "/unique-fqdn-set/{@id}/certificate-requests",
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:certificate_requests_paginated",
        "/unique-fqdn-set/{@id}/certificate-requests/{@page}",
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:certificate_signeds",
        "/unique-fqdn-set/{@id}/certificate-signeds",
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:certificate_signeds_paginated",
        "/unique-fqdn-set/{@id}/certificate-signeds/{@page}",
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:uniquely_challenged_fqdn_sets",
        "/unique-fqdn-set/{@id}/uniquely-challenged-fqdn-sets",
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:uniquely_challenged_fqdn_sets_paginated",
        "/unique-fqdn-set/{@id}/uniquely-challenged-fqdn-sets/{@page}",
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:modify",
        "/unique-fqdn-set/{@id}/modify",
        jsonify=True,
    )
    config.add_route_7(
        "admin:unique_fqdn_set:new",
        "/unique-fqdn-set/new",
        jsonify=True,
    )

    # !!!: Uniquely Challenged FQDN Sets
    # tied to RenewalConfigurations and AcmeOrders
    config.add_route_7(
        "admin:uniquely_challenged_fqdn_sets",
        "/uniquely-challenged-fqdn-sets",
        jsonify=True,
    )
    config.add_route_7(
        "admin:uniquely_challenged_fqdn_sets_paginated",
        "/uniquely-challenged-fqdn-sets/{@page}",
        jsonify=True,
    )

    # !!!: Uniquely Challenged FQDN Set - Focus
    config.add_route_7(
        "admin:uniquely_challenged_fqdn_set:focus",
        "/uniquely-challenged-fqdn-set/{@id}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:uniquely_challenged_fqdn_set:focus:acme_orders",
        "/uniquely-challenged-fqdn-set/{@id}/acme-orders",
    )
    config.add_route_7(
        "admin:uniquely_challenged_fqdn_set:focus:acme_orders_paginated",
        "/uniquely-challenged-fqdn-set/{@id}/acme-orders/{@page}",
    )
    config.add_route_7(
        "admin:uniquely_challenged_fqdn_set:focus:certificate_signeds",
        "/uniquely-challenged-fqdn-set/{@id}/certificate-signeds",
    )
    config.add_route_7(
        "admin:uniquely_challenged_fqdn_set:focus:certificate_signeds_paginated",
        "/uniquely-challenged-fqdn-set/{@id}/certificate-signeds/{@page}",
    )
    config.add_route_7(
        "admin:uniquely_challenged_fqdn_set:focus:renewal_configurations",
        "/uniquely-challenged-fqdn-set/{@id}/renewal-configurations",
    )
    config.add_route_7(
        "admin:uniquely_challenged_fqdn_set:focus:renewal_configurations_paginated",
        "/uniquely-challenged-fqdn-set/{@id}/renewal-configurations/{@page}",
    )

    config.scan("peter_sslers.web.views_admin")
