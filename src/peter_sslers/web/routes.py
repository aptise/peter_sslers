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
    config.add_route_7_kvpattern("websafe_or_id", r"[\d\w\-]+")

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
    config.add_route_7("admin:debug", "/debug")

    # !!!: AcmeAccounts
    # AcmeAccounts are the LetsEncrypt accounts
    config.add_route_7(
        "admin:acme_accounts",
        "/acme-accounts",
        jsonify=True,
        paginate=True,
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
        paginate=True,
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_account_keys",
        "/acme-account/{@id}/acme-account-keys",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_orders",
        "/acme-account/{@id}/acme-orders",
        paginate=True,
    )
    config.add_route_7(
        "admin:acme_account:focus:x509_certificates",
        "/acme-account/{@id}/x509-certificates",
        paginate=True,
    )
    config.add_route_7(
        "admin:acme_account:focus:private_keys",
        "/acme-account/{@id}/private-keys",
        paginate=True,
    )
    config.add_route_7(
        "admin:acme_account:focus:renewal_configurations",
        "/acme-account/{@id}/renewal-configurations",
        paginate=True,
    )
    config.add_route_7(
        "admin:acme_account:focus:renewal_configurations_backup",
        "/acme-account/{@id}/renewal-configurations-backup",
        paginate=True,
    )
    config.add_route_7(
        "admin:acme_account:focus:terms_of_service",
        "/acme-account/{@id}/terms-of-service",
        paginate=True,
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
        paginate=True,
    )
    config.add_route_7(
        "admin:acme_authorization:focus",
        "/acme-authorization/{@id}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_authorization:focus:acme_orders",
        "/acme-authorization/{@id}/acme-orders",
        paginate=True,
    )
    config.add_route_7(
        "admin:acme_authorization:focus:acme_challenges",
        "/acme-authorization/{@id}/acme-challenges",
        paginate=True,
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
        paginate=True,
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
        paginate=True,
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
        paginate=True,
    )

    # !!!: AcmeChallengeUnknown Poll
    config.add_route_7(
        "admin:acme_challenge_unknown_polls",
        "/acme-challenge-unknown-polls",
        jsonify=True,
        paginate=True,
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
        paginate=True,
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
        "admin:acme_dns_server:focus:acme_dns_server_accounts:all|csv",
        "/acme-dns-server/{@id}/acme-dns-server-accounts/all.csv",
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:acme_dns_server_accounts:all|json",
        "/acme-dns-server/{@id}/acme-dns-server-accounts/all.json",
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:acme_dns_server_accounts",
        "/acme-dns-server/{@id}/acme-dns-server-accounts",
        jsonify=True,
        paginate=True,
    )

    # !!!: AcmeDnsServer Accounts
    config.add_route_7(
        "admin:acme_dns_server_accounts:all|csv",
        "/acme-dns-server-accounts/all.csv",
    )
    config.add_route_7(
        "admin:acme_dns_server_accounts:all|json",
        "/acme-dns-server-accounts/all.json",
    )
    config.add_route_7(
        "admin:acme_dns_server_accounts",
        "/acme-dns-server-accounts",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:acme_dns_server_account:focus",
        "/acme-dns-server-account/{@id}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:acme_dns_server_account:focus:audit",
        "/acme-dns-server-account/{@id}/audit",
        jsonify=True,
    )

    # !!!: AcmeEventLog
    config.add_route_7(
        "admin:acme_event_log",
        "/acme-event-logs",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:acme_event_log:focus",
        "/acme-event-log/{@id}",
        jsonify=True,
    )

    # !!!: AcmePollingError
    config.add_route_7(
        "admin:acme_polling_errors",
        "/acme-polling-errors",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:acme_polling_error:focus",
        "/acme-polling-error/{@id}",
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
        paginate=True,
    )
    config.add_route_7(
        "admin:acme_orders:active",
        "/acme-orders/active",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:acme_orders:finished",
        "/acme-orders/finished",
        jsonify=True,
        paginate=True,
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
        "admin:acme_order:focus:acme_event_logs",
        "/acme-order/{@id}/acme-event-logs",
        paginate=True,
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
        paginate=True,
    )
    config.add_route_7(
        "admin:acme_server:focus:acme_server_configurations",
        "/acme-server/{@id}/acme-server-configurations",
        paginate=True,
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
        "admin:api:domain:certificate_if_needed",
        "/api/domain/certificate-if-needed",
        jsonify=True,
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
        paginate=True,
    )
    config.add_route_7(
        "admin:ari_checks:cert_latest",
        "/ari-checks/cert-latest",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:ari_checks:cert_latest_overdue",
        "/ari-checks/cert-latest-overdue",
        jsonify=True,
        paginate=True,
    )

    # !!!: CertificateCAs (Certificate Authority)
    config.add_route_7(
        "admin:certificate_cas",
        "/certificate-cas",
        jsonify=True,
        paginate=True,
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
        "admin:certificate_ca:focus:x509_certificates",
        "/certificate-ca/{@id}/x509-certificates",
        paginate=True,
    )
    config.add_route_7(
        "admin:certificate_ca:focus:x509_certificates_alt",
        "/certificate-ca/{@id}/x509-certificates-alt",
        paginate=True,
    )
    config.add_route_7(
        "admin:certificate_ca:focus:certificate_ca_chains_0",
        "/certificate-ca/{@id}/certificate-ca-chains-0",
        paginate=True,
    )
    config.add_route_7(
        "admin:certificate_ca:focus:certificate_ca_chains_n",
        "/certificate-ca/{@id}/certificate-ca-chains-n",
        paginate=True,
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
        paginate=True,
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

    # !!!: CertificateCAPreferencePolicys
    config.add_route_7(
        "admin:certificate_ca_preference_policys",
        "/certificate-ca-preference-policys",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:certificate_ca_preference_policy:focus",
        "/certificate-ca-preference-policy/{@id}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_ca_preference_policy:focus:add",
        "/certificate-ca-preference-policy/{@id}/add",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_ca_preference_policy:focus:delete",
        "/certificate-ca-preference-policy/{@id}/delete",
        jsonify=True,
    )
    config.add_route_7(
        "admin:certificate_ca_preference_policy:focus:prioritize",
        "/certificate-ca-preference-policy/{@id}/prioritize",
        jsonify=True,
    )

    # !!!: X509 Certificate Requests
    config.add_route_7(
        "admin:x509_certificate_requests",
        "/x509-certificate-requests",
        jsonify=True,
        paginate=True,
    )

    # !!!: X509 Certificate Request - Focus
    config.add_route_7(
        "admin:x509_certificate_request:focus",
        "/x509-certificate-request/{@id}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:x509_certificate_request:focus:acme_orders",
        "/x509-certificate-request/{@id}/acme-orders",
        paginate=True,
    )
    config.add_route_7(
        "admin:x509_certificate_request:focus:raw",
        "/x509-certificate-request/{@id}/csr.{format:(csr|pem|pem.txt)}",
    )

    # !!!: X509Certificates
    config.add_route_7(
        "admin:x509_certificates",
        "/x509-certificates",
        jsonify=True,
    )

    config.add_route_7(
        "admin:x509_certificates:all",
        "/x509-certificates/all",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:x509_certificates:active",
        "/x509-certificates/active",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:x509_certificates:active_expired",
        "/x509-certificates/active-expired",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:x509_certificates:expiring",
        "/x509-certificates/expiring",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:x509_certificates:inactive",
        "/x509-certificates/inactive",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:x509_certificates:inactive_unexpired",
        "/x509-certificates/inactive-unexpired",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:x509_certificates:active_duplicates",
        "/x509-certificates/active-duplicates",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:x509_certificates:search",
        "/x509-certificates/search",
        jsonify=True,
    )

    # !!!: X509Certificate - Focus
    config.add_route_7(
        "admin:x509_certificate:focus",
        "/x509-certificate/{@id}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:x509_certificate:focus:config|json",
        "/x509-certificate/{@id}/config.json",
    )
    config.add_route_7(
        "admin:x509_certificate:focus:config|zip",
        "/x509-certificate/{@id}/config.zip",
    )
    config.add_route_7(
        "admin:x509_certificate:focus:parse|json",
        "/x509-certificate/{@id}/parse.json",
    )
    config.add_route_7(
        "admin:x509_certificate:focus:cert:raw",
        "/x509-certificate/{@id}/cert.{format:(cer|crt|der|pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:x509_certificate:focus:chain:raw",
        "/x509-certificate/{@id}/chain.{format:(pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:x509_certificate:focus:fullchain:raw",
        "/x509-certificate/{@id}/fullchain.{format:(pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:x509_certificate:focus:privatekey:raw",
        "/x509-certificate/{@id}/privkey.{format:(key|pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:x509_certificate:focus:ari_check",
        r"/x509-certificate/{@id}/ari-check",
        jsonify=True,
    )
    config.add_route_7(
        "admin:x509_certificate:focus:ari_check_history",
        r"/x509-certificate/{@id}/ari-check-history",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:x509_certificate:focus:nginx_cache_expire",
        r"/x509-certificate/{@id}/nginx-cache-expire",
        jsonify=True,
    )
    # via ca-cert routes
    config.add_route_7(
        "admin:x509_certificate:focus:via_certificate_ca_chain:config|json",
        "/x509-certificate/{@id}/via-certificate-ca-chain/{id_cachain}/config.json",
    )
    config.add_route_7(
        "admin:x509_certificate:focus:via_certificate_ca_chain:config|zip",
        "/x509-certificate/{@id}/via-certificate-ca-chain/{id_cachain}/config.zip",
    )
    config.add_route_7(
        "admin:x509_certificate:focus:via_certificate_ca_chain:chain:raw",
        "/x509-certificate/{@id}/via-certificate-ca-chain/{id_cachain}/chain.{format:(cer|crt|der|pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:x509_certificate:focus:via_certificate_ca_chain:fullchain:raw",
        "/x509-certificate/{@id}/via-certificate-ca-chain/{id_cachain}/fullchain.{format:(pem|pem.txt)}",
    )
    # end via ca-cert

    config.add_route_7(
        "admin:x509_certificate:upload",
        "/x509-certificate/upload",
        jsonify=True,
    )
    config.add_route_7(
        "admin:x509_certificate:focus:mark",
        "/x509-certificate/{@id}/mark",
        jsonify=True,
    )

    # !!!: CoverageAssuranceEvents
    config.add_route_7("admin:coverage_assurance_events", "/coverage-assurance-events")
    config.add_route_7(
        "admin:coverage_assurance_events:all",
        "/coverage-assurance-events/all",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:coverage_assurance_events:unresolved",
        "/coverage-assurance-events/unresolved",
        jsonify=True,
        paginate=True,
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
        paginate=True,
    )
    config.add_route_7(
        "admin:domains:challenged",
        "/domains/challenged",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:domains:authz_potential",
        "/domains/authz-potential",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:domains:expiring",
        "/domains/expiring",
        jsonify=True,
        paginate=True,
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
        paginate=True,
    )
    config.add_route_7(
        "admin:domain:focus:acme_authorization_potentials",
        "/domain/{domain_identifier}/acme-authz-potentials",
        paginate=True,
    )
    config.add_route_7(
        "admin:domain:focus:acme_challenges",
        "/domain/{domain_identifier}/acme-challenges",
        paginate=True,
    )
    config.add_route_7(
        "admin:domain:focus:acme_orders",
        "/domain/{domain_identifier}/acme-orders",
        paginate=True,
    )
    config.add_route_7(
        "admin:domain:focus:domain_autocerts",
        "/domain/{domain_identifier}/domain-autocerts",
        paginate=True,
    )
    config.add_route_7(
        "admin:domain:focus:x509_certificates",
        "/domain/{domain_identifier}/x509-certificates",
        paginate=True,
    )
    # -
    config.add_route_7(
        "admin:domain:focus:x509_certificates:all",
        "/domain/{domain_identifier}/x509-certificates/all",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:domain:focus:x509_certificates:single",
        "/domain/{domain_identifier}/x509-certificates/single",
        jsonify=True,
        paginate=True,
    )
    # -
    config.add_route_7(
        "admin:domain:focus:x509_certificates:multi",
        "/domain/{domain_identifier}/x509-certificates/multi",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:domain:focus:x509_certificate_requests",
        "/domain/{domain_identifier}/x509-certificate-requests",
        paginate=True,
    )
    config.add_route_7(
        "admin:domain:focus:renewal_configurations",
        "/domain/{domain_identifier}/renewal-configurations",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:domain:focus:renewal_configurations:all",
        "/domain/{domain_identifier}/renewal-configurations/all",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:domain:focus:renewal_configurations:single",
        "/domain/{domain_identifier}/renewal-configurations/single",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:domain:focus:renewal_configurations:multi",
        "/domain/{domain_identifier}/renewal-configurations/multi",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:domain:focus:unique_fqdn_sets",
        "/domain/{domain_identifier}/unique-fqdn-sets",
        paginate=True,
    )
    config.add_route_7(
        "admin:domain:focus:uniquely_challenged_fqdn_sets",
        "/domain/{domain_identifier}/uniquely-challenged-fqdn-sets",
        paginate=True,
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
        paginate=True,
    )

    # !!!: DomainBlocklist
    config.add_route_7(
        "admin:domains_blocklisted",
        "/domains-blocklisted",
        jsonify=True,
        paginate=True,
    )

    # !!!: EnrollmentFactorys
    config.add_route_7(
        "admin:enrollment_factorys",
        "/enrollment-factorys",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:enrollment_factorys:new",
        "/enrollment-factorys/new",
        jsonify=True,
    )
    config.add_route_7(
        "admin:enrollment_factory:focus",
        "/enrollment-factory/{@id}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:enrollment_factory:focus:edit",
        "/enrollment-factory/{@id}/edit",
        jsonify=True,
    )
    config.add_route_7(
        "admin:enrollment_factory:focus:query",
        "/enrollment-factory/{@id}/query",
        jsonify=True,
    )
    config.add_route_7(
        "admin:enrollment_factory:focus:x509_certificates",
        "/enrollment-factory/{@id}/x509-certificates",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:enrollment_factory:focus:renewal_configurations",
        "/enrollment-factory/{@id}/renewal-configurations",
        jsonify=True,
        paginate=True,
    )

    # !!!: Operations & Sync Events
    config.add_route_7(
        "admin:notifications:all",
        "/notifications",
        paginate=True,
        jsonify=True,
    )
    # -
    config.add_route_7(
        "admin:notification:focus:mark",
        "/notification/{@id}/mark",
        jsonify=True,
    )

    # !!!: Operations & Sync Events
    config.add_route_7("admin:operations", "/operations")
    # -
    config.add_route_7(
        "admin:operations:log",
        "/operations/log",
        paginate=True,
    )
    config.add_route_7("admin:operations:log:focus", "/operations/log/item/{@id}")
    # -
    config.add_route_7(
        "admin:operations:object_log",
        "/operations/object-log",
        paginate=True,
    )
    config.add_route_7(
        "admin:operations:object_log:focus", "/operations/object-log/item/{@id}"
    )
    # -
    config.add_route_7(
        "admin:operations:nginx",
        "/operations/nginx",
        paginate=True,
    )
    # -
    config.add_route_7(
        "admin:operations:redis",
        "/operations/redis",
        paginate=True,
    )

    # !!!: Private Keys
    # used to sign X509Certificates
    config.add_route_7(
        "admin:private_keys",
        "/private-keys",
        jsonify=True,
        paginate=True,
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
        "admin:private_key:focus:x509_certificate_requests",
        "/private-key/{@id}/x509-certificate-requests",
        paginate=True,
    )
    config.add_route_7(
        "admin:private_key:focus:x509_certificates",
        "/private-key/{@id}/x509-certificates",
        paginate=True,
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

    # !!!: Rate Limiteds
    config.add_route_7(
        "admin:rate_limiteds",
        "/rate-limiteds",
        jsonify=True,
    )
    config.add_route_7(
        "admin:rate_limiteds:all",
        "/rate-limiteds/all",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:rate_limited:focus",
        "/rate-limited/{@id}",
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
        paginate=True,
    )
    config.add_route_7(
        "admin:renewal_configurations:active",
        "/renewal-configurations/active",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:renewal_configurations:disabled",
        "/renewal-configurations/disabled",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:renewal_configuration:new",
        "/renewal-configuration/new",
        jsonify=True,
    )
    config.add_route_7(
        "admin:renewal_configuration:new_enrollment",
        "/renewal-configuration/new-enrollment",
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
        paginate=True,
    )
    config.add_route_7(
        "admin:renewal_configuration:focus:x509_certificates",
        "/renewal-configuration/{@id}/x509-certificates",
        jsonify=True,
        paginate=True,
    )
    config.add_route_7(
        "admin:renewal_configuration:focus:lineages",
        "/renewal-configuration/{@id}/lineages",
        jsonify=True,
        paginate=False,
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
        paginate=True,
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

    # !!!: Routine Executions
    config.add_route_7(
        "admin:routine_executions",
        "/routine-executions",
        jsonify=True,
        paginate=True,
    )

    # !!!: SystemConfigurations
    config.add_route_7(
        "admin:system_configurations",
        "/system-configurations",
        jsonify=True,
    )
    config.add_route_7(
        "admin:system_configuration:focus",
        "/system-configuration/{@websafe_or_id}",
        jsonify=True,
    )
    config.add_route_7(
        "admin:system_configuration:focus:edit",
        "/system-configuration/{@websafe_or_id}/edit",
        jsonify=True,
    )

    # !!!: Unique FQDN Sets
    # tied to Certs and Ratelimits
    config.add_route_7(
        "admin:unique_fqdn_sets",
        "/unique-fqdn-sets",
        jsonify=True,
        paginate=True,
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
        paginate=True,
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:x509_certificate_requests",
        "/unique-fqdn-set/{@id}/x509-certificate-requests",
        paginate=True,
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:x509_certificates",
        "/unique-fqdn-set/{@id}/x509-certificates",
        paginate=True,
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:uniquely_challenged_fqdn_sets",
        "/unique-fqdn-set/{@id}/uniquely-challenged-fqdn-sets",
        paginate=True,
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
        paginate=True,
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
        paginate=True,
    )
    config.add_route_7(
        "admin:uniquely_challenged_fqdn_set:focus:x509_certificates",
        "/uniquely-challenged-fqdn-set/{@id}/x509-certificates",
        paginate=True,
    )
    config.add_route_7(
        "admin:uniquely_challenged_fqdn_set:focus:renewal_configurations",
        "/uniquely-challenged-fqdn-set/{@id}/renewal-configurations",
        paginate=True,
    )

    config.scan("peter_sslers.web.views_admin")
