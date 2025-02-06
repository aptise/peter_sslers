# stdlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyramid.config import Configurator

# ==============================================================================


def includeme(config: "Configurator") -> None:
    enable_views_admin = config.registry.settings["app_settings"]["enable_views_admin"]
    enable_views_public = config.registry.settings["app_settings"][
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
        route_prefix = config.registry.settings["app_settings"].get("admin_prefix")
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
    config.add_route_7("admin:acme_accounts", "/acme-accounts")
    config.add_route_7("admin:acme_accounts|json", "/acme-accounts.json")
    config.add_route_7("admin:acme_accounts_paginated", "/acme-accounts/{@page}")
    config.add_route_7(
        "admin:acme_accounts_paginated|json", "/acme-accounts/{@page}.json"
    )
    config.add_route_7("admin:acme_account:upload", "/acme-account/upload")
    config.add_route_7("admin:acme_account:upload|json", "/acme-account/upload.json")
    config.add_route_7("admin:acme_account:new", "/acme-account/new")
    config.add_route_7("admin:acme_account:new|json", "/acme-account/new.json")

    # !!!: AcmeAccount - Focus
    config.add_route_7("admin:acme_account:focus", "/acme-account/{@id}")
    config.add_route_7("admin:acme_account:focus|json", "/acme-account/{@id}.json")
    config.add_route_7("admin:acme_account:focus:edit", "/acme-account/{@id}/edit")
    config.add_route_7(
        "admin:acme_account:focus:edit|json", "/acme-account/{@id}/edit.json"
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
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_authorizations_paginated",
        "/acme-account/{@id}/acme-authorizations/{@page}",
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_authorizations|json",
        "/acme-account/{@id}/acme-authorizations.json",
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_authorizations_paginated|json",
        "/acme-account/{@id}/acme-authorizations/{@page}.json",
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_account_keys",
        "/acme-account/{@id}/acme-account-keys",
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_account_keys_paginated",
        "/acme-account/{@id}/acme-account-keys/{@page}",
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_account_keys|json",
        "/acme-account/{@id}/acme-account-keys.json",
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_account_keys_paginated|json",
        "/acme-account/{@id}/acme-account-keys/{@page}.json",
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
        "admin:acme_account:focus:terms_of_service",
        "/acme-account/{@id}/terms-of-service",
    )
    config.add_route_7(
        "admin:acme_account:focus:terms_of_service_paginated",
        "/acme-account/{@id}/terms-of-service/{@page}",
    )
    config.add_route_7("admin:acme_account:focus:mark", "/acme-account/{@id}/mark")
    config.add_route_7(
        "admin:acme_account:focus:mark|json", "/acme-account/{@id}/mark.json"
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_server:authenticate",
        "/acme-account/{@id}/acme-server/authenticate",
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_server:authenticate|json",
        "/acme-account/{@id}/acme-server/authenticate.json",
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_server:check",
        "/acme-account/{@id}/acme-server/check",
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_server:check|json",
        "/acme-account/{@id}/acme-server/check.json",
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_server:deactivate_pending_authorizations",
        "/acme-account/{@id}/acme-server/deactivate-pending-authorizations",
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_server:deactivate_pending_authorizations|json",
        "/acme-account/{@id}/acme-server/deactivate-pending-authorizations.json",
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_server:deactivate",
        "/acme-account/{@id}/acme-server/deactivate",
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_server:deactivate|json",
        "/acme-account/{@id}/acme-server/deactivate.json",
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_server:key_change",
        "/acme-account/{@id}/acme-server/key-change",
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_server:key_change|json",
        "/acme-account/{@id}/acme-server/key-change.json",
    )

    # !!!: AcmeAuthorizations
    config.add_route_7("admin:acme_authorizations", "/acme-authorizations")
    config.add_route_7(
        "admin:acme_authorizations_paginated", "/acme-authorizations/{@page}"
    )
    config.add_route_7("admin:acme_authorizations|json", "/acme-authorizations.json")
    config.add_route_7(
        "admin:acme_authorizations_paginated|json", "/acme-authorizations/{@page}.json"
    )

    config.add_route_7("admin:acme_authorization:focus", "/acme-authorization/{@id}")
    config.add_route_7(
        "admin:acme_authorization:focus|json", "/acme-authorization/{@id}.json"
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
    )
    config.add_route_7(
        "admin:acme_authorization:focus:acme_server:deactivate|json",
        "/acme-authorization/{@id}/acme-server/deactivate.json",
    )
    config.add_route_7(
        "admin:acme_authorization:focus:acme_server:sync",
        "/acme-authorization/{@id}/acme-server/sync",
    )
    config.add_route_7(
        "admin:acme_authorization:focus:acme_server:sync|json",
        "/acme-authorization/{@id}/acme-server/sync.json",
    )

    # !!!: AcmeAuthorizationPotenials
    config.add_route_7("admin:acme_authorization_potentials", "/acme-authz-potentials")
    config.add_route_7(
        "admin:acme_authorization_potentials_paginated",
        "/acme-authz-potentials/{@page}",
    )
    config.add_route_7(
        "admin:acme_authorization_potentials|json", "/acme-authz-potentials.json"
    )
    config.add_route_7(
        "admin:acme_authorization_potentials_paginated|json",
        "/acme-authz-potentials/{@page}.json",
    )
    config.add_route_7(
        "admin:acme_authorization_potential:focus", "/acme-authz-potential/{@id}"
    )
    config.add_route_7(
        "admin:acme_authorization_potential:focus|json",
        "/acme-authz-potential/{@id}.json",
    )
    config.add_route_7(
        "admin:acme_authorization_potential:focus:delete",
        "/acme-authz-potential/{@id}/delete",
    )
    config.add_route_7(
        "admin:acme_authorization_potential:focus:delete|json",
        "/acme-authz-potential/{@id}/delete.json",
    )

    # !!!: AcmeChallenge
    config.add_route_7("admin:acme_challenges", "/acme-challenges")
    config.add_route_7("admin:acme_challenges_paginated", "/acme-challenges/{@page}")

    config.add_route_7("admin:acme_challenges|json", "/acme-challenges.json")
    config.add_route_7(
        "admin:acme_challenges_paginated|json", "/acme-challenges/{@page}.json"
    )

    config.add_route_7("admin:acme_challenge:focus", "/acme-challenge/{@id}")
    config.add_route_7("admin:acme_challenge:focus|json", "/acme-challenge/{@id}.json")
    config.add_route_7(
        "admin:acme_challenge:focus:acme_server:sync",
        "/acme-challenge/{@id}/acme-server/sync",
    )
    config.add_route_7(
        "admin:acme_challenge:focus:acme_server:sync|json",
        "/acme-challenge/{@id}/acme-server/sync.json",
    )
    config.add_route_7(
        "admin:acme_challenge:focus:acme_server:trigger",
        "/acme-challenge/{@id}/acme-server/trigger",
    )
    config.add_route_7(
        "admin:acme_challenge:focus:acme_server:trigger|json",
        "/acme-challenge/{@id}/acme-server/trigger.json",
    )

    # !!!: AcmeChallenge Poll
    config.add_route_7("admin:acme_challenge_polls", "/acme-challenge-polls")
    config.add_route_7(
        "admin:acme_challenge_polls_paginated", "/acme-challenge-polls/{@page}"
    )
    config.add_route_7("admin:acme_challenge_polls|json", "/acme-challenge-polls.json")
    config.add_route_7(
        "admin:acme_challenge_polls_paginated|json",
        "/acme-challenge-polls/{@page}.json",
    )

    # !!!: AcmeChallengeUnknown Poll
    config.add_route_7(
        "admin:acme_challenge_unknown_polls", "/acme-challenge-unknown-polls"
    )
    config.add_route_7(
        "admin:acme_challenge_unknown_polls_paginated",
        "/acme-challenge-unknown-polls/{@page}",
    )
    config.add_route_7(
        "admin:acme_challenge_unknown_polls|json", "/acme-challenge-unknown-polls.json"
    )
    config.add_route_7(
        "admin:acme_challenge_unknown_polls_paginated|json",
        "/acme-challenge-unknown-polls/{@page}.json",
    )

    # !!!: AcmeDnsServer
    config.add_route_7("admin:acme_dns_server:new", "/acme-dns-server/new")
    config.add_route_7("admin:acme_dns_server:new|json", "/acme-dns-server/new.json")
    config.add_route_7("admin:acme_dns_servers", "/acme-dns-servers")
    config.add_route_7("admin:acme_dns_servers_paginated", "/acme-dns-servers/{@page}")
    config.add_route_7("admin:acme_dns_servers|json", "/acme-dns-servers.json")
    config.add_route_7(
        "admin:acme_dns_servers_paginated|json", "/acme-dns-servers/{@page}.json"
    )
    config.add_route_7("admin:acme_dns_server:focus", "/acme-dns-server/{@id}")
    config.add_route_7(
        "admin:acme_dns_server:focus|json", "/acme-dns-server/{@id}.json"
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:mark", "/acme-dns-server/{@id}/mark"
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:mark|json", "/acme-dns-server/{@id}/mark.json"
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:check", "/acme-dns-server/{@id}/check"
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:check|json", "/acme-dns-server/{@id}/check.json"
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:edit", "/acme-dns-server/{@id}/edit"
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:edit|json", "/acme-dns-server/{@id}/edit.json"
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:ensure_domains",
        "/acme-dns-server/{@id}/ensure-domains",
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:ensure_domains|json",
        "/acme-dns-server/{@id}/ensure-domains.json",
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:ensure_domains_results",
        "/acme-dns-server/{@id}/ensure-domains-results",
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:ensure_domains_results|json",
        "/acme-dns-server/{@id}/ensure-domains-results.json",
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:import_domain",
        "/acme-dns-server/{@id}/import-domain",
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:import_domain|json",
        "/acme-dns-server/{@id}/import-domain.json",
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:acme_dns_server_accounts",
        "/acme-dns-server/{@id}/acme-dns-server-accounts",
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:acme_dns_server_accounts|json",
        "/acme-dns-server/{@id}/acme-dns-server-accounts.json",
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:acme_dns_server_accounts_paginated",
        "/acme-dns-server/{@id}/acme-dns-server-accounts/{@page}",
    )
    config.add_route_7(
        "admin:acme_dns_server:focus:acme_dns_server_accounts_paginated|json",
        "/acme-dns-server/{@id}/acme-dns-server-accounts/{@page}.json",
    )

    # !!!: AcmeDnsServer Accounts
    config.add_route_7("admin:acme_dns_server_accounts", "/acme-dns-server-accounts")
    config.add_route_7(
        "admin:acme_dns_server_accounts_paginated", "/acme-dns-server-accounts/{@page}"
    )
    config.add_route_7(
        "admin:acme_dns_server_accounts|json", "/acme-dns-server-accounts.json"
    )
    config.add_route_7(
        "admin:acme_dns_server_accounts_paginated|json",
        "/acme-dns-server-accounts/{@page}.json",
    )
    config.add_route_7(
        "admin:acme_dns_server_account:focus",
        "/acme-dns-server-account/{@id}",
    )
    config.add_route_7(
        "admin:acme_dns_server_account:focus|json",
        "/acme-dns-server-account/{@id}.json",
    )

    # !!!: AcmeEventLog
    config.add_route_7("admin:acme_event_log", "/acme-event-logs")
    config.add_route_7("admin:acme_event_log_paginated", "/acme-event-logs/{@page}")

    config.add_route_7("admin:acme_event_log|json", "/acme-event-logs.json")
    config.add_route_7(
        "admin:acme_event_log_paginated|json", "/acme-event-logs/{@page}.json"
    )

    config.add_route_7("admin:acme_event_log:focus", "/acme-event-log/{@id}")
    config.add_route_7("admin:acme_event_log:focus|json", "/acme-event-log/{@id}.json")

    # !!!: AcmeOrder
    config.add_route_7("admin:acme_orders", "/acme-orders")
    config.add_route_7("admin:acme_orders|json", "/acme-orders.json")
    config.add_route_7("admin:acme_orders:all", "/acme-orders/all")
    config.add_route_7("admin:acme_orders:all|json", "/acme-orders/all.json")
    config.add_route_7("admin:acme_orders:all_paginated", "/acme-orders/all/{@page}")
    config.add_route_7(
        "admin:acme_orders:all_paginated|json", "/acme-orders/all/{@page}.json"
    )
    config.add_route_7("admin:acme_orders:active", "/acme-orders/active")
    config.add_route_7("admin:acme_orders:active|json", "/acme-orders/active.json")
    config.add_route_7(
        "admin:acme_orders:active_paginated", "/acme-orders/active/{@page}"
    )
    config.add_route_7(
        "admin:acme_orders:active_paginated|json", "/acme-orders/active/{@page}.json"
    )
    config.add_route_7("admin:acme_orders:finished", "/acme-orders/finished")
    config.add_route_7("admin:acme_orders:finished|json", "/acme-orders/finished.json")
    config.add_route_7(
        "admin:acme_orders:finished_paginated", "/acme-orders/finished/{@page}"
    )
    config.add_route_7(
        "admin:acme_orders:finished_paginated|json",
        "/acme-orders/finished/{@page}.json",
    )
    config.add_route_7(
        "admin:acme_orders:active:acme_server:sync",
        "/acme-orders/active/acme-server/sync",
    )
    config.add_route_7(
        "admin:acme_orders:active:acme_server:sync|json",
        "/acme-orders/active/acme-server/sync.json",
    )
    config.add_route_7("admin:acme_order:focus|json", "/acme-order/{@id}.json")
    config.add_route_7("admin:acme_order:focus", "/acme-order/{@id}")
    config.add_route_7(
        "admin:acme_order:focus:audit|json", "/acme-order/{@id}/audit.json"
    )
    config.add_route_7("admin:acme_order:focus:audit", "/acme-order/{@id}/audit")

    config.add_route_7(
        "admin:acme_order:focus:acme_event_logs", "/acme-order/{@id}/acme-event-logs"
    )
    config.add_route_7(
        "admin:acme_order:focus:acme_event_logs_paginated",
        "/acme-order/{@id}/acme-event-logs/{@page}",
    )

    config.add_route_7(
        "admin:acme_order:focus:acme_process", "/acme-order/{@id}/acme-process"
    )
    config.add_route_7(
        "admin:acme_order:focus:acme_process|json",
        "/acme-order/{@id}/acme-process.json",
    )
    config.add_route_7(
        "admin:acme_order:focus:acme_finalize", "/acme-order/{@id}/acme-finalize"
    )
    config.add_route_7(
        "admin:acme_order:focus:acme_finalize|json",
        "/acme-order/{@id}/acme-finalize.json",
    )
    config.add_route_7(
        "admin:acme_order:focus:acme_server:sync", "/acme-order/{@id}/acme-server/sync"
    )
    config.add_route_7(
        "admin:acme_order:focus:acme_server:sync|json",
        "/acme-order/{@id}/acme-server/sync.json",
    )
    config.add_route_7(
        "admin:acme_order:focus:acme_server:sync_authorizations",
        "/acme-order/{@id}/acme-server/sync-authorizations",
    )
    config.add_route_7(
        "admin:acme_order:focus:acme_server:sync_authorizations|json",
        "/acme-order/{@id}/acme-server/sync-authorizations.json",
    )
    config.add_route_7(
        "admin:acme_order:focus:acme_server:deactivate_authorizations",
        "/acme-order/{@id}/acme-server/deactivate-authorizations",
    )
    config.add_route_7(
        "admin:acme_order:focus:acme_server:deactivate_authorizations|json",
        "/acme-order/{@id}/acme-server/deactivate-authorizations.json",
    )
    config.add_route_7(
        "admin:acme_order:focus:acme_server:download_certificate",
        "/acme-order/{@id}/acme-server/download-certificate",
    )
    config.add_route_7(
        "admin:acme_order:focus:acme_server:download_certificate|json",
        "/acme-order/{@id}/acme-server/download-certificate.json",
    )

    config.add_route_7("admin:acme_order:focus:mark", "/acme-order/{@id}/mark")
    config.add_route_7(
        "admin:acme_order:focus:mark|json", "/acme-order/{@id}/mark.json"
    )
    config.add_route_7("admin:acme_order:focus:retry", "/acme-order/{@id}/retry")
    config.add_route_7(
        "admin:acme_order:focus:retry|json", "/acme-order/{@id}/retry.json"
    )
    config.add_route_7("admin:acme_order:new:freeform", "/acme-order/new/freeform")
    config.add_route_7(
        "admin:acme_order:new:freeform|json", "/acme-order/new/freeform.json"
    )

    # !!!: AcmeServer
    # this is just letsencrypt endpoints
    config.add_route_7("admin:acme_servers", "/acme-servers")
    config.add_route_7("admin:acme_servers|json", "/acme-servers.json")
    config.add_route_7("admin:acme_server:focus", "/acme-server/{@id}")
    config.add_route_7("admin:acme_server:focus|json", "/acme-server/{@id}.json")
    config.add_route_7(
        "admin:acme_server:focus:acme_accounts", "/acme-server/{@id}/acme-accounts"
    )
    config.add_route_7(
        "admin:acme_server:focus:acme_accounts|json",
        "/acme-server/{@id}/acme-accounts.json",
    )
    config.add_route_7(
        "admin:acme_server:focus:acme_accounts__paginated",
        "/acme-server/{@id}/acme-accounts/{@page}",
    )
    config.add_route_7(
        "admin:acme_server:focus:acme_accounts__paginated|json",
        "/acme-server/{@id}/acme-accounts/{@page}.json",
    )
    config.add_route_7(
        "admin:acme_server:focus:check_support",
        "/acme-server/{@id}/check-support",
    )
    config.add_route_7(
        "admin:acme_server:focus:check_support|json",
        "/acme-server/{@id}/check-support.json",
    )
    config.add_route_7("admin:acme_server:focus:mark", "/acme-server/{@id}/mark")
    config.add_route_7(
        "admin:acme_server:focus:mark|json", "/acme-server/{@id}/mark.json"
    )

    # !!!: Admin API Items
    config.add_route_7("admin:api", "/api")
    config.add_route_7(
        "admin:api:domain:certificate-if-needed", "/api/domain/certificate-if-needed"
    )
    config.add_route_7("admin:api:domain:autocert", "/api/domain/autocert")
    config.add_route_7("admin:api:domain:autocert|json", "/api/domain/autocert.json")

    # -
    config.add_route_7("admin:api:deactivate_expired", "/api/deactivate-expired")
    config.add_route_7(
        "admin:api:deactivate_expired|json", "/api/deactivate-expired.json"
    )
    # -
    config.add_route_7("admin:api:nginx:cache_flush", "/api/nginx/cache-flush")
    config.add_route_7(
        "admin:api:nginx:cache_flush|json", "/api/nginx/cache-flush.json"
    )
    config.add_route_7("admin:api:redis:prime", "/api/redis/prime")
    config.add_route_7("admin:api:redis:prime|json", "/api/redis/prime.json")
    config.add_route_7("admin:api:nginx:status|json", "/api/nginx/status.json")

    config.add_route_7("admin:api:update_recents", "/api/update-recents")
    config.add_route_7("admin:api:update_recents|json", "/api/update-recents.json")

    config.add_route_7("admin:api:reconcile_cas", "/api/reconcile-cas")
    config.add_route_7("admin:api:reconcile_cas|json", "/api/reconcile-cas.json")

    config.add_route_7("admin:api:version", "/api/version")
    config.add_route_7("admin:api:version|json", "/api/version.json")

    # !!!: AriCheck
    # config.add_route_7("admin:ari_check", "/ari-check")
    # config.add_route_7("admin:ari_check|json", "/ari-check.json")
    config.add_route_7("admin:ari_check:focus", "/ari-check/{@id}")
    config.add_route_7("admin:ari_check:focus|json", "/ari-check/{@id}.json")

    config.add_route_7("admin:ari_checks", "/ari-checks")
    config.add_route_7("admin:ari_checks|json", "/ari-checks.json")

    config.add_route_7("admin:ari_checks:all", "/ari-checks/all")
    config.add_route_7("admin:ari_checks:all|json", "/ari-checks/all.json")
    config.add_route_7("admin:ari_checks:all_paginated", "/ari-checks/all/{@page}")
    config.add_route_7(
        "admin:ari_checks:all_paginated|json", "/ari-checks/all/{@page}.json"
    )

    config.add_route_7("admin:ari_checks:cert_latest", "/ari-checks/cert-latest")
    config.add_route_7(
        "admin:ari_checks:cert_latest|json", "/ari-checks/cert-latest.json"
    )
    config.add_route_7(
        "admin:ari_checks:cert_latest_paginated", "/ari-checks/cert-latest/{@page}"
    )
    config.add_route_7(
        "admin:ari_checks:cert_latest_paginated|json",
        "/ari-checks/cert-latest/{@page}.json",
    )

    config.add_route_7(
        "admin:ari_checks:cert_latest_overdue", "/ari-checks/cert-latest-overdue"
    )
    config.add_route_7(
        "admin:ari_checks:cert_latest_overdue|json",
        "/ari-checks/cert-latest-overdue.json",
    )
    config.add_route_7(
        "admin:ari_checks:cert_latest_overdue_paginated",
        "/ari-checks/cert-latest-overdue/{@page}",
    )
    config.add_route_7(
        "admin:ari_checks:cert_latest_overdue_paginated|json",
        "/ari-checks/cert-latest-overdue/{@page}.json",
    )

    # !!!: CertificateCAs (Certificate Authority)
    config.add_route_7("admin:certificate_cas", "/certificate-cas")
    config.add_route_7("admin:certificate_cas_paginated", "/certificate-cas/{@page}")
    config.add_route_7("admin:certificate_cas|json", "/certificate-cas.json")
    config.add_route_7(
        "admin:certificate_cas_paginated|json", "/certificate-cas/{@page}.json"
    )
    config.add_route_7("admin:certificate_cas:preferred", "/certificate-cas/preferred")
    config.add_route_7(
        "admin:certificate_cas:preferred|json", "/certificate-cas/preferred.json"
    )
    config.add_route_7(
        "admin:certificate_cas:preferred:add", "/certificate-cas/preferred/add"
    )
    config.add_route_7(
        "admin:certificate_cas:preferred:add|json",
        "/certificate-cas/preferred/add.json",
    )
    config.add_route_7(
        "admin:certificate_cas:preferred:delete", "/certificate-cas/preferred/delete"
    )
    config.add_route_7(
        "admin:certificate_cas:preferred:delete|json",
        "/certificate-cas/preferred/delete.json",
    )
    config.add_route_7(
        "admin:certificate_cas:preferred:prioritize",
        "/certificate-cas/preferred/prioritize",
    )
    config.add_route_7(
        "admin:certificate_cas:preferred:prioritize|json",
        "/certificate-cas/preferred/prioritize.json",
    )

    config.add_route_7("admin:certificate_ca:focus", "/certificate-ca/{@id}")
    config.add_route_7("admin:certificate_ca:focus|json", "/certificate-ca/{@id}.json")
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
        "admin:certificate_ca:upload_cert", "/certificate-ca/upload-cert"
    )
    config.add_route_7(
        "admin:certificate_ca:upload_cert|json", "/certificate-ca/upload-cert.json"
    )

    # !!!: CertificateCAChains (Certificate Authority)
    config.add_route_7("admin:certificate_ca_chains", "/certificate-ca-chains")
    config.add_route_7(
        "admin:certificate_ca_chains_paginated", "/certificate-ca-chains/{@page}"
    )
    config.add_route_7(
        "admin:certificate_ca_chains|json", "/certificate-ca-chains.json"
    )
    config.add_route_7(
        "admin:certificate_ca_chains_paginated|json",
        "/certificate-ca-chains/{@page}.json",
    )
    config.add_route_7(
        "admin:certificate_ca_chain:focus", "/certificate-ca-chain/{@id}"
    )
    config.add_route_7(
        "admin:certificate_ca_chain:focus|json", "/certificate-ca-chain/{@id}.json"
    )
    config.add_route_7(
        "admin:certificate_ca_chain:focus:raw",
        "/certificate-ca-chain/{@id}/chain.{format:(pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:certificate_ca_chain:upload_chain", "/certificate-ca-chain/upload-chain"
    )
    config.add_route_7(
        "admin:certificate_ca_chain:upload_chain|json",
        "/certificate-ca-chain/upload-chain.json",
    )

    # !!!: Certificate Requests
    config.add_route_7("admin:certificate_requests", "/certificate-requests")
    config.add_route_7(
        "admin:certificate_requests_paginated", "/certificate-requests/{@page}"
    )
    config.add_route_7("admin:certificate_requests|json", "/certificate-requests.json")
    config.add_route_7(
        "admin:certificate_requests_paginated|json",
        "/certificate-requests/{@page}.json",
    )

    # !!!: Certificate Request - Focus
    config.add_route_7("admin:certificate_request:focus", "/certificate-request/{@id}")
    config.add_route_7(
        "admin:certificate_request:focus|json", "/certificate-request/{@id}.json"
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
    config.add_route_7("admin:certificate_signeds", "/certificate-signeds")

    config.add_route_7("admin:certificate_signeds:all", "/certificate-signeds/all")
    config.add_route_7(
        "admin:certificate_signeds:all_paginated",
        "/certificate-signeds/all/{@page}",
    )
    config.add_route_7(
        "admin:certificate_signeds:active", "/certificate-signeds/active"
    )
    config.add_route_7(
        "admin:certificate_signeds:active_paginated",
        "/certificate-signeds/active/{@page}",
    )
    config.add_route_7(
        "admin:certificate_signeds:active_expired",
        "/certificate-signeds/active-expired",
    )
    config.add_route_7(
        "admin:certificate_signeds:active_expired_paginated",
        "/certificate-signeds/active-expired/{@page}",
    )
    config.add_route_7(
        "admin:certificate_signeds:expiring", "/certificate-signeds/expiring"
    )
    config.add_route_7(
        "admin:certificate_signeds:expiring_paginated",
        "/certificate-signeds/expiring/{@page}",
    )
    config.add_route_7(
        "admin:certificate_signeds:inactive", "/certificate-signeds/inactive"
    )
    config.add_route_7(
        "admin:certificate_signeds:inactive_paginated",
        "/certificate-signeds/inactive/{@page}",
    )
    config.add_route_7(
        "admin:certificate_signeds:inactive_unexpired",
        "/certificate-signeds/inactive-unexpired",
    )
    config.add_route_7(
        "admin:certificate_signeds:inactive_unexpired_paginated",
        "/certificate-signeds/inactive-unexpired/{@page}",
    )
    config.add_route_7("admin:certificate_signeds|json", "/certificate-signeds.json")
    config.add_route_7(
        "admin:certificate_signeds:all|json", "/certificate-signeds/all.json"
    )
    config.add_route_7(
        "admin:certificate_signeds:all_paginated|json",
        "/certificate-signeds/all/{@page}.json",
    )
    config.add_route_7(
        "admin:certificate_signeds:active|json", "/certificate-signeds/active.json"
    )
    config.add_route_7(
        "admin:certificate_signeds:active_paginated|json",
        "/certificate-signeds/active/{@page}.json",
    )
    config.add_route_7(
        "admin:certificate_signeds:active_expired|json",
        "/certificate-signeds/active-expired.json",
    )
    config.add_route_7(
        "admin:certificate_signeds:active_expired_paginated|json",
        "/certificate-signeds/active-expired/{@page}.json",
    )
    config.add_route_7(
        "admin:certificate_signeds:expiring|json", "/certificate-signeds/expiring.json"
    )
    config.add_route_7(
        "admin:certificate_signeds:expiring_paginated|json",
        "/certificate-signeds/expiring/{@page}.json",
    )
    config.add_route_7(
        "admin:certificate_signeds:inactive|json", "/certificate-signeds/inactive.json"
    )
    config.add_route_7(
        "admin:certificate_signeds:inactive_paginated|json",
        "/certificate-signeds/inactive/{@page}.json",
    )
    config.add_route_7(
        "admin:certificate_signeds:inactive_unexpired|json",
        "/certificate-signeds/inactive-unexpired.json",
    )
    config.add_route_7(
        "admin:certificate_signeds:inactive_unexpired_paginated|json",
        "/certificate-signeds/inactive-unexpired/{@page}.json",
    )

    # !!!: CertificateSigned - Focus
    config.add_route_7("admin:certificate_signed:focus", "/certificate-signed/{@id}")
    config.add_route_7(
        "admin:certificate_signed:focus|json", "/certificate-signed/{@id}.json"
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
    )
    config.add_route_7(
        "admin:certificate_signed:focus:ari_check|json",
        r"/certificate-signed/{@id}/ari-check.json",
    )
    config.add_route_7(
        "admin:certificate_signed:focus:ari_check_history",
        r"/certificate-signed/{@id}/ari-check-history",
    )
    config.add_route_7(
        "admin:certificate_signed:focus:ari_check_history|json",
        r"/certificate-signed/{@id}/ari-check-history.json",
    )
    config.add_route_7(
        "admin:certificate_signed:focus:ari_check_history__paginated",
        r"/certificate-signed/{@id}/ari-check-history/{@page}",
    )
    config.add_route_7(
        "admin:certificate_signed:focus:ari_check_history__paginated|json",
        r"/certificate-signed/{@id}/ari-check-history/{@page}.json",
    )
    config.add_route_7(
        "admin:certificate_signed:focus:nginx_cache_expire",
        r"/certificate-signed/{@id}/nginx-cache-expire",
    )
    config.add_route_7(
        "admin:certificate_signed:focus:nginx_cache_expire|json",
        r"/certificate-signed/{@id}/nginx-cache-expire.json",
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

    config.add_route_7("admin:certificate_signed:upload", "/certificate-signed/upload")
    config.add_route_7(
        "admin:certificate_signed:upload|json", "/certificate-signed/upload.json"
    )
    config.add_route_7(
        "admin:certificate_signed:focus:mark", "/certificate-signed/{@id}/mark"
    )
    config.add_route_7(
        "admin:certificate_signed:focus:mark|json",
        "/certificate-signed/{@id}/mark.json",
    )

    # !!!: CoverageAssuranceEvents
    config.add_route_7("admin:coverage_assurance_events", "/coverage-assurance-events")
    config.add_route_7(
        "admin:coverage_assurance_events:all", "/coverage-assurance-events/all"
    )
    config.add_route_7(
        "admin:coverage_assurance_events:all_paginated",
        "/coverage-assurance-events/all/{@page}",
    )
    config.add_route_7(
        "admin:coverage_assurance_events:unresolved",
        "/coverage-assurance-events/unresolved",
    )
    config.add_route_7(
        "admin:coverage_assurance_events:unresolved_paginated",
        "/coverage-assurance-events/unresolved/{@page}",
    )
    config.add_route_7(
        "admin:coverage_assurance_events:all|json",
        "/coverage-assurance-events/all.json",
    )
    config.add_route_7(
        "admin:coverage_assurance_events:all_paginated|json",
        "/coverage-assurance-events/all/{@page}.json",
    )
    config.add_route_7(
        "admin:coverage_assurance_events:unresolved|json",
        "/coverage-assurance-events/unresolved.json",
    )
    config.add_route_7(
        "admin:coverage_assurance_events:unresolved_paginated|json",
        "/coverage-assurance-events/unresolved/{@page}.json",
    )

    # !!!: CoverageAssuranceEvent - Focus
    config.add_route_7(
        "admin:coverage_assurance_event:focus", "/coverage-assurance-event/{@id}"
    )
    config.add_route_7(
        "admin:coverage_assurance_event:focus|json",
        "/coverage-assurance-event/{@id}.json",
    )
    config.add_route_7(
        "admin:coverage_assurance_event:focus:children",
        "/coverage-assurance-event/{@id}/children",
    )
    config.add_route_7(
        "admin:coverage_assurance_event:focus:children|json",
        "/coverage-assurance-event/{@id}/children.json",
    )
    config.add_route_7(
        "admin:coverage_assurance_event:focus:mark",
        "/coverage-assurance-event/{@id}/mark",
    )
    config.add_route_7(
        "admin:coverage_assurance_event:focus:mark|json",
        "/coverage-assurance-event/{@id}/mark.json",
    )

    # !!!: Domains
    config.add_route_7("admin:domains", "/domains")
    config.add_route_7("admin:domains|json", "/domains.json")
    config.add_route_7("admin:domains_paginated", "/domains/{@page}")
    config.add_route_7("admin:domains_paginated|json", "/domains/{@page}.json")
    config.add_route_7("admin:domains:challenged", "/domains/challenged")
    config.add_route_7("admin:domains:challenged|json", "/domains/challenged.json")
    config.add_route_7(
        "admin:domains:challenged_paginated", "/domains/challenged/{@page}"
    )
    config.add_route_7(
        "admin:domains:challenged_paginated|json", "/domains/challenged/{@page}.json"
    )
    config.add_route_7("admin:domains:authz_potential", "/domains/authz-potential")
    config.add_route_7(
        "admin:domains:authz_potential|json", "/domains/authz-potential.json"
    )
    config.add_route_7(
        "admin:domains:authz_potential_paginated", "/domains/authz-potential/{@page}"
    )
    config.add_route_7(
        "admin:domains:authz_potential_paginated|json",
        "/domains/authz-potential/{@page}.json",
    )
    config.add_route_7("admin:domains:expiring", "/domains/expiring")
    config.add_route_7("admin:domains:expiring|json", "/domains/expiring.json")
    config.add_route_7("admin:domains:expiring_paginated", "/domains/expiring/{@page}")
    config.add_route_7(
        "admin:domains:expiring_paginated|json", "/domains/expiring/{@page}.json"
    )
    config.add_route_7("admin:domains:search", "/domains/search")
    config.add_route_7("admin:domains:search|json", "/domains/search.json")
    config.add_route_7("admin:domain:new", "/domain/new")
    config.add_route_7("admin:domain:new|json", "/domain/new.json")

    # !!!: Domain Focus
    # json first otherwise we think it's the extension
    config.add_route_7("admin:domain:focus|json", "/domain/{domain_identifier}.json")
    config.add_route_7("admin:domain:focus", "/domain/{domain_identifier}")
    config.add_route_7(
        "admin:domain:focus:config|json", "/domain/{domain_identifier}/config.json"
    )
    config.add_route_7(
        "admin:domain:focus:calendar|json", "/domain/{domain_identifier}/calendar.json"
    )
    config.add_route_7(
        "admin:domain:focus:update_recents|json",
        "/domain/{domain_identifier}/update-recents.json",
    )
    config.add_route_7(
        "admin:domain:focus:update_recents",
        "/domain/{domain_identifier}/update-recents",
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
    )
    config.add_route_7(
        "admin:domain:focus:nginx_cache_expire|json",
        "/domain/{domain_identifier}/nginx-cache-expire.json",
    )
    config.add_route_7(
        "admin:domain:focus:acme_dns_server_accounts",
        "/domain/{domain_identifier}/acme-dns-server-accounts",
    )
    config.add_route_7(
        "admin:domain:focus:acme_dns_server_accounts|json",
        "/domain/{domain_identifier}/acme-dns-server-accounts.json",
    )
    config.add_route_7(
        "admin:domain:focus:acme_dns_server:new",
        "/domain/{domain_identifier}/acme-dns-server/new",
    )
    config.add_route_7(
        "admin:domain:focus:acme_dns_server:new|json",
        "/domain/{domain_identifier}/acme-dns-server/new.json",
    )

    # !!!: DomainAutocerts
    config.add_route_7("admin:domain_autocerts", "/domain-autocerts")
    config.add_route_7("admin:domain_autocerts|json", "/domain-autocerts.json")
    config.add_route_7("admin:domain_autocerts_paginated", "/domain-autocerts/{@page}")
    config.add_route_7(
        "admin:domain_autocerts_paginated|json", "/domain-autocerts/{@page}.json"
    )

    # !!!: DomainBlocklist
    config.add_route_7("admin:domains_blocklisted", "/domains-blocklisted")
    config.add_route_7("admin:domains_blocklisted|json", "/domains-blocklisted.json")
    config.add_route_7(
        "admin:domains_blocklisted_paginated", "/domains-blocklisted/{@page}"
    )
    config.add_route_7(
        "admin:domains_blocklisted_paginated|json", "/domains-blocklisted/{@page}.json"
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
    config.add_route_7("admin:private_keys", "/private-keys")
    config.add_route_7("admin:private_keys_paginated", "/private-keys/{@page}")
    config.add_route_7("admin:private_keys|json", "/private-keys.json")
    config.add_route_7(
        "admin:private_keys_paginated|json", "/private-keys/{@page}.json"
    )

    # !!!: Private Key - Focus
    config.add_route_7("admin:private_key:focus", "/private-key/{@id}")
    config.add_route_7("admin:private_key:focus|json", "/private-key/{@id}.json")
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
    config.add_route_7("admin:private_key:focus:mark", "/private-key/{@id}/mark")
    config.add_route_7(
        "admin:private_key:focus:mark|json", "/private-key/{@id}/mark.json"
    )

    # !!!: Private Key - New
    config.add_route_7("admin:private_key:new", "/private-key/new")
    config.add_route_7("admin:private_key:new|json", "/private-key/new.json")
    config.add_route_7("admin:private_key:upload", "/private-key/upload")
    config.add_route_7("admin:private_key:upload|json", "/private-key/upload.json")

    # !!!: Renewal Configurations
    config.add_route_7("admin:renewal_configurations", "/renewal-configurations")
    config.add_route_7(
        "admin:renewal_configurations|json", "/renewal-configurations.json"
    )
    config.add_route_7(
        "admin:renewal_configurations:all", "/renewal-configurations/all"
    )
    config.add_route_7(
        "admin:renewal_configurations:all|json", "/renewal-configurations/all.json"
    )
    config.add_route_7(
        "admin:renewal_configurations:all_paginated",
        "/renewal-configurations/all/{@page}",
    )
    config.add_route_7(
        "admin:renewal_configurations:all_paginated|json",
        "/renewal-configurations/all/{@page}.json",
    )
    config.add_route_7(
        "admin:renewal_configurations:active", "/renewal-configurations/active"
    )
    config.add_route_7(
        "admin:renewal_configurations:active|json",
        "/renewal-configurations/active.json",
    )
    config.add_route_7(
        "admin:renewal_configurations:active_paginated",
        "/renewal-configurations/active/{@page}",
    )
    config.add_route_7(
        "admin:renewal_configurations:active_paginated|json",
        "/renewal-configurations/active/{@page}.json",
    )
    config.add_route_7(
        "admin:renewal_configurations:disabled", "/renewal-configurations/disabled"
    )
    config.add_route_7(
        "admin:renewal_configurations:disabled|json",
        "/renewal-configurations/disabled.json",
    )
    config.add_route_7(
        "admin:renewal_configurations:disabled_paginated",
        "/renewal-configurations/disabled/{@page}",
    )
    config.add_route_7(
        "admin:renewal_configurations:disabled_paginated|json",
        "/renewal-configurations/disabled/{@page}.json",
    )
    config.add_route_7("admin:renewal_configuration:new", "/renewal-configuration/new")
    config.add_route_7(
        "admin:renewal_configuration:new|json", "/renewal-configuration/new.json"
    )
    config.add_route_7(
        "admin:renewal_configuration:focus", "/renewal-configuration/{@id}"
    )
    config.add_route_7(
        "admin:renewal_configuration:focus|json", "/renewal-configuration/{@id}.json"
    )
    config.add_route_7(
        "admin:renewal_configuration:focus:acme_orders",
        "/renewal-configuration/{@id}/acme-orders",
    )
    config.add_route_7(
        "admin:renewal_configuration:focus:acme_orders_paginated",
        "/renewal-configuration/{@id}/acme-orders/{@page}",
    )
    config.add_route_7(
        "admin:renewal_configuration:focus:acme_orders|json",
        "/renewal-configuration/{@id}/acme-orders.json",
    )
    config.add_route_7(
        "admin:renewal_configuration:focus:acme_orders_paginated|json",
        "/renewal-configuration/{@id}/acme-orders/{@page}.json",
    )
    config.add_route_7(
        "admin:renewal_configuration:focus:certificate_signeds",
        "/renewal-configuration/{@id}/certificate-signeds",
    )
    config.add_route_7(
        "admin:renewal_configuration:focus:certificate_signeds_paginated",
        "/renewal-configuration/{@id}/certificate-signeds/{@page}",
    )
    config.add_route_7(
        "admin:renewal_configuration:focus:certificate_signeds|json",
        "/renewal-configuration/{@id}/certificate-signeds.json",
    )
    config.add_route_7(
        "admin:renewal_configuration:focus:certificate_signeds_paginated|json",
        "/renewal-configuration/{@id}/certificate-signeds/{@page}.json",
    )

    config.add_route_7(
        "admin:renewal_configuration:focus:mark", "/renewal-configuration/{@id}/mark"
    )
    config.add_route_7(
        "admin:renewal_configuration:focus:mark|json",
        "/renewal-configuration/{@id}/mark.json",
    )
    config.add_route_7(
        "admin:renewal_configuration:focus:new_order",
        "/renewal-configuration/{@id}/new-order",
    )
    config.add_route_7(
        "admin:renewal_configuration:focus:new_order|json",
        "/renewal-configuration/{@id}/new-order.json",
    )
    config.add_route_7(
        "admin:renewal_configuration:focus:new_configuration",
        "/renewal-configuration/{@id}/new-configuration",
    )
    config.add_route_7(
        "admin:renewal_configuration:focus:new_configuration|json",
        "/renewal-configuration/{@id}/new-configuration.json",
    )

    # !!!: Root Stores
    config.add_route_7("admin:root_stores", "/root-stores")
    config.add_route_7("admin:root_stores_paginated", "/root-stores/{@page}")
    config.add_route_7("admin:root_stores|json", "/root-stores.json")
    config.add_route_7("admin:root_stores_paginated|json", "/root-stores/{@page}.json")

    # !!!: Root Store - Focus
    config.add_route_7("admin:root_store:focus", "/root-store/{@id}")
    config.add_route_7("admin:root_store:focus|json", "/root-store/{@id}.json")

    # !!!: Root Store Version - Focus
    config.add_route_7("admin:root_store_version:focus", "/root-store-version/{@id}")
    config.add_route_7(
        "admin:root_store_version:focus|json", "/root-store-version/{@id}.json"
    )

    # !!!: Unique FQDN Sets
    # tied to Certs and Ratelimits
    config.add_route_7("admin:unique_fqdn_sets", "/unique-fqdn-sets")
    config.add_route_7("admin:unique_fqdn_sets_paginated", "/unique-fqdn-sets/{@page}")
    config.add_route_7("admin:unique_fqdn_sets|json", "/unique-fqdn-sets.json")
    config.add_route_7(
        "admin:unique_fqdn_sets_paginated|json", "/unique-fqdn-sets/{@page}.json"
    )

    # !!!: Unique FQDN Set - Focus
    config.add_route_7("admin:unique_fqdn_set:focus", "/unique-fqdn-set/{@id}")
    config.add_route_7(
        "admin:unique_fqdn_set:focus|json", "/unique-fqdn-set/{@id}.json"
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:calendar|json",
        "/unique-fqdn-set/{@id}/calendar.json",
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:update_recents|json",
        "/unique-fqdn-set/{id}/update-recents.json",
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:update_recents",
        "/unique-fqdn-set/{id}/update-recents",
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
        "admin:unique_fqdn_set:focus:modify", "/unique-fqdn-set/{@id}/modify"
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:modify|json", "/unique-fqdn-set/{@id}/modify.json"
    )
    config.add_route_7("admin:unique_fqdn_set:new", "/unique-fqdn-set/new")
    config.add_route_7("admin:unique_fqdn_set:new|json", "/unique-fqdn-set/new.json")

    # !!!: Uniquely Challenged FQDN Sets
    # tied to RenewalConfigurations and AcmeOrders
    config.add_route_7(
        "admin:uniquely_challenged_fqdn_sets", "/uniquely-challenged-fqdn-sets"
    )
    config.add_route_7(
        "admin:uniquely_challenged_fqdn_sets_paginated",
        "/uniquely-challenged-fqdn-sets/{@page}",
    )
    config.add_route_7(
        "admin:uniquely_challenged_fqdn_sets|json",
        "/uniquely-challenged-fqdn-sets.json",
    )
    config.add_route_7(
        "admin:uniquely_challenged_fqdn_sets_paginated|json",
        "/uniquely-challenged-fqdn-sets/{@page}.json",
    )

    # !!!: Uniquely Challenged FQDN Set - Focus
    config.add_route_7(
        "admin:uniquely_challenged_fqdn_set:focus",
        "/uniquely-challenged-fqdn-set/{@id}",
    )
    config.add_route_7(
        "admin:uniquely_challenged_fqdn_set:focus|json",
        "/uniquely-challenged-fqdn-set/{@id}.json",
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
