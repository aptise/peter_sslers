from ..lib.config_utils import set_bool_setting
from ..lib.config_utils import set_int_setting


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def includeme(config):

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


def _admin_views(config):

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
        "admin:acme_account:focus:config|json",
        "/acme-account/{@id}/config.json",
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
        "admin:acme_account:focus:acme_orders",
        "/acme-account/{@id}/acme-orders",
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_orders_paginated",
        "/acme-account/{@id}/acme-orders/{@page}",
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
        "admin:acme_account:focus:server_certificates",
        "/acme-account/{@id}/server-certificates",
    )
    config.add_route_7(
        "admin:acme_account:focus:server_certificates_paginated",
        "/acme-account/{@id}/server-certificates/{@page}",
    )
    config.add_route_7(
        "admin:acme_account:focus:queue_certificates",
        "/acme-account/{@id}/queue-certificates",
    )
    config.add_route_7(
        "admin:acme_account:focus:queue_certificates_paginated",
        "/acme-account/{@id}/queue-certificates/{@page}",
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
        "admin:acme_account:focus:acme_server:deactivate_pending_authorizations",
        "/acme-account/{@id}/acme-server/deactivate-pending-authorizations",
    )
    config.add_route_7(
        "admin:acme_account:focus:acme_server:deactivate_pending_authorizations|json",
        "/acme-account/{@id}/acme-server/deactivate-pending-authorizations.json",
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
        "admin:acme_orders:active:acme_server:sync",
        "/acme-orders/active/acme-server/sync",
    )
    config.add_route_7(
        "admin:acme_orders:active:acme_server:sync|json",
        "/acme-orders/active/acme-server/sync.json",
    )
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
    config.add_route_7(
        "admin:acme_order:focus:renew:custom",
        "/acme-order/{@id}/renew/custom",
    )
    config.add_route_7(
        "admin:acme_order:focus:renew:custom|json",
        "/acme-order/{@id}/renew/custom.json",
    )
    config.add_route_7(
        "admin:acme_order:focus:renew:quick",
        "/acme-order/{@id}/renew/quick",
    )
    config.add_route_7(
        "admin:acme_order:focus:renew:quick|json",
        "/acme-order/{@id}/renew/quick.json",
    )
    config.add_route_7("admin:acme_order:new:freeform", "/acme-order/new/freeform")
    config.add_route_7(
        "admin:acme_order:new:freeform|json", "/acme-order/new/freeform.json"
    )

    # !!!: AcmeOrderless / AcmeFlow - our manual system
    config.add_route_7("admin:acme_orderlesss", "/acme-orderlesss")
    config.add_route_7("admin:acme_orderlesss_paginated", "/acme-orderlesss/{@page}")

    config.add_route_7("admin:acme_orderlesss|json", "/acme-orderlesss.json")
    config.add_route_7(
        "admin:acme_orderlesss_paginated|json", "/acme-orderlesss/{@page}.json"
    )

    config.add_route_7("admin:acme_orderless:new", "/acme-orderless/new")
    config.add_route_7("admin:acme_orderless:new|json", "/acme-orderless/new.json")

    config.add_route_7(
        "admin:acme_orderless:focus",
        "/acme-orderless/{@id}",
    )
    config.add_route_7("admin:acme_orderless:focus|json", "/acme-orderless/{@id}.json")
    config.add_route_7(
        "admin:acme_orderless:focus:add",
        "/acme-orderless/{@id}/add",
    )
    config.add_route_7(
        "admin:acme_orderless:focus:add|json",
        "/acme-orderless/{@id}/add.json",
    )
    config.add_route_7(
        "admin:acme_orderless:focus:update",
        "/acme-orderless/{@id}/update",
    )
    config.add_route_7(
        "admin:acme_orderless:focus:update|json", "/acme-orderless/{@id}/update.json"
    )
    config.add_route_7(
        "admin:acme_orderless:focus:deactivate",
        "/acme-orderless/{@id}/deactivate",
    )
    config.add_route_7(
        "admin:acme_orderless:focus:deactivate|json",
        "/acme-orderless/{@id}/deactivate.json",
    )

    config.add_route_7(
        "admin:acme_orderless:focus:acme_challenge",
        r"/acme-orderless/{@id}/acme-challenge/{id_challenge:\d+}",
    )
    config.add_route_7(
        "admin:acme_orderless:focus:acme_challenge|json",
        r"/acme-orderless/{@id}/acme-challenge/{id_challenge:\d+}.json",
    )

    # !!!: AcmeProvider
    # this is just letsencrypt endpoints
    config.add_route_7("admin:acme_account_providers", "/acme-account-providers")
    config.add_route_7(
        "admin:acme_account_providers|json", "/acme-account-providers.json"
    )

    # !!!: Admin API Items
    config.add_route_7("admin:api", "/api")
    config.add_route_7("admin:api:domain:enable", "/api/domain/enable")
    config.add_route_7("admin:api:domain:disable", "/api/domain/disable")
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
    config.add_route_7(
        "admin:api:ca_certificate:letsencrypt_download",
        "/api/ca-certificate/letsencrypt-download",
    )
    config.add_route_7(
        "admin:api:ca_certificate:letsencrypt_download|json",
        "/api/ca-certificate/letsencrypt-download.json",
    )
    config.add_route_7("admin:api:nginx:cache_flush", "/api/nginx/cache-flush")
    config.add_route_7(
        "admin:api:nginx:cache_flush|json", "/api/nginx/cache-flush.json"
    )
    config.add_route_7("admin:api:redis:prime", "/api/redis/prime")
    config.add_route_7("admin:api:redis:prime|json", "/api/redis/prime.json")
    config.add_route_7("admin:api:nginx:status|json", "/api/nginx/status.json")

    config.add_route_7("admin:api:update_recents", "/api/update-recents")
    config.add_route_7("admin:api:update_recents|json", "/api/update-recents.json")

    # !!!: Admin API Items - QueueCertificates
    config.add_route_7(
        "admin:api:queue_certificates:process", "/api/queue-certificates/process"
    )
    config.add_route_7(
        "admin:api:queue_certificates:process|json",
        "/api/queue-certificates/process.json",
    )
    config.add_route_7(
        "admin:api:queue_certificates:update", "/api/queue-certificates/update"
    )
    config.add_route_7(
        "admin:api:queue_certificates:update|json",
        "/api/queue-certificates/update.json",
    )

    # !!!: CA Certificates (Certificate Authority)
    config.add_route_7("admin:ca_certificates", "/ca-certificates")
    config.add_route_7("admin:ca_certificates_paginated", "/ca-certificates/{@page}")
    config.add_route_7("admin:ca_certificates|json", "/ca-certificates.json")
    config.add_route_7(
        "admin:ca_certificates_paginated|json", "/ca-certificates/{@page}.json"
    )
    config.add_route_7("admin:ca_certificate:focus", "/ca-certificate/{@id}")
    config.add_route_7("admin:ca_certificate:focus|json", "/ca-certificate/{@id}.json")
    config.add_route_7(
        "admin:ca_certificate:focus:parse|json", "/ca-certificate/{@id}/parse.json"
    )
    config.add_route_7(
        "admin:ca_certificate:focus:raw",
        "/ca-certificate/{@id}/chain.{format:(cer|crt|der|pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:ca_certificate:focus:server_certificates",
        "/ca-certificate/{@id}/server-certificates",
    )
    config.add_route_7(
        "admin:ca_certificate:focus:server_certificates_paginated",
        "/ca-certificate/{@id}/server-certificates/{@page}",
    )
    config.add_route_7(
        "admin:ca_certificate:focus:server_certificates_alt",
        "/ca-certificate/{@id}/server-certificates-alt",
    )
    config.add_route_7(
        "admin:ca_certificate:focus:server_certificates_alt_paginated",
        "/ca-certificate/{@id}/server-certificates-alt/{@page}",
    )
    config.add_route_7("admin:ca_certificate:upload", "/ca-certificate/upload")
    config.add_route_7(
        "admin:ca_certificate:upload|json", "/ca-certificate/upload.json"
    )
    config.add_route_7(
        "admin:ca_certificate:upload_bundle", "/ca-certificate/upload-bundle"
    )
    config.add_route_7(
        "admin:ca_certificate:upload_bundle|json", "/ca-certificate/upload-bundle.json"
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
        "admin:domain:focus:acme_orderlesss",
        "/domain/{domain_identifier}/acme-orderlesss",
    )
    config.add_route_7(
        "admin:domain:focus:acme_orderlesss_paginated",
        "/domain/{domain_identifier}/acme-orderlesss/{@page}",
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
        "admin:domain:focus:server_certificates",
        "/domain/{domain_identifier}/server-certificates",
    )
    config.add_route_7(
        "admin:domain:focus:server_certificates_paginated",
        "/domain/{domain_identifier}/server-certificates/{@page}",
    )
    config.add_route_7(
        "admin:domain:focus:queue_certificates",
        "/domain/{domain_identifier}/queue-certificates",
    )
    config.add_route_7(
        "admin:domain:focus:queue_certificates_paginated",
        "/domain/{domain_identifier}/queue-certificates/{@page}",
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
    config.add_route_7("admin:domain:focus:mark", "/domain/{domain_identifier}/mark")
    config.add_route_7(
        "admin:domain:focus:mark|json", "/domain/{domain_identifier}/mark.json"
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

    # !!!: DomainBlocklist
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
    config.add_route_7(
        "admin:operations:ca_certificate_downloads",
        "/operations/ca-certificate-downloads",
    )
    config.add_route_7(
        "admin:operations:ca_certificate_downloads_paginated",
        "/operations/ca-certificate-downloads/{@page}",
    )
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
    # used to sign ServerCertificates
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
        "admin:private_key:focus:server_certificates",
        "/private-key/{@id}/server-certificates",
    )
    config.add_route_7(
        "admin:private_key:focus:server_certificates_paginated",
        "/private-key/{@id}/server-certificates/{@page}",
    )
    config.add_route_7(
        "admin:private_key:focus:queue_certificates",
        "/private-key/{@id}/queue-certificates",
    )
    config.add_route_7(
        "admin:private_key:focus:queue_certificates_paginated",
        "/private-key/{@id}/queue-certificates/{@page}",
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

    # !!!: Queue Certificates
    # these 2 redirect to /all or /unprocessed
    config.add_route_7("admin:queue_certificates", "/queue-certificates")
    config.add_route_7("admin:queue_certificates|json", "/queue-certificates.json")
    # all
    config.add_route_7("admin:queue_certificates:all", "/queue-certificates/all")
    config.add_route_7(
        "admin:queue_certificates:all_paginated", "/queue-certificates/all/{@page}"
    )
    config.add_route_7(
        "admin:queue_certificates:all|json", "/queue-certificates/all.json"
    )
    config.add_route_7(
        "admin:queue_certificates:all_paginated|json",
        "/queue-certificates/all/{@page}.json",
    )
    # failures
    config.add_route_7(
        "admin:queue_certificates:failures",
        "/queue-certificates/failures",
    )
    config.add_route_7(
        "admin:queue_certificates:failures_paginated",
        "/queue-certificates/failures/{@page}",
    )
    config.add_route_7(
        "admin:queue_certificates:failures|json",
        "/queue-certificates/failures.json",
    )
    config.add_route_7(
        "admin:queue_certificates:failures_paginated|json",
        "/queue-certificates/failures/{@page}.json",
    )
    # successes
    config.add_route_7(
        "admin:queue_certificates:successes",
        "/queue-certificates/successes",
    )
    config.add_route_7(
        "admin:queue_certificates:successes_paginated",
        "/queue-certificates/successes/{@page}",
    )
    config.add_route_7(
        "admin:queue_certificates:successes|json",
        "/queue-certificates/successes.json",
    )
    config.add_route_7(
        "admin:queue_certificates:successes_paginated|json",
        "/queue-certificates/successes/{@page}.json",
    )
    # unprocessed
    config.add_route_7(
        "admin:queue_certificates:unprocessed",
        "/queue-certificates/unprocessed",
    )
    config.add_route_7(
        "admin:queue_certificates:unprocessed_paginated",
        "/queue-certificates/unprocessed/{@page}",
    )
    config.add_route_7(
        "admin:queue_certificates:unprocessed|json",
        "/queue-certificates/unprocessed.json",
    )
    config.add_route_7(
        "admin:queue_certificates:unprocessed_paginated|json",
        "/queue-certificates/unprocessed/{@page}.json",
    )

    config.add_route_7(
        "admin:queue_certificate:new_structured", "/queue-certificate/new/structured"
    )
    config.add_route_7(
        "admin:queue_certificate:new_structured|json",
        "/queue-certificate/new/structured.json",
    )
    config.add_route_7(
        "admin:queue_certificate:new_freeform", "/queue-certificate/new/freeform"
    )
    config.add_route_7(
        "admin:queue_certificate:new_freeform|json",
        "/queue-certificate/new/freeform.json",
    )

    config.add_route_7("admin:queue_certificate:focus", "/queue-certificate/{@id}")
    config.add_route_7(
        "admin:queue_certificate:focus|json", "/queue-certificate/{@id}.json"
    )
    config.add_route_7(
        "admin:queue_certificate:focus:mark", "/queue-certificate/{@id}/mark"
    )
    config.add_route_7(
        "admin:queue_certificate:focus:mark|json", "/queue-certificate/{@id}/mark.json"
    )

    # !!!: Queue Domains
    # Domains can be queued in for batch processing
    config.add_route_7("admin:queue_domains", "/queue-domains")
    config.add_route_7("admin:queue_domains_paginated", "/queue-domains/{@page}")
    config.add_route_7("admin:queue_domains:all", "/queue-domains/all")
    config.add_route_7(
        "admin:queue_domains:all_paginated", "/queue-domains/all/{@page}"
    )
    config.add_route_7("admin:queue_domains|json", "/queue-domains.json")
    config.add_route_7(
        "admin:queue_domains_paginated|json", "/queue-domains/{@page}.json"
    )
    config.add_route_7("admin:queue_domains:all|json", "/queue-domains/all.json")
    config.add_route_7(
        "admin:queue_domains:all_paginated|json", "/queue-domains/all/{@page}.json"
    )

    config.add_route_7("admin:queue_domains:add", "/queue-domains/add")
    config.add_route_7("admin:queue_domains:add|json", "/queue-domains/add.json")
    config.add_route_7("admin:queue_domains:process", "/queue-domains/process")
    config.add_route_7(
        "admin:queue_domains:process|json", "/queue-domains/process.json"
    )
    config.add_route_7("admin:queue_domain:focus", "/queue-domain/{@id}")
    config.add_route_7("admin:queue_domain:focus|json", "/queue-domain/{@id}.json")
    config.add_route_7("admin:queue_domain:focus:mark", "/queue-domain/{@id}/mark")
    config.add_route_7(
        "admin:queue_domain:focus:mark|json", "/queue-domain/{@id}/mark.json"
    )

    # !!!: ServerCertificates
    config.add_route_7("admin:server_certificates", "/server-certificates")

    config.add_route_7("admin:server_certificates:all", "/server-certificates/all")
    config.add_route_7(
        "admin:server_certificates:all_paginated",
        "/server-certificates/all/{@page}",
    )
    config.add_route_7(
        "admin:server_certificates:active", "/server-certificates/active"
    )
    config.add_route_7(
        "admin:server_certificates:active_paginated",
        "/server-certificates/active/{@page}",
    )
    config.add_route_7(
        "admin:server_certificates:expiring", "/server-certificates/expiring"
    )
    config.add_route_7(
        "admin:server_certificates:expiring_paginated",
        "/server-certificates/expiring/{@page}",
    )
    config.add_route_7(
        "admin:server_certificates:inactive", "/server-certificates/inactive"
    )
    config.add_route_7(
        "admin:server_certificates:inactive_paginated",
        "/server-certificates/inactive/{@page}",
    )
    config.add_route_7("admin:server_certificates|json", "/server-certificates.json")
    config.add_route_7(
        "admin:server_certificates:all|json", "/server-certificates/all.json"
    )
    config.add_route_7(
        "admin:server_certificates:all_paginated|json",
        "/server-certificates/all/{@page}.json",
    )
    config.add_route_7(
        "admin:server_certificates:active|json", "/server-certificates/active.json"
    )
    config.add_route_7(
        "admin:server_certificates:active_paginated|json",
        "/server-certificates/active/{@page}.json",
    )
    config.add_route_7(
        "admin:server_certificates:expiring|json", "/server-certificates/expiring.json"
    )
    config.add_route_7(
        "admin:server_certificates:expiring_paginated|json",
        "/server-certificates/expiring/{@page}.json",
    )
    config.add_route_7(
        "admin:server_certificates:inactive|json", "/server-certificates/inactive.json"
    )
    config.add_route_7(
        "admin:server_certificates:inactive_paginated|json",
        "/server-certificates/inactive/{@page}.json",
    )

    # !!!: ServerCertificate - Focus
    config.add_route_7("admin:server_certificate:focus", "/server-certificate/{@id}")
    config.add_route_7(
        "admin:server_certificate:focus|json", "/server-certificate/{@id}.json"
    )
    config.add_route_7(
        "admin:server_certificate:focus:config|json",
        "/server-certificate/{@id}/config.json",
    )
    config.add_route_7(
        "admin:server_certificate:focus:config|zip",
        "/server-certificate/{@id}/config.zip",
    )
    config.add_route_7(
        "admin:server_certificate:focus:parse|json",
        "/server-certificate/{@id}/parse.json",
    )
    config.add_route_7(
        "admin:server_certificate:focus:chain:raw",
        "/server-certificate/{@id}/chain.{format:(cer|crt|der|pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:server_certificate:focus:fullchain:raw",
        "/server-certificate/{@id}/fullchain.{format:(pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:server_certificate:focus:privatekey:raw",
        "/server-certificate/{@id}/privkey.{format:(key|pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:server_certificate:focus:cert:raw",
        "/server-certificate/{@id}/cert.{format:(crt|pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:server_certificate:focus:nginx_cache_expire",
        r"/server-certificate/{@id}/nginx-cache-expire",
    )
    config.add_route_7(
        "admin:server_certificate:focus:nginx_cache_expire|json",
        r"/server-certificate/{@id}/nginx-cache-expire.json",
    )
    # via ca-cert routes
    config.add_route_7(
        "admin:server_certificate:focus:via_ca_cert:config|json",
        "/server-certificate/{@id}/via-ca-cert/{id_cacert}/config.json",
    )
    config.add_route_7(
        "admin:server_certificate:focus:via_ca_cert:config|zip",
        "/server-certificate/{@id}/via-ca-cert/{id_cacert}/config.zip",
    )
    config.add_route_7(
        "admin:server_certificate:focus:via_ca_cert:chain:raw",
        "/server-certificate/{@id}/via-ca-cert/{id_cacert}/chain.{format:(cer|crt|der|pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:server_certificate:focus:via_ca_cert:fullchain:raw",
        "/server-certificate/{@id}/via-ca-cert/{id_cacert}/fullchain.{format:(pem|pem.txt)}",
    )
    # end via ca-cert

    config.add_route_7("admin:server_certificate:upload", "/server-certificate/upload")
    config.add_route_7(
        "admin:server_certificate:upload|json", "/server-certificate/upload.json"
    )
    config.add_route_7(
        "admin:server_certificate:focus:mark", "/server-certificate/{@id}/mark"
    )
    config.add_route_7(
        "admin:server_certificate:focus:mark|json",
        "/server-certificate/{@id}/mark.json",
    )
    config.add_route_7(
        "admin:server_certificate:focus:queue_certificates",
        "/server-certificate/{@id}/queue-certificates",
    )
    config.add_route_7(
        "admin:server_certificate:focus:queue_certificates_paginated",
        "/server-certificate/{@id}/queue-certificates/{@page}",
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
        "admin:unique_fqdn_set:focus:server_certificates",
        "/unique-fqdn-set/{@id}/server-certificates",
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:server_certificates_paginated",
        "/unique-fqdn-set/{@id}/server-certificates/{@page}",
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:queue_certificates",
        "/unique-fqdn-set/{@id}/queue-certificates",
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:queue_certificates_paginated",
        "/unique-fqdn-set/{@id}/queue-certificates/{@page}",
    )

    config.scan("peter_sslers.web.views_admin")
