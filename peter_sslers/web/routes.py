from .lib.config_utils import set_bool_setting
from .lib.config_utils import set_int_setting


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def includeme(config):

    enable_views_admin = config.registry.settings["enable_views_admin"]
    enable_views_public = config.registry.settings["enable_views_public"]

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
        route_prefix = config.registry.settings.get("admin_prefix")
        config.include(_admin_views, route_prefix=route_prefix)
        config.add_route_7("admin", route_prefix)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _admin_views(config):

    config.add_static_view("/static", "static", cache_max_age=3600)

    config.add_route_7("admin", "")
    config.add_route_7("admin_whoami", "/whoami")
    config.add_route_7("admin:help", "/help")
    config.add_route_7("admin:search", "/search")
    config.add_route_7("admin:settings", "/settings")

    # !!!: AcmeAuthorizations
    config.add_route_7("admin:acme_authorizations", "/acme-authorizations")
    config.add_route_7(
        "admin:acme_authorizations_paginated", "/acme-authorizations/{@page}"
    )
    config.add_route_7("admin:acme_authorization:focus", "/acme-authorization/{@id}")
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
        "admin:acme_authorization:focus:acme_server_sync",
        "/acme-authorization/{@id}/acme-server-sync",
    )
    config.add_route_7(
        "admin:acme_authorization:focus:acme_server_deactivate",
        "/acme-authorization/{@id}/acme-server-deactivate",
    )

    # !!!: AcmeAccountKeys
    # AccountKeys are the LetsEncrypt accounts
    config.add_route_7("admin:acme_account_keys", "/acme-account-keys")
    config.add_route_7("admin:acme_account_keys|json", "/acme-account-keys.json")
    config.add_route_7(
        "admin:acme_account_keys_paginated", "/acme-account-keys/{@page}"
    )
    config.add_route_7(
        "admin:acme_account_keys_paginated|json", "/acme-account-keys/{@page}.json"
    )

    # !!!: AcmeAccountKey - Focus
    config.add_route_7("admin:acme_account_key:focus", "/acme-account-key/{@id}")
    config.add_route_7(
        "admin:acme_account_key:focus|json", "/acme-account-key/{@id}.json"
    )
    config.add_route_7(
        "admin:acme_account_key:focus:config|json",
        "/acme-account-key/{@id}/config.json",
    )
    config.add_route_7(
        "admin:acme_account_key:focus:parse|json", "/acme-account-key/{@id}/parse.json"
    )
    config.add_route_7(
        "admin:acme_account_key:focus:raw",
        "/acme-account-key/{@id}/key.{format:(key|pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:acme_account_key:focus:acme_authorizations",
        "/acme-account-key/{@id}/acme-authorizations",
    )
    config.add_route_7(
        "admin:acme_account_key:focus:acme_authorizations_paginated",
        "/acme-account-key/{@id}/acme-authorizations/{@page}",
    )
    config.add_route_7(
        "admin:acme_account_key:focus:acme_orders",
        "/acme-account-key/{@id}/acme-orders",
    )
    config.add_route_7(
        "admin:acme_account_key:focus:acme_orders_paginated",
        "/acme-account-key/{@id}/acme-orders/{@page}",
    )
    config.add_route_7(
        "admin:acme_account_key:focus:certificate_requests",
        "/acme-account-key/{@id}/certificate-requests",
    )
    config.add_route_7(
        "admin:acme_account_key:focus:certificate_requests_paginated",
        "/acme-account-key/{@id}/certificate-requests/{@page}",
    )
    config.add_route_7(
        "admin:acme_account_key:focus:certificates",
        "/acme-account-key/{@id}/certificates",
    )
    config.add_route_7(
        "admin:acme_account_key:focus:certificates_paginated",
        "/acme-account-key/{@id}/certificates/{@page}",
    )
    config.add_route_7(
        "admin:acme_account_key:focus:authenticate",
        "/acme-account-key/{@id}/authenticate",
    )
    config.add_route_7(
        "admin:acme_account_key:focus:authenticate|json",
        "/acme-account-key/{@id}/authenticate.json",
    )
    config.add_route_7(
        "admin:acme_account_key:focus:mark", "/acme-account-key/{@id}/mark"
    )
    config.add_route_7(
        "admin:acme_account_key:focus:mark|json", "/acme-account-key/{@id}/mark.json"
    )
    config.add_route_7("admin:acme_account_key:upload", "/acme-account-key/upload")
    config.add_route_7(
        "admin:acme_account_key:upload|json", "/acme-account-key/upload.json"
    )

    # !!!: AcmeChallenge
    config.add_route_7("admin:acme_challenges", "/acme-challenges")
    config.add_route_7("admin:acme_challenges_paginated", "/acme-challenges/{@page}")
    config.add_route_7("admin:acme_challenge:focus", "/acme-challenge/{@id}")
    config.add_route_7(
        "admin:acme_challenge:focus:acme_server_sync",
        "/acme-challenge/{@id}/acme-server-sync",
    )

    # !!!: AcmeChallenge Poll
    config.add_route_7("admin:acme_challenge_polls", "/acme-challenge-polls")
    config.add_route_7(
        "admin:acme_challenge_polls_paginated", "/acme-challenge-polls/{@page}"
    )
    config.add_route_7("admin:acme_challenge_poll:focus", "/acme-challenge-poll/{@id}")

    # !!!: AcmeChallengeUnknown Poll
    config.add_route_7(
        "admin:acme_challenge_unknown_polls", "/acme-challenge-unknown-polls"
    )
    config.add_route_7(
        "admin:acme_challenge_unknown_polls_paginated",
        "/acme-challenge-unknown-polls/{@page}",
    )

    # !!!: AcmeEvents Logging
    config.add_route_7("admin:acme_event_log", "/acme-event-logs")
    config.add_route_7("admin:acme_event_log_paginated", "/acme-event-logs/{@page}")
    config.add_route_7("admin:acme_event_log:focus", "/acme-event-log/{@id}")

    # !!!: AcmeOrderless / AcmeFlow - our manual system
    config.add_route_7("admin:acme_orderlesss", "/acme-orderlesss")
    config.add_route_7("admin:acme_orderlesss_paginated", "/acme-orderlesss/{@page}")
    config.add_route_7("admin:acme_orderless:new", "/acme-orderless/new")

    config.add_route_7(
        "admin:acme_orderless:focus", "/acme-orderless/{@id}",
    )
    config.add_route_7("admin:acme_orderless:focus|json", "/acme-orderless/{@id}.json")
    config.add_route_7(
        "admin:acme_orderless:focus:add", "/acme-orderless/{@id}/add",
    )
    config.add_route_7(
        "admin:acme_orderless:focus:add|json", "/acme-orderless/{@id}/add.json",
    )
    config.add_route_7(
        "admin:acme_orderless:focus:update", "/acme-orderless/{@id}/update",
    )
    config.add_route_7(
        "admin:acme_orderless:focus:update|json", "/acme-orderless/{@id}/update.json"
    )
    config.add_route_7(
        "admin:acme_orderless:focus:deactivate", "/acme-orderless/{@id}/deactivate",
    )
    config.add_route_7(
        "admin:acme_orderless:focus:deactivate|json",
        "/acme-orderless/{@id}/deactivate.json",
    )

    config.add_route_7(
        "admin:acme_orderless:focus:acme_orderless_challenge",
        "/acme-orderless/{@id}/acme-orderless-challenge/{id_challenge:\d+}",
    )
    config.add_route_7(
        "admin:acme_orderless:focus:acme_orderless_challenge|json",
        "/acme-orderless/{@id}/acme-orderless-challenge/{id_challenge:\d+}.json",
    )

    # !!!: AcmeOrder
    config.add_route_7("admin:acme_orders", "/acme-orders")
    config.add_route_7("admin:acme_orders_paginated", "/acme-orders/{@page}")
    config.add_route_7("admin:acme_order:focus", "/acme-order/{@id}")
    config.add_route_7("admin:acme_order:focus:process", "/acme-order/{@id}/process")
    config.add_route_7(
        "admin:acme_order:focus:acme_server_sync", "/acme-order/{@id}/acme-server-sync"
    )
    config.add_route_7(
        "admin:acme_order:focus:acme_server_deactivate_authorizations",
        "/acme-order/{@id}/acme-server-deactivate-authorizations",
    )

    config.add_route_7("admin:acme_order:focus:retry", "/acme-order/{@id}/retry")
    config.add_route_7("admin:acme_order:focus:mark", "/acme-order/{@id}/mark")
    config.add_route_7("admin:acme_order:new:automated", "/acme-order/new/automated")
    config.add_route_7(
        "admin:acme_order:new:from-certificate-request",
        "/acme-order/new/from-certificate-request",
    )

    # !!!: AcmeProvider
    # this is just letsencrypt endpoints
    config.add_route_7("admin:acme_providers", "/acme-providers")
    config.add_route_7("admin:acme_providers|json", "/acme-providers.json")

    # !!!: Admin API Items
    config.add_route_7("admin:api", "/api")
    config.add_route_7("admin:api:domain:enable", "/api/domain/enable")
    config.add_route_7("admin:api:domain:disable", "/api/domain/disable")
    config.add_route_7(
        "admin:api:domain:certificate-if-needed", "/api/domain/certificate-if-needed"
    )
    # -
    config.add_route_7("admin:api:deactivate_expired", "/api/deactivate-expired")
    config.add_route_7(
        "admin:api:deactivate_expired|json", "/api/deactivate-expired.json"
    )
    # -
    config.add_route_7(
        "admin:api:ca_certificate_probes:probe", "/api/ca-certificate-probes/probe"
    )
    config.add_route_7(
        "admin:api:ca_certificate_probes:probe|json",
        "/api/ca-certificate-probes/probe.json",
    )
    config.add_route_7("admin:api:nginx:cache_flush", "/api/nginx/cache-flush")
    config.add_route_7(
        "admin:api:nginx:cache_flush|json", "/api/nginx/cache-flush.json"
    )
    config.add_route_7("admin:api:redis:prime", "/api/redis/prime")
    config.add_route_7("admin:api:redis:prime|json", "/api/redis/prime.json")
    config.add_route_7("admin:api:nginx:status|json", "/api/nginx/status.json")
    # -
    config.add_route_7("admin:api:update_recents", "/api/update-recents")
    config.add_route_7("admin:api:update_recents|json", "/api/update-recents.json")

    config.add_route_7("admin:api:queue_renewals:update", "/api/queue-renewals/update")
    config.add_route_7(
        "admin:api:queue_renewals:update|json", "/api/queue-renewals/update.json"
    )
    config.add_route_7(
        "admin:api:queue_renewals:process", "/api/queue-renewals/process"
    )
    config.add_route_7(
        "admin:api:queue_renewals:process|json", "/api/queue-renewals/process.json"
    )

    # !!!: CertificateAuthority Certificates
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
        "admin:ca_certificate:focus:certificates_signed",
        "/ca-certificate/{@id}/certificates-signed",
    )
    config.add_route_7(
        "admin:ca_certificate:focus:certificates_signed_paginated",
        "/ca-certificate/{@id}/certificates-signed/{@page}",
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

    # !!!: Certificates
    config.add_route_7("admin:certificates", "/certificates")
    config.add_route_7("admin:certificates_paginated", "/certificates/{@page}")
    config.add_route_7("admin:certificates:active", "/certificates/active")
    config.add_route_7(
        "admin:certificates:active_paginated", "/certificates/active/{@page}"
    )
    config.add_route_7("admin:certificates:expiring", "/certificates/expiring")
    config.add_route_7(
        "admin:certificates:expiring_paginated", "/certificates/expiring/{@page}"
    )
    config.add_route_7("admin:certificates:inactive", "/certificates/inactive")
    config.add_route_7(
        "admin:certificates:inactive_paginated", "/certificates/inactive/{@page}"
    )
    config.add_route_7("admin:certificates|json", "/certificates.json")
    config.add_route_7(
        "admin:certificates_paginated|json", "/certificates/{@page}.json"
    )
    config.add_route_7("admin:certificates:active|json", "/certificates/active.json")
    config.add_route_7(
        "admin:certificates:active_paginated|json", "/certificates/active/{@page}.json"
    )
    config.add_route_7(
        "admin:certificates:expiring|json", "/certificates/expiring.json"
    )
    config.add_route_7(
        "admin:certificates:expiring_paginated|json",
        "/certificates/expiring/{@page}.json",
    )
    config.add_route_7(
        "admin:certificates:inactive|json", "/certificates/inactive.json"
    )
    config.add_route_7(
        "admin:certificates:inactive_paginated|json",
        "/certificates/inactive/{@page}.json",
    )

    # !!!: Certificate - Focus
    config.add_route_7("admin:certificate:focus", "/certificate/{@id}")
    config.add_route_7("admin:certificate:focus|json", "/certificate/{@id}.json")
    config.add_route_7(
        "admin:certificate:focus:config|json", "/certificate/{@id}/config.json"
    )
    config.add_route_7(
        "admin:certificate:focus:parse|json", "/certificate/{@id}/parse.json"
    )
    config.add_route_7(
        "admin:certificate:focus:chain:raw",
        "/certificate/{@id}/chain.{format:(cer|crt|der|pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:certificate:focus:fullchain:raw",
        "/certificate/{@id}/fullchain.{format:(pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:certificate:focus:privatekey:raw",
        "/certificate/{@id}/privkey.{format:(key|pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:certificate:focus:cert:raw",
        "/certificate/{@id}/cert.{format:(crt|pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:certificate:focus:nginx_cache_expire",
        r"/certificate/{@id}/nginx-cache-expire",
    )
    config.add_route_7(
        "admin:certificate:focus:nginx_cache_expire|json",
        r"/certificate/{@id}/nginx-cache-expire.json",
    )
    config.add_route_7(
        "admin:certificate:focus:renew:queue", "/certificate/{@id}/renew/queue"
    )
    config.add_route_7(
        "admin:certificate:focus:renew:queue|json",
        "/certificate/{@id}/renew/queue.json",
    )
    config.add_route_7(
        "admin:certificate:focus:renew:quick", "/certificate/{@id}/renew/quick"
    )
    config.add_route_7(
        "admin:certificate:focus:renew:quick|json",
        "/certificate/{@id}/renew/quick.json",
    )
    config.add_route_7(
        "admin:certificate:focus:renew:custom", "/certificate/{@id}/renew/custom"
    )
    config.add_route_7(
        "admin:certificate:focus:renew:custom|json",
        "/certificate/{@id}/renew/custom.json",
    )
    config.add_route_7("admin:certificate:upload", "/certificate/upload")
    config.add_route_7("admin:certificate:upload|json", "/certificate/upload.json")
    config.add_route_7("admin:certificate:focus:mark", "/certificate/{@id}/mark")
    config.add_route_7(
        "admin:certificate:focus:mark|json", "/certificate/{@id}/mark.json"
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
        "admin:certificate_request:focus:raw",
        "/certificate-request/{@id}/csr.{format:(csr|pem|pem.txt)}",
    )

    # !!!: Domains
    config.add_route_7("admin:domains", "/domains")
    config.add_route_7("admin:domains|json", "/domains.json")
    config.add_route_7("admin:domains:search", "/domains/search")
    config.add_route_7("admin:domains:search|json", "/domains/search.json")
    config.add_route_7("admin:domains_paginated", "/domains/{@page}")
    config.add_route_7("admin:domains_paginated|json", "/domains/{@page}.json")
    config.add_route_7("admin:domains:expiring", "/domains/expiring")
    config.add_route_7("admin:domains:expiring|json", "/domains/expiring.json")
    config.add_route_7("admin:domains:expiring_paginated", "/domains/expiring/{@page}")
    config.add_route_7(
        "admin:domains:expiring_paginated|json", "/domains/expiring/{@page}.json"
    )

    # !!!: Domain Focus
    # json first otherwise we think it's the extension
    config.add_route_7("admin:domain:focus|json", "/domain/{domain_identifier}.json")
    config.add_route_7("admin:domain:focus", "/domain/{domain_identifier}")
    # config.add_route_7('admin:domain:focus_name', '/domain/{domain_identifier}')
    # config.add_route_7('admin:domain:focus_name|json', '/domain/{domain_identifier}.json')
    config.add_route_7(
        "admin:domain:focus:config|json", "/domain/{domain_identifier}/config.json"
    )
    config.add_route_7(
        "admin:domain:focus:calendar|json", "/domain/{domain_identifier}/calendar.json"
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
        "admin:domain:focus:acme_orderless_challenges",
        "/domain/{domain_identifier}/acme-orderless-challenges",
    )
    config.add_route_7(
        "admin:domain:focus:acme_orderless_challenges_paginated",
        "/domain/{domain_identifier}/acme-orderless-challenges/{@page}",
    )

    config.add_route_7(
        "admin:domain:focus:certificates", "/domain/{domain_identifier}/certificates"
    )
    config.add_route_7(
        "admin:domain:focus:certificates_paginated",
        "/domain/{domain_identifier}/certificates/{@page}",
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

    # !!!: Operations & Sync Events
    config.add_route_7("admin:operations", "/operations")
    # -
    config.add_route_7(
        "admin:operations:ca_certificate_probes", "/operations/ca-certificate-probes"
    )
    config.add_route_7(
        "admin:operations:ca_certificate_probes_paginated",
        "/operations/ca-certificate-probes/{@page}",
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
    # used to sign Certificates
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
        "admin:private_key:focus:certificates", "/private-key/{@id}/certificates"
    )
    config.add_route_7(
        "admin:private_key:focus:certificates_paginated",
        "/private-key/{@id}/certificates/{@page}",
    )
    config.add_route_7(
        "admin:private_key:focus:certificate_requests",
        "/private-key/{@id}/certificate-requests",
    )
    config.add_route_7(
        "admin:private_key:focus:certificate_requests_paginated",
        "/private-key/{@id}/certificate-requests/{@page}",
    )
    config.add_route_7("admin:private_key:focus:mark", "/private-key/{@id}/mark")
    config.add_route_7(
        "admin:private_key:focus:mark|json", "/private-key/{@id}/mark.json"
    )
    config.add_route_7("admin:private_key:upload", "/private-key/upload")
    config.add_route_7("admin:private_key:upload|json", "/private-key/upload.json")

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

    # !!!: Queue Renewals
    config.add_route_7("admin:queue_renewals", "/queue-renewals")
    config.add_route_7("admin:queue_renewals|json", "/queue-renewals.json")
    config.add_route_7("admin:queue_renewals_paginated", "/queue-renewals/{@page}")
    config.add_route_7(
        "admin:queue_renewals_paginated|json", "/queue-renewals/{@page}.json"
    )
    config.add_route_7("admin:queue_renewals:all", "/queue-renewals/all")
    config.add_route_7(
        "admin:queue_renewals:all_paginated", "/queue-renewals/all/{@page}"
    )
    config.add_route_7("admin:queue_renewals:all|json", "/queue-renewals/all.json")
    config.add_route_7(
        "admin:queue_renewals:all_paginated|json", "/queue-renewals/all/{@page}.json"
    )
    config.add_route_7(
        "admin:queue_renewals:active_failures", "/queue-renewals/active-failures"
    )
    config.add_route_7(
        "admin:queue_renewals:active_failures_paginated",
        "/queue-renewals/active-failures/{@page}",
    )
    config.add_route_7(
        "admin:queue_renewals:active_failures|json",
        "/queue-renewals/active-failures.json",
    )
    config.add_route_7(
        "admin:queue_renewals:active_failures_paginated|json",
        "/queue-renewals/active-failures/{@page}.json",
    )
    config.add_route_7("admin:queue_renewal:focus", "/queue-renewal/{@id}")
    config.add_route_7("admin:queue_renewal:focus|json", "/queue-renewal/{@id}.json")
    config.add_route_7("admin:queue_renewal:focus:mark", "/queue-renewal/{@id}/mark")
    config.add_route_7(
        "admin:queue_renewal:focus:mark|json", "/queue-renewal/{@id}/mark.json"
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
        "admin:unique_fqdn_set:focus:acme_orders", "/unique-fqdn-set/{@id}/acme-orders",
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:acme_orders_paginated",
        "/unique-fqdn-set/{@id}/acme-orders/{@page}",
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:certificates",
        "/unique-fqdn-set/{@id}/certificates",
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:certificates_paginated",
        "/unique-fqdn-set/{@id}/certificates/{@page}",
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
        "admin:unique_fqdn_set:focus:renew:queue", "/unique-fqdn-set/{@id}/renew/queue"
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:renew:queue|json",
        "/unique-fqdn-set/{@id}/renew/queue.json",
    )

    config.scan("peter_sslers.web.views_admin")
