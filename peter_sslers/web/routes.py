from .lib.config_utils import *


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def includeme(config):

    enable_views_admin = config.registry.settings["enable_views_admin"]
    enable_views_public = config.registry.settings["enable_views_public"]

    # pyramid_route_7 lets us default repeatable macros for our routes
    config.include("pyramid_route_7")
    config.add_route_7_kvpattern("id", "\d+")
    config.add_route_7_kvpattern("page", "\d+")

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

    # this is just letsencrypt endpoints
    config.add_route_7("admin:acme_providers", "/acme-providers")
    config.add_route_7("admin:acme_providers|json", "/acme-providers.json")

    # AccountKeys are the LetsEncrypt accounts
    config.add_route_7("admin:account_keys", "/account-keys")
    config.add_route_7("admin:account_keys|json", "/account-keys.json")
    config.add_route_7("admin:account_keys_paginated", "/account-keys/{@page}")
    config.add_route_7(
        "admin:account_keys_paginated|json", "/account-keys/{@page}.json"
    )
    config.add_route_7("admin:account_key:focus", "/account-key/{@id}")
    config.add_route_7("admin:account_key:focus|json", "/account-key/{@id}.json")
    config.add_route_7(
        "admin:account_key:focus:config|json", "/account-key/{@id}/config.json"
    )
    config.add_route_7(
        "admin:account_key:focus:parse|json", "/account-key/{@id}/parse.json"
    )
    config.add_route_7(
        "admin:account_key:focus:raw",
        "/account-key/{@id}/key.{format:(key|pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:account_key:focus:certificate_requests",
        "/account-key/{@id}/certificate-requests",
    )
    config.add_route_7(
        "admin:account_key:focus:certificate_requests_paginated",
        "/account-key/{@id}/certificate-requests/{@page}",
    )
    config.add_route_7(
        "admin:account_key:focus:certificates", "/account-key/{@id}/certificates"
    )
    config.add_route_7(
        "admin:account_key:focus:certificates_paginated",
        "/account-key/{@id}/certificates/{@page}",
    )
    config.add_route_7(
        "admin:account_key:focus:authenticate", "/account-key/{@id}/authenticate"
    )
    config.add_route_7(
        "admin:account_key:focus:authenticate|json",
        "/account-key/{@id}/authenticate.json",
    )
    config.add_route_7("admin:account_key:focus:mark", "/account-key/{@id}/mark")
    config.add_route_7(
        "admin:account_key:focus:mark|json", "/account-key/{@id}/mark.json"
    )
    config.add_route_7("admin:account_key:upload", "/account-key/upload")
    config.add_route_7("admin:account_key:upload|json", "/account-key/upload.json")

    # Admin API Items
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

    # AcmeEvents Logging
    config.add_route_7("admin:acme_event_log", "/acme-event-logs")
    config.add_route_7("admin:acme_event_log_paginated", "/acme-event-logs/{@page}")
    config.add_route_7("admin:acme_event_log:focus", "/acme-event-log/{@id}")
    config.add_route_7("admin:acme_challenge_log", "/acme-challenge-logs")
    config.add_route_7(
        "admin:acme_challenge_log_paginated", "/acme-challenge-logs/{@page}"
    )
    config.add_route_7("admin:acme_challenge_log:focus", "/acme-challenge-log/{@id}")

    config.add_route_7(
        "admin:acme_challenge_log:filtered", "/acme-challenge-logs/filtered"
    )
    config.add_route_7(
        "admin:acme_challenge_log:filtered|json", "/acme-challenge-logs/filtered.json"
    )

    # CertificateAuthority Certificates
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

    # Certificates
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
        "/certificate/{id:\d}/nginx-cache-expire",
    )
    config.add_route_7(
        "admin:certificate:focus:nginx_cache_expire|json",
        "/certificate/{id:\d}/nginx-cache-expire.json",
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

    # Certificate Requests
    config.add_route_7("admin:certificate_requests", "/certificate-requests")
    config.add_route_7(
        "admin:certificate_requests_paginated", "/certificate-requests/{@page}"
    )
    config.add_route_7("admin:certificate_requests|json", "/certificate-requests.json")
    config.add_route_7(
        "admin:certificate_requests_paginated|json",
        "/certificate-requests/{@page}.json",
    )
    config.add_route_7("admin:certificate_request:focus", "/certificate-request/{@id}")
    config.add_route_7(
        "admin:certificate_request:focus|json", "/certificate-request/{@id}.json"
    )
    config.add_route_7(
        "admin:certificate_request:focus:raw",
        "/certificate-request/{@id}/csr.{format:(csr|pem|pem.txt)}",
    )
    config.add_route_7(
        "admin:certificate_request:focus:acme-flow:deactivate",
        "/certificate-request/{@id}/acme-flow/deactivate",
    )
    config.add_route_7(
        "admin:certificate_request:focus:acme-flow:deactivate|json",
        "/certificate-request/{@id}/acme-flow/deactivate.json",
    )
    config.add_route_7(
        "admin:certificate_request:focus:acme-flow:manage",
        "/certificate-request/{@id}/acme-flow/manage",
    )
    config.add_route_7(
        "admin:certificate_request:focus:acme-flow:manage:domain",
        "/certificate-request/{@id}/acme-flow/manage/domain/{domain_identifier}",
    )
    # two types of CR handling
    config.add_route_7(
        "admin:certificate_request:new:acme-flow", "/certificate-request/new-acme-flow"
    )
    config.add_route_7(
        "admin:certificate_request:new:acme-automated",
        "/certificate-request/new-acme-automated",
    )

    # Domains
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

    # Operations & sync events
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

    # Private Keys sign Certificates
    config.add_route_7("admin:private_keys", "/private-keys")
    config.add_route_7("admin:private_keys_paginated", "/private-keys/{@page}")
    config.add_route_7("admin:private_keys|json", "/private-keys.json")
    config.add_route_7(
        "admin:private_keys_paginated|json", "/private-keys/{@page}.json"
    )
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

    # Unique FQDN Sets are tied to Certs and Ratelimits
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

    # Unique FQDN Sets are tied to Certs and Ratelimits
    config.add_route_7("admin:unique_fqdn_sets", "/unique-fqdn-sets")
    config.add_route_7("admin:unique_fqdn_sets_paginated", "/unique-fqdn-sets/{@page}")
    config.add_route_7("admin:unique_fqdn_sets|json", "/unique-fqdn-sets.json")
    config.add_route_7(
        "admin:unique_fqdn_sets_paginated|json", "/unique-fqdn-sets/{@page}.json"
    )
    config.add_route_7("admin:unique_fqdn_set:focus", "/unique-fqdn-set/{@id}")
    config.add_route_7(
        "admin:unique_fqdn_set:focus|json", "/unique-fqdn-set/{@id}.json"
    )
    config.add_route_7(
        "admin:unique_fqdn_set:focus:calendar|json",
        "/unique-fqdn-set/{@id}/calendar.json",
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
