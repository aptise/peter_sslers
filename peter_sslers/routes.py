from .lib.config_utils import *


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def includeme(config):

    enable_views_admin = config.registry.settings['enable_views_admin']
    enable_views_public = config.registry.settings['enable_views_public']

    # pyramid_route_7 lets us default repeatable macros for our routes
    config.include("pyramid_route_7")
    config.add_route_7_kvpattern('id', '\d+')
    config.add_route_7_kvpattern('page', '\d+')

    # public
    if enable_views_public:
        # public url
        config.add_route_7('public_challenge', '/.well-known/acme-challenge/{challenge}')
        config.add_route_7('public_whoami', '/.well-known/public/whoami')

        config.scan("peter_sslers.views_public")

    # admin
    if enable_views_admin:
        route_prefix = config.registry.settings.get("admin_prefix")
        config.include(_admin_views, route_prefix=route_prefix)
        config.add_route_7('admin', route_prefix)

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _admin_views(config):

    config.add_static_view('/static', 'static', cache_max_age=3600)

    config.add_route_7('admin', '')
    config.add_route_7('admin_whoami', '/whoami')
    config.add_route_7('admin:help', '/help')
    config.add_route_7('admin:search', '/search')

    # AccountKeys are the LetsEncrypt accounts
    config.add_route_7('admin:account_keys', '/account-keys')
    config.add_route_7('admin:account_keys_paginated', '/account-keys/{@page}')
    config.add_route_7('admin:account_key:focus', '/account-key/{@id}')
    config.add_route_7('admin:account_key:focus:config_json', '/account-key/{@id}/config.json')
    config.add_route_7('admin:account_key:focus:parse.json', '/account-key/{@id}/parse.json')
    config.add_route_7('admin:account_key:focus:raw', '/account-key/{@id}/key.{format:(key|pem|pem.txt)}')
    config.add_route_7('admin:account_key:focus:certificate_requests', '/account-key/{@id}/certificate-requests')
    config.add_route_7('admin:account_key:focus:certificate_requests_paginated', '/account-key/{@id}/certificate-requests/{@page}')
    config.add_route_7('admin:account_key:focus:certificates', '/account-key/{@id}/certificates')
    config.add_route_7('admin:account_key:focus:certificates_paginated', '/account-key/{@id}/certificates/{@page}')
    config.add_route_7('admin:account_key:focus:authenticate', '/account-key/{@id}/authenticate')
    config.add_route_7('admin:account_key:focus:mark', '/account-key/{@id}/mark')
    config.add_route_7('admin:account_key:focus:mark.json', '/account-key/{@id}/mark.json')
    config.add_route_7('admin:account_key:new', '/account-key/new')

    # AccountKeys are the LetsEncrypt accounts
    config.add_route_7('admin:api', '/api')
    config.add_route_7('admin:api:domain:enable', '/api/domain/enable')
    config.add_route_7('admin:api:domain:disable', '/api/domain/disable')

    # CertificateAuthority Certificates
    config.add_route_7('admin:ca_certificates', '/ca-certificates')
    config.add_route_7('admin:ca_certificates_paginated', '/ca-certificates/{@page}')
    config.add_route_7('admin:ca_certificate:focus', '/ca-certificate/{@id}')
    config.add_route_7('admin:ca_certificate:focus:parse.json', '/ca-certificate/{@id}/parse.json')
    config.add_route_7('admin:ca_certificate:focus:raw', '/ca-certificate/{@id}/chain.{format:(cer|crt|der|pem|pem.txt)}')
    config.add_route_7('admin:ca_certificate:focus:signed_certificates', '/ca-certificate/{@id}/signed_certificates')
    config.add_route_7('admin:ca_certificate:focus:signed_certificates_paginated', '/ca-certificate/{@id}/signed_certificates/{@page}')
    config.add_route_7('admin:ca_certificate:upload', '/ca-certificate/upload')
    config.add_route_7('admin:ca_certificate:upload.json', '/ca-certificate/upload.json')
    config.add_route_7('admin:ca_certificate:upload_bundle', '/ca-certificate/upload-bundle')
    config.add_route_7('admin:ca_certificate:upload_bundle.json', '/ca-certificate/upload-bundle.json')

    # Certificates
    config.add_route_7('admin:certificates', '/certificates')
    config.add_route_7('admin:certificates_paginated', '/certificates/{@page}')
    config.add_route_7('admin:certificates:expiring', '/certificates/expiring')
    config.add_route_7('admin:certificates:expiring_paginated', '/certificates/expiring/{@page}')
    config.add_route_7('admin:certificate:focus', '/certificate/{@id}')
    config.add_route_7('admin:certificate:focus:config_json', '/certificate/{@id}/config.json')
    config.add_route_7('admin:certificate:focus:parse.json', '/certificate/{@id}/parse.json')
    config.add_route_7('admin:certificate:focus:chain:raw', '/certificate/{@id}/chain.{format:(cer|crt|der|pem|pem.txt)}')
    config.add_route_7('admin:certificate:focus:fullchain:raw', '/certificate/{@id}/fullchain.{format:(pem|pem.txt)}')
    config.add_route_7('admin:certificate:focus:privatekey:raw', '/certificate/{@id}/privkey.{format:(key|pem|pem.txt)}')
    config.add_route_7('admin:certificate:focus:cert:raw', '/certificate/{@id}/cert.{format:(crt|pem|pem.txt)}')
    config.add_route_7('admin:certificate:focus:nginx_cache_expire', '/certificate/{id:\d}/nginx-cache-expire')
    config.add_route_7('admin:certificate:focus:nginx_cache_expire.json', '/certificate/{id:\d}/nginx-cache-expire.json')
    config.add_route_7('admin:certificate:focus:renew:quick', '/certificate/{@id}/renew/quick')
    config.add_route_7('admin:certificate:focus:renew:quick.json', '/certificate/{@id}/renew/quick.json')
    config.add_route_7('admin:certificate:focus:renew:custom', '/certificate/{@id}/renew/custom')
    config.add_route_7('admin:certificate:focus:renew:custom.json', '/certificate/{@id}/renew/custom.json')
    config.add_route_7('admin:certificate:upload', '/certificate/upload')
    config.add_route_7('admin:certificate:upload.json', '/certificate/upload.json')
    config.add_route_7('admin:certificate:focus:mark', '/certificate/{@id}/mark')
    config.add_route_7('admin:certificate:focus:mark.json', '/certificate/{@id}/mark.json')

    # Certificate Requests
    config.add_route_7('admin:certificate_requests', '/certificate-requests')
    config.add_route_7('admin:certificate_requests_paginated', '/certificate-requests/{@page}')
    config.add_route_7('admin:certificate_request:focus', '/certificate-request/{@id}')
    config.add_route_7('admin:certificate_request:focus:raw', '/certificate-request/{@id}/csr.{format:(csr|pem|pem.txt)}')
    config.add_route_7('admin:certificate_request:focus:acme-flow:manage', '/certificate-request/{@id}/acme-flow/manage')
    config.add_route_7('admin:certificate_request:focus:acme-flow:manage:domain', '/certificate-request/{@id}/acme-flow/manage/domain/{domain_id:\d+}')
    config.add_route_7('admin:certificate_request:focus:deactivate', '/certificate-request/{@id}/deactivate')
    # two types of CR handling
    config.add_route_7('admin:certificate_request:new:acme-flow', '/certificate-request/new-acme-flow')
    config.add_route_7('admin:certificate_request:new:acme-automated', '/certificate-request/new-acme-automated')

    # Domains
    config.add_route_7('admin:domains', '/domains')
    config.add_route_7('admin:domains_paginated', '/domains/{@page}')
    config.add_route_7('admin:domains:expiring', '/domains/expiring')
    config.add_route_7('admin:domains:expiring_paginated', '/domains/expiring/{@page}')
    config.add_route_7('admin:domain:focus', '/domain/{domain_identifier}')
    config.add_route_7('admin:domain:focus_name', '/domain/{domain_identifier}')
    config.add_route_7('admin:domain:focus:config_json', '/domain/{domain_identifier}/config.json')
    config.add_route_7('admin:domain:focus:nginx_cache_expire', '/domain/{domain_identifier}/nginx-cache-expire')
    config.add_route_7('admin:domain:focus:nginx_cache_expire.json', '/domain/{domain_identifier}/nginx-cache-expire.json')
    config.add_route_7('admin:domain:focus:certificates', '/domain/{domain_identifier}/certificates')
    config.add_route_7('admin:domain:focus:certificates_paginated', '/domain/{domain_identifier}/certificates/{@page}')
    config.add_route_7('admin:domain:focus:certificate_requests', '/domain/{domain_identifier}/certificate-requests')
    config.add_route_7('admin:domain:focus:certificate_requests_paginated', '/domain/{domain_identifier}/certificate-requests/{@page}')
    config.add_route_7('admin:domain:focus:calendar', '/domain/{domain_identifier}/calendar')
    config.add_route_7('admin:domain:focus:unique_fqdn_sets', '/domain/{domain_identifier}/unique-fqdn-sets')
    config.add_route_7('admin:domain:focus:unique_fqdn_sets_paginated', '/domain/{domain_identifier}/unique-fqdn-sets/{@page}')
    config.add_route_7('admin:domain:focus:mark', '/domain/{domain_identifier}/mark')
    config.add_route_7('admin:domain:focus:mark.json', '/domain/{domain_identifier}/mark.json')

    # Operations & sync events
    config.add_route_7('admin:operations', '/operations')
    # -
    config.add_route_7('admin:operations:ca_certificate_probes', '/operations/ca-certificate-probes')
    config.add_route_7('admin:operations:ca_certificate_probes_paginated', '/operations/ca-certificate-probes/{@page}')
    config.add_route_7('admin:operations:ca_certificate_probes:probe', '/operations/ca-certificate-probes/probe')
    config.add_route_7('admin:operations:ca_certificate_probes:probe.json', '/operations/ca-certificate-probes/probe.json')
    # -
    config.add_route_7('admin:operations:deactivate_expired', '/operations/deactivate-expired')
    config.add_route_7('admin:operations:deactivate_expired.json', '/operations/deactivate-expired.json')
    # -
    config.add_route_7('admin:operations:log', '/operations/log')
    config.add_route_7('admin:operations:log_paginated', '/operations/log/{@page}')
    config.add_route_7('admin:operations:log:focus', '/operations/log/item/{@id}')
    # -
    config.add_route_7('admin:operations:nginx', '/operations/nginx')
    config.add_route_7('admin:operations:nginx_paginated', '/operations/nginx/{@page}')
    config.add_route_7('admin:operations:nginx:cache_flush', '/operations/nginx/cache-flush')
    config.add_route_7('admin:operations:nginx:cache_flush.json', '/operations/nginx/cache-flush.json')
    # -
    config.add_route_7('admin:operations:redis', '/operations/redis')
    config.add_route_7('admin:operations:redis_paginated', '/operations/redis/{@page}')
    config.add_route_7('admin:operations:redis:prime', '/operations/redis/prime')
    config.add_route_7('admin:operations:redis:prime.json', '/operations/redis/prime.json')
    # -
    config.add_route_7('admin:operations:update_recents', '/operations/update-recents')
    config.add_route_7('admin:operations:update_recents.json', '/operations/update-recents.json')

    # Private Keys sign Certificates
    config.add_route_7('admin:private_keys', '/private-keys')
    config.add_route_7('admin:private_keys_paginated', '/private-keys/{@page}')
    config.add_route_7('admin:private_key:focus', '/private-key/{@id}')
    config.add_route_7('admin:private_key:focus:parse.json', '/private-key/{@id}/parse.json')
    config.add_route_7('admin:private_key:focus:raw', '/private-key/{@id}/key.{format:(key|pem|pem.txt)}')
    config.add_route_7('admin:private_key:focus:certificates', '/private-key/{@id}/certificates')
    config.add_route_7('admin:private_key:focus:certificates_paginated', '/private-key/{@id}/certificates/{@page}')
    config.add_route_7('admin:private_key:focus:certificate_requests', '/private-key/{@id}/certificate-requests')
    config.add_route_7('admin:private_key:focus:certificate_requests_paginated', '/private-key/{@id}/certificate-requests/{@page}')
    config.add_route_7('admin:private_key:focus:mark', '/private-key/{@id}/mark')
    config.add_route_7('admin:private_key:focus:mark.json', '/private-key/{@id}/mark.json')
    config.add_route_7('admin:private_key:new', '/private-key/new')

    # Domains can be queued in for batch processing
    config.add_route_7('admin:queue_domains', '/queue-domains')
    config.add_route_7('admin:queue_domains_paginated', '/queue-domains/{@page}')
    config.add_route_7('admin:queue_domains:all', '/queue-domains/all')
    config.add_route_7('admin:queue_domains:all_paginated', '/queue-domains/all/{@page}')
    config.add_route_7('admin:queue_domains:add', '/queue-domains/add')
    config.add_route_7('admin:queue_domains:add.json', '/queue-domains/add.json')
    config.add_route_7('admin:queue_domains:process', '/queue-domains/process')
    config.add_route_7('admin:queue_domains:process.json', '/queue-domains/process.json')
    config.add_route_7('admin:queue_domain:focus', '/queue-domain/{@id}')

    # Unique FQDN Sets are tied to Certs and Ratelimits
    config.add_route_7('admin:queue_renewals', '/queue-renewals')
    config.add_route_7('admin:queue_renewals_paginated', '/queue-renewals/{@page}')
    config.add_route_7('admin:queue_renewals:all', '/queue-renewals/all')
    config.add_route_7('admin:queue_renewals:all_paginated', '/queue-renewals/all/{@page}')
    config.add_route_7('admin:queue_renewals:process', '/queue-renewals/process')
    config.add_route_7('admin:queue_renewals:process.json', '/queue-renewals/process.json')
    config.add_route_7('admin:queue_renewal:focus', '/queue-renewal/{@id}')

    # Unique FQDN Sets are tied to Certs and Ratelimits
    config.add_route_7('admin:unique_fqdn_sets', '/unique-fqdn-sets')
    config.add_route_7('admin:unique_fqdn_sets_paginated', '/unique-fqdn-sets/{@page}')
    config.add_route_7('admin:unique_fqdn_set:focus', '/unique-fqdn-set/{@id}')
    config.add_route_7('admin:unique_fqdn_set:focus:calendar', '/unique-fqdn-set/{@id}/calendar')
    config.add_route_7('admin:unique_fqdn_set:focus:certificates', '/unique-fqdn-set/{@id}/certificates')
    config.add_route_7('admin:unique_fqdn_set:focus:certificates_paginated', '/unique-fqdn-set/{@id}/certificates/{@page}')
    config.add_route_7('admin:unique_fqdn_set:focus:certificate_requests', '/unique-fqdn-set/{@id}/certificate-requests')
    config.add_route_7('admin:unique_fqdn_set:focus:certificate_requests_paginated', '/unique-fqdn-set/{@id}/certificate-requests/{@page}')

    config.scan("peter_sslers.views_admin")
