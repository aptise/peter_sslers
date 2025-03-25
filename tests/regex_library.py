# stdlib
import re


# ==============================================================================


# note: AcmeAccount

RE_AcmeAccount_new = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-account/(\d+)\?result=success&operation=new&is_created=1$"""
)


RE_AcmeAccount_deactivate = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-account/(\d+)\?result=success&operation=acme-server--deactivate$"""
)


RE_AcmeAccount_deactivate_pending_post_required = re.compile(
    r"""http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-account/(\d+)/acme-authorizations\?status=active&result=error&error=post\+required&operation=acme-server--deactivate-pending-authorizations"""
)
RE_AcmeAccount_deactivate_pending_success = re.compile(
    r"""http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-account/(\d+)/acme-authorizations\?status=active&result=success&operation=acme-server--deactivate-pending-authorizations"""
)


# NOTE: AcmeAuthorization
# !!!: the space after `btn-info ` and no `disabled` class
RE_AcmeAuthorization_sync_btn = re.compile(
    r"""<button class="btn btn-xs btn-primary " id="btn-acme_authorization-sync">"""
)
RE_AcmeAuthorization_deactivate_btn = re.compile(
    r"""<button class="btn btn-xs btn-danger " id="btn-acme_authorization-deactivate">"""
)

RE_AcmeAuthorization_deactivated = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-authorization/\d+\?result=success&operation=acme\+server\+deactivate"""
)
RE_AcmeAuthorization_deactivate_fail = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-authorization/\d+\?result=error&error=ACME\+Server\+Sync\+is\+not\+allowed\+for\+this\+AcmeAuthorization&operation=acme\+server\+deactivate"""
)

RE_AcmeAuthorization_triggered = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-authorization/\d+\?result=success&operation=acme\+server\+trigger"""
)

RE_AcmeAuthorization_synced = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-authorization/\d+\?result=success&operation=acme\+server\+sync"""
)


# note: AcmeChallenge
# !!!: the space after `btn-info ` and no `disabled` class
RE_AcmeChallenge_sync_btn = re.compile(
    r"""<button class="btn btn-xs btn-primary " id="btn-acme_challenge-sync">"""
)
RE_AcmeChallenge_trigger_btn = re.compile(
    r"""<button class="btn btn-xs btn-primary " id="btn-acme_challenge-trigger">"""
)
RE_AcmeChallenge_triggered = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-challenge/\d+\?result=success&operation=acme\+server\+trigger"""
)
RE_AcmeChallenge_synced = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-challenge/\d+\?result=success&operation=acme\+server\+sync"""
)
RE_AcmeChallenge_trigger_fail = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-challenge/\d+\?result=error&error=ACME\+Server\+Trigger\+is\+not\+allowed\+for\+this\+AcmeChallenge&operation=acme\+server\+trigger"""
)


# note: AcmeDnsServer

RE_AcmeDnsServer = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-dns-server/(\d+)$"""
)
RE_AcmeDnsServer_created = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-dns-server/(\d+)\?result=success&operation=new&is_created=1$"""
)

RE_AcmeDnsServer_marked_global_default = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-dns-server/(\d+)\?result=success&operation=mark&action=global_default$"""
)
RE_AcmeDnsServer_marked_active = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-dns-server/(\d+)\?result=success&operation=mark&action=active$"""
)
RE_AcmeDnsServer_marked_inactive = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-dns-server/(\d+)\?result=success&operation=mark&action=inactive$"""
)
RE_AcmeDnsServer_edited = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-dns-server/(\d+)\?result=success&operation=edit$"""
)
RE_AcmeDnsServer_checked = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-dns-server/(\d+)\?result=success&operation=check$"""
)
RE_AcmeDnsServer_ensure_domains_results = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-dns-server/(\d+)/ensure-domains-results\?acme-dns-server-accounts=[\d,]+$"""
)
RE_AcmeDnsServer_import_domain_success = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-dns-server-account/(\d+)\?result=success&operation=import$"""
)
RE_AcmeDnsServer_import_domain_existing = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-dns-server-account/(\d+)\?result=existing&operation=import$"""
)


# note: AcmeOrder

RE_AcmeOrder = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-order/(\d+)(?:\?is_duplicate_renewal=true)?$"""
)
RE_AcmeOrder_retry = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-order/(\d+)\?result=success&operation=retry\+order$"""
)
RE_AcmeOrder_deactivated = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-order/(\d+)\?result=success&operation=mark&action=deactivate$"""
)
RE_AcmeOrder_invalidated = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-order/(\d+)\?result=success&operation=mark&action=invalid$"""
)
RE_AcmeOrder_invalidated_error = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-order/(\d+)\?result=error&error=Can\+not\+mark\+this\+order\+as\+%27invalid%27\.&operation=mark&action=invalid$"""
)


RE_AcmeOrder_processed = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-order/(\d+)\?result=success&operation=acme\+process$"""
)
RE_AcmeOrder_btn_acme_process__can = re.compile(
    r"""<button class="btn btn-xs btn-primary" id="btn-acme_process">"""
)


RE_AcmeOrder_downloaded_certificate = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-order/(\d+)\?result=success&operation=acme\+server\+download\+certificate$"""
)

RE_AcmeOrder_renewal_configuration = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-order/(\d+)\?result=success&operation=renewal\+configuration$"""
)

RE_AcmeOrder_renew_custom = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/acme-order/(\d+)\?result=success&operation=renew\+custom$"""
)


# note the space after `btn-info ` and no `disabled` class
RE_AcmeOrder_btn_deactive_authorizations = re.compile(
    r"""<button class="btn btn-xs btn-danger\s?" id="btn-deactivate_authorizations">"""
)

# note the `disabled` class
RE_AcmeOrder_btn_deactive_authorizations__off = re.compile(
    r"""<button class="btn btn-xs btn-danger disabled" id="btn-deactivate_authorizations">"""
)

# this should be hinted better...
RE_AcmeOrder_status = re.compile(r"<th>status</th>\s*<td><code>(\w+)</code>")


# note: CertificateCA

RE_CertificateCA_uploaded = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/certificate-ca/(\d+)\?result=success&is_created=\d$"""
)

# note: CertificateCAChain

RE_CertificateCAChain_uploaded = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/certificate-ca-chain/(\d+)\?result=success&is_created=\d$"""
)

# note: CertificateSigned

RE_CertificateSigned_main = re.compile(
    r"""href="/\.well-known/peter_sslers/certificate-signed/(\d+)"""
)

RE_CertificateSigned_operation_nginx_expire = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/certificate-signed/\d+\?result=success&operation=nginx-cache-expire&event\.id=\d+$"""
)

RE_CertificateSigned_operation_nginx_expire__GET = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/certificate-signed/\d+\?result=error&operation=nginx-cache-expire&message=POST\+required$"""
)


RE_CertificateSigned_button = re.compile(
    r"""
    <a\s+
        class="label\ label-info"\s+
        href="/.well-known/peter_sslers/certificate-signed/(\d+)"\s+
    >\s+
        <span\ class="glyphicon\ glyphicon-file"\ aria-hidden="true"></span>\s+
        CertificateSigned-(\d+)\s+
    </a>""",
    re.X,
)


# note: CoverageAssuranceEvent

RE_CoverageAssuranceEvent_mark = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/coverage-assurance-event/(\d+)\?result=success&operation=mark&action=resolution$"""
)

RE_CoverageAssuranceEvent_mark_nochange = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/coverage-assurance-event/(\d+)\?result=error&error=Error_Main--There\+was\+an\+error\+with\+your\+form\.\+No\+Change&operation=mark&action=resolution$"""
)

# note: Domain

RE_Domain_new = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/domain/(\d+)\?result=success&operation=new&is_created=1$"""
)

RE_Domain_new_AcmeDnsServerAccount = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/domain/(\d+)/acme-dns-server-accounts\?result=success&operation=new$"""
)

RE_Domain_operation_nginx_expire = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/domain/\d+\?result=success&operation=nginx-cache-expire&event\.id=\d+$"""
)

RE_Domain_operation_nginx_expire__GET = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/domain/\d+\?result=error&operation=nginx-cache-expire&message=POST\+required$"""
)

# note: RenewalConfiguration
RE_RenewalConfiguration = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/renewal-configuration/(\d+)(?:\?is_duplicate_renewal=true)?$"""
)

RE_RenewalConfiguration_link = re.compile(
    r'''href="/\.well-known/peter_sslers/renewal-configuration/(\d+)"'''
)


# note: UniqueFQDNSet

RE_UniqueFQDNSet_new = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/unique-fqdn-set/(\d+)\?result=success&operation=new&is_created=(\w+)"""
)

RE_UniqueFQDNSet_modify = re.compile(
    r"""^http://peter-sslers\.example\.com/\.well-known/peter_sslers/unique-fqdn-set/(\d+)\?result=success&operation=modify&is_created=(\w+)"""
)
