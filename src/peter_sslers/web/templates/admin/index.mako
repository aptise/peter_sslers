<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="page_header_col">
##    <h2>Admin Index</h2>

    % if not AcmeAccount_GlobalDefault:
        <div class="alert alert-warning">
            <span class="glyphicon glyphicon-exclamation-sign" aria-hidden="true"></span>
            <b>Setup Not Finished</b>
            There is no Global Default AcmeAccount configured.
            Any AcmeAccount for can be configured as the Global Default.
            Browse AcmeAccounts at
            <a  class="label label-info"
                href="${admin_prefix}/acme-accounts"
            >
                <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                AcmeAccounts
            </a>
        </div>
    % endif

</%block>


<%block name="content_main">
    ${admin_partials.handle_querystring_result()}


    <div class="row">
        <div class="col-sm-4 pull-right">
            <a  href="${admin_prefix}/help"
                class="btn btn-xs btn-warning"
            >
                <span class="glyphicon glyphicon-info-sign" aria-hidden="true"></span>
                Help</a>
            <a  href="${admin_prefix}/settings"
                class="btn btn-xs btn-warning"
            >
                <span class="glyphicon glyphicon-info-sign" aria-hidden="true"></span>
                Settings</a>
            <a href="${admin_prefix}/api"
                class="btn btn-xs btn-warning"
            >
                <span class="glyphicon glyphicon-transfer" aria-hidden="true"></span>
                api endpoints
                </a>
        </div>
    </div>

    <div class="row">
        <div class="col-sm-4">
            <h3>Enrolled Records</h3>
            <ul class="nav nav-pills nav-stacked">
                <li><a href="${admin_prefix}/domains"
                       title="Domains"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    domains</a></li>
                <li><a href="${admin_prefix}/private-keys"
                       title="PrivateKeys"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    private-keys</a></li>
                <li><a href="${admin_prefix}/certificate-signeds"
                       title="CertificateSigneds"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    certificate-signeds</a></li>
                <li><a href="${admin_prefix}/unique-fqdn-sets"
                       title="UniqueFQDNs"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    unique-fqdn-sets</a></li>
                <li><a href="${admin_prefix}/domains-blocklisted"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    domains-blocklisted</a></li>
                <li><a href="${admin_prefix}/renewal-configurations"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    renewal-configurations</a></li>
            </ul>

            <h3>Recordkeeping - ACME Logs</h3>
            <ul class="nav nav-pills nav-stacked">
                <li><a href="${admin_prefix}/acme-challenge-polls"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    acme-challenge-polls</a></li>
                <li><a href="${admin_prefix}/acme-challenge-unknown-polls"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    acme-challenge-unknown-polls</a></li>
                <li><a href="${admin_prefix}/acme-event-logs"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    acme-event-logs</a></li>
                <li><a href="${admin_prefix}/ari-checks"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    ari-checks</a></li>
            </ul>

            <h3>Recordkeeping - ACME & Objects</h3>
            <ul class="nav nav-pills nav-stacked">
                <li><a href="${admin_prefix}/acme-accounts"
                       title="ACME Accounts"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    acme-accounts</a></li>
                <li><a href="${admin_prefix}/acme-authorizations"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    acme-authorizations</a></li>
                <li><a href="${admin_prefix}/acme-authz-potentials"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    acme-authz-potentials</a></li>
                <li><a href="${admin_prefix}/acme-challenges"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    acme-challenges</a></li>
                <li><a href="${admin_prefix}/acme-orders/all"
                       title="ACME Orders"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    acme-orders</a></li>
                <li><a href="${admin_prefix}/certificate-requests"
                       title="CertificateRequests"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    certificate-requests
                    </a></li>
                <li><a href="${admin_prefix}/domain-autocerts"
                       title="DomainAutocerts"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    domain-autocerts
                    </a></li>
            </ul>

            <h3>Upstream Providers</h3>
            <ul class="nav nav-pills nav-stacked">
                <li><a href="${admin_prefix}/acme-servers"
                       title="Acme Servers"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    acme-servers</a></li>
                <li><a href="${admin_prefix}/acme-dns-servers"
                       title="acme-dns Servers"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    acme-dns Servers</a></li>
                <li><a href="${admin_prefix}/acme-dns-server-accounts"
                       title="acme-dns Server Accounts"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    acme-dns Server Accounts</a></li>
                <li><a href="${admin_prefix}/certificate-cas"
                       title="CertificateCAs"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    certificate-cas</a></li>
                <li><a href="${admin_prefix}/certificate-ca-chains"
                       title="CertificateCAChains"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    certificate-ca-chains</a></li>
            </ul>


        </div>
        <div class="col-sm-4">
            <h3>Status</h3>
            <ul class="nav nav-pills nav-stacked">
                <li><a href="${admin_prefix}/api/nginx/status.json">
                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                    api : nginx/status.json</a></li>
            </ul>
            <h3>Tools</h3>
            <ul class="nav nav-pills nav-stacked">
                <li><a href="${admin_prefix}/domains/search">
                    <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                    search domains</a></li>
                <li><a href="${admin_prefix}/domains/challenged">
                    <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                    domains with blocking challenges</a></li>
                <li><a href="${admin_prefix}/coverage-assurance-events"
                    >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    coverage-assurance-events</a></li>
            </ul>
            ${admin_partials.operations_options(enable_redis=enable_redis,
                                                enable_nginx=enable_nginx,
                                                as_list=True,
                                                )}
        </div>
        <div class="col-sm-4">
            <h3>New CertificateSigneds</h3>
            <ul class="nav nav-pills nav-stacked">
                <li>
                    <a  href="${admin_prefix}/renewal-configuration/new"
                        title="New Renewal Configuration"
                        class="btn btn-primary"
                    >
                    <span class="glyphicon glyphicon-wrench" aria-hidden="true"></span>
                    New Renewal Configuration</a></li>
                <li>
                    <a  href="${admin_prefix}/acme-order/new/freeform"
                        title="AcmeOrder NEW Freeform"
                        class="btn btn-primary"
                    >
                    <span class="glyphicon glyphicon-wrench" aria-hidden="true"></span>
                    New ACME Order: Automated</a></li>
            </ul>

            <h3>Existing CertificateSigneds</h3>
            <ul class="nav nav-pills nav-stacked">
                <li>
                    <a  href="${admin_prefix}/acme-account/upload"
                        title="If you need to upload a LetEncrypt AccountKey"
                    >
                    <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
                    Upload: AcmeAccount</a></li>
                <li>
                    <a  href="${admin_prefix}/certificate-ca/upload-cert"
                        title="CertificateCA - Upload"
                    >
                    <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
                    Upload: CertificateCA</a></li>
                <li>
                    <a  href="${admin_prefix}/certificate-signed/upload"
                        title="CertificateSigned - Upload"
                    >
                    <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
                    Upload: Certificate (Existing)</a></li>
                <li>
                    <a  href="${admin_prefix}/private-key/upload"
                        title="Private Key - Upload"
                    >
                    <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
                    Upload: Private Key</a></li>
            </ul>

            <h3>System Info</h3>
            <em>Detailed information is available on the "Settings" page.</em>
            <table class="table table-striped table-condensed">
                <tr>
                    <th>enable_nginx</th>
                    <td>${request.registry.settings["app_settings"]['enable_nginx']}</td>
                </tr>
                <tr>
                    <th>enable_redis</th>
                    <td>${request.registry.settings["app_settings"]['enable_redis']}</td>
                </tr>
            </table>
        </div>
    </div>
</%block>
