<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-dns-server-accounts">AcmeDnsServerAccounts</a></li>
        <li><a href="${admin_prefix}/acme-dns-server-account/${AcmeDnsServerAccount.id}">Focus [${AcmeDnsServerAccount.id}]</a></li>
        <li class="active">Audit</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>AcmeDnsServerAccount Focus ${AcmeDnsServerAccount.id} - Audit</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-dns-server-account/${AcmeDnsServerAccount.id}/audit.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">

            <table class="table table-striped table-condensed">
                <tr>
                    <th></th>
                    <th>source</th>
                    <th>expected</th>
                    <th>actual</th>
                </tr>
                <tr>
                    <th>CNAME</th>
                    <td><code>_acme-challenge.${AcmeDnsServerAccount.domain.domain_name}</code></td>
                    <td><code>${AcmeDnsServerAccount.cname_target}</code></td>
                    <td><code>${AuditResults["resolved"]["CNAME"] or ''}</code></td>
                </tr>
                <tr>
                    <th>TXT</th>
                    <td><code>_acme-challenge.${AcmeDnsServerAccount.domain.domain_name}</code></td>
                    <td><code>${AcmeDnsServerAccount.cname_target}</code></td>
                    <td><code>${AuditResults["resolved"]["TXT"] or ''}</code></td>
                </tr>
            </table>
        </div>
    </div>
</%block>
