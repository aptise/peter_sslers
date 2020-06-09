<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-dns-server-accounts">AcmeDnsServerAccounts</a></li>
        <li class="active">Focus [${AcmeDnsServerAccount.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>AcmeDnsServerAccount Focus</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-dns-server-account/${AcmeDnsServerAccount.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
        
            <table class='table table-striped table-condensed'>
                <tr>
                    <th>id</th>
                    <td>${AcmeDnsServerAccount.id}</td>
                </tr>        
                <tr>
                    <th>timestamp_created</th>
                    <td><timestamp>${AcmeDnsServerAccount.timestamp_created}</timestamp></td>
                </tr>        
                <tr>
                    <th>acme-dns Server</th>
                    <td>
                        <a
                            href="${admin_prefix}/acme-dns-server/${AcmeDnsServerAccount.acme_dns_server_id}"
                            class="btn btn-xs btn-info"
                        >
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            AcmeDnsServer | ${AcmeDnsServerAccount.acme_dns_server_id}
                        </a>
                    </td>
                </tr>        
                <tr>
                    <th>Domain</th>
                    <td>
                        <a
                            href="${admin_prefix}/domain/${AcmeDnsServerAccount.domain_id}"
                            class="btn btn-xs btn-info"
                        >
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            Domain | ${AcmeDnsServerAccount.domain_id} | ${AcmeDnsServerAccount.domain.domain_name}
                        </a>
                    </td>
                </tr>        

                <tr>
                    <th>is_active</th>
                    <td>${AcmeDnsServerAccount.is_active}</td>
                </tr>
                <tr>
                    <th>username</th>
                    <td><code>${AcmeDnsServerAccount.username}</code></td>
                </tr>

                <tr>
                    <th>password</th>
                    <td><code>${AcmeDnsServerAccount.password}</code></td>
                </tr>
                <tr>
                    <th>fulldomain</th>
                    <td><code>${AcmeDnsServerAccount.fulldomain}</code></td>
                </tr>
                <tr>
                    <th>subdomain</th>
                    <td><code>${AcmeDnsServerAccount.subdomain}</code></td>
                </tr>
                <tr>
                    <th>allowfrom</th>
                    <td><code>${AcmeDnsServerAccount.allowfrom}</code></td>
                </tr>
            </table>




        </div>
    </div>
</%block>
