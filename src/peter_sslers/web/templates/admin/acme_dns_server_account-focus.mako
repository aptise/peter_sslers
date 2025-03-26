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
        <form action="${admin_prefix}/acme-dns-server-account/${AcmeDnsServerAccount.id}/audit" method="POST">
            <button class="btn btn-xs btn-primary" type="submit"  name="submit" value="submit">
                <span class="glyphicon glyphicon-wrench" aria-hidden="true"></span>
                audit
            </button>
        </form>
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
                    <td><span class="label label-default">${AcmeDnsServerAccount.id}</span></td>
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
                            class="label label-info"
                        >
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            AcmeDnsServer-${AcmeDnsServerAccount.acme_dns_server_id}
                        </a>
                    </td>
                </tr>        
                <tr>
                    <th>Domain</th>
                    <td>
                    
                        <a
                            href="${admin_prefix}/domain/${AcmeDnsServerAccount.domain_id}"
                            class="label label-info"
                        >
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            Domain-${AcmeDnsServerAccount.domain_id}
                        </a>
                        <span class="label label-default">${AcmeDnsServerAccount.domain.domain_name}</span>
                    </td>
                </tr>        

                <tr>
                    <th>is_active</th>
                    <td>
                        % if AcmeDnsServerAccount.is_active:
                            <span class="label label-success">active</span>
                        % else:
                            <span class="label label-danger">inactive</span>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>username</th>
                    <td><code>${AcmeDnsServerAccount.username}</code></td>
                </tr>

                <tr>
                    <th>password</th>
                    <td><code>${AcmeDnsServerAccount.password_sample}</code></td>
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
            
            
            <p>
                The ACME server expects this CNAME record:
                <table class="table table-striped table-condensed">
                    <tr>
                        <td>source</td>
                        <td><code>${AcmeDnsServerAccount.domain.acme_challenge_domain_name}</code></td>
                    </tr>
                    <tr>
                        <td>destination</td>
                        <td><code>${AcmeDnsServerAccount.cname_target}</code></td>
                    </tr>
                </table>
            </p>
            

            ## <a href="${admin_prefix}/acme-dns-server-account/${AcmeDnsServerAccount.id}/get"
            ##   class="btn btn-info"
            ## >
            ##    <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
            ##    GET
            ## </a>

        </div>
    </div>
</%block>
