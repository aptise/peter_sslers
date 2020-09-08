<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-dns-servers">acme-dns Servers</a></li>
        <li><a href="${admin_prefix}/acme-dns-server/${AcmeDnsServer.id}">Focus ${AcmeDnsServer.id}</a></li>
        <li class="active">Ensure Domains - Results</li>
    </ol>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-dns-server/${AcmeDnsServer.id}/ensure-domains-results.json?acme-dns-server-accounts=${request.params.get('acme-dns-server-accounts')}" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="page_header_col">
    <h2>acme-dns Server: Focus: Ensure Domain - Results</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
        
            <h3>Ensure Domains - Results</h3>
        
            <table class="table table-striped table-condensed">
                <thead>
                    <tr>
                        <th>id</th>
                        <th>domain name</th>
                        <th>CNAME key</th>
                        <th>CNAME value</th>
                    </tr>
                </thead>
                <tbody>
                    % for _acct in AcmeDnsServerAccounts:
                        <tr>
                            <td>
                                <a href="${admin_prefix}/acme-dns-server-account/${_acct.id}" class="label label-info">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeDnsServerAccount-${_acct.id}
                                </a>
                            </td>
                            <td>
                                <code>${_acct.domain.domain_name}</code>
                            </td>
                            <td>
                                <code>_acme-challenge</code>
                            </td>
                            <td>
                                <code>${_acct.fulldomain}</code>
                            </td>
                        </tr>                    
                    % endfor
                </tbody>
            </table>
        </div>
    </div>
</%block>
