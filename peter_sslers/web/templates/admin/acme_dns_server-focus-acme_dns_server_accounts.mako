<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-dns-servers">acme-dns Servers</a></li>
        <li><a href="${admin_prefix}/acme-dns-server/${AcmeDnsServer.id}">Focus ${AcmeDnsServer.id}</a></li>
        <li class="active">AcmeDnsServer Accounts</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>acme-dns Server: Focus</h2>
    ${admin_partials.handle_querystring_result()}
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-dns-server/${AcmeDnsServer.id}/accounts.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            ${AcmeDnsServerAccounts}
        </div>
    </div>
</%block>
