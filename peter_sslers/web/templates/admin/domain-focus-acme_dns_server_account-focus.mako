<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/domains">Domains</a></li>
        <li><a href="${admin_prefix}/domain/${Domain.id}">Focus [${Domain.id}]</a></li>
        <li class="active">AcmeDnsServerAccount</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Domain Focus - AcmeDnsServerAccount</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/domain/${Domain.id}/acme-dns-server/${AcmeDnsServerAccount.acme_dns_server_id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            ${AcmeDnsServerAccount.__dict__}
        </div>
    </div>
</%block>
