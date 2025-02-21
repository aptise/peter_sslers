<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-servers">Acme Servers</a></li>
        <li><a href="${admin_prefix}/acme-server/${AcmeServer.id}">Focus ${AcmeServer.id}</a></li>
        <li class="active">AcmeServer Accounts</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Acme Server: Focus - Accounts</h2>
    ${admin_partials.handle_querystring_result()}
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-server/${AcmeServer.id}/acme-accounts.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if AcmeAccounts:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_AcmeAccounts(AcmeAccounts, perspective="AcmeServer")}
            % else:
                No known AcmeAccounts.
            % endif
        </div>
    </div>
</%block>

