<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-accounts">AcmeAccounts</a></li>
        <li><a href="${admin_prefix}/acme-account/${AcmeAccount.id}">Focus [${AcmeAccount.id}]</a></li>
        <li class="active">AcmeAccountKeys</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>AcmeAccount - Focus | AcmeAccountKeys</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-account/${AcmeAccount.id}/acme-account-keys.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if AcmeAccountKeys:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_AcmeAccountKeys(AcmeAccountKeys, perspective='AcmeAccount')}
            % else:
                No known AcmeAccountKeys.
            % endif
        </div>
    </div>
</%block>
