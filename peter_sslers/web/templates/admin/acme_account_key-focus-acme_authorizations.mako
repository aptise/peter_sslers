<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-account-keys">AcmeAccountKeys</a></li>
        <li><a href="${admin_prefix}/acme-account-key/${AcmeAccountKey.id}">Focus [${AcmeAccountKey.id}]</a></li>
        <li class="active">AcmeAuthorizations</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>AcmeAccountKey - Focus | AcmeAuthorizations</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if AcmeAuthorizations:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_AcmeAuthorizations(AcmeAuthorizations, perspective='AcmeAccountKey')}
            % else:
                No known AcmeAuthorizations.
            % endif
        </div>
    </div>
</%block>
