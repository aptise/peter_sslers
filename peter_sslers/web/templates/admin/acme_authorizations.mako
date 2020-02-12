<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">ACME Authorizations</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>ACME Authorizations</h2>
</%block>


<%block name="page_header_nav">
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if AcmeAuthorizations:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_AcmeAuthorizations(AcmeAuthorizations, perspective="AcmeAuthorizations")}
            % else:
                <em>
                    No ACME Authorizations
                </em>
            % endif
        </div>
    </div>
</%block>
