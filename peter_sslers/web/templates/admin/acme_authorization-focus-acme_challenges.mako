<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-authorizations">ACME Authorization</a></li>
        <li><a href="${admin_prefix}/acme-authorization/${AcmeAuthorization.id}">Focus [${AcmeAuthorization.id}]</a></li>
        <li class="active">Acme Challenges</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>ACME Authorization - Focus - Acme Challenges</h2>
</%block>


<%block name="page_header_nav">
</%block>


<%block name="content_main">
    ${admin_partials.handle_querystring_result()}
    
    <div class="row">
        <div class="col-sm-12">
            ${admin_partials.nav_pagination(pager)}
            ${admin_partials.table_AcmeChallenges(AcmeChallenges, perspective="AcmeAuthorization")}
        </div>
    </div>
</%block>
