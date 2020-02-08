<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-orders">ACME Orders</a></li>
        <li><a href="${admin_prefix}/acme-orders/${AcmeOrder.id}">Focus [${AcmeOrder.id}]</a></li>
        <li class="active">Authorizations</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>ACME Order - Focus - Authorizations</h2>
    ${admin_partials.standard_error_display()}
</%block>


<%block name="page_header_nav">
</%block>


<%block name="content_main">
    ${admin_partials.handle_querystring_result()}
    ${admin_partials.nav_pagination(pager)}
    ${admin_partials.table_AcmeAuthorizations(AcmeOrder, perspective='AcmeOrder.to_acme_authorizations')}
</%block>
