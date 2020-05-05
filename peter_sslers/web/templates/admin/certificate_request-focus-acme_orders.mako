<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificate-requests">Certificate Requests</a></li>
        <li><a href="${admin_prefix}/certificate-request/${CertificateRequest.id}">Focus [${CertificateRequest.id}]</a></li>
        <li class="active">ACME Orders</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Certificate Request - Focus - ACME Orders</h2>
</%block>


<%block name="page_header_nav">
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">

            ${admin_partials.nav_pagination(pager)}
            ${admin_partials.table_AcmeOrders(AcmeOrders, perspective='CertificateRequest')}

        </div>
    </div>
</%block>
