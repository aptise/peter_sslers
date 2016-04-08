<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li>Certificate Requests</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Certificate Requests</h2>

    ${admin_partials.standard_error_display(has_message=True)}
</%block>


<%block name="content_main">

    % if SslCertificateRequests:
        ${admin_partials.nav_pagination(pager)}
        ${admin_partials.table_certificate_requests__list(SslCertificateRequests, show_domains=True, show_certificate=True)}
    % else:
        <em>
            No Certificate Requests
        </em>
    % endif
</%block>
