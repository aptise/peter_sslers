<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li>Certificate Requests</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Certificate Requests</h2>
</%block>

    
<%block name="content_main">
    % if LetsencryptCertificateRequests:
        ${admin_partials.table_certificate_requests__list(LetsencryptCertificateRequests)}
    % else:
        <em>
            No certificate_requests
        </em>
    % endif
</%block>
