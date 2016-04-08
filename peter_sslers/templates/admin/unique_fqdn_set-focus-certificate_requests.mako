<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/unique-fqdn-sets">Unique FQDN Sets</a></li>
        <li><a href="${admin_prefix}/unique-fqdn-set/${SslUniqueFQDNSet.id}">Focus [${SslUniqueFQDNSet.id}]</a></li>
        <li class="active">Certificate Requests</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Unique FQDN Set Focus - Certificate Requests</h2>
</%block>


<%block name="content_main">

    % if SslCertificateRequests:
        ${admin_partials.nav_pagination(pager)}
        ${admin_partials.table_certificate_requests__list(SslCertificateRequests, show_domains=True)}
    % else:
        No known certificates requests.
    % endif

</%block>
