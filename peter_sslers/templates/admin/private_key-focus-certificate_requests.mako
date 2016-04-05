<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li><a href="/.well-known/admin/private-keys">Private Keys</a></li>
        <li><a href="/.well-known/admin/private-key/${LetsencryptPrivateKey.id}">Focus [${LetsencryptPrivateKey.id}]</a></li>
        <li class="active">Certificate Requests</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Private Key - Focus | Certificate Requests</h2>
</%block>


<%block name="content_main">

    % if LetsencryptCertificateRequests:
        ${admin_partials.nav_pagination(pager)}
        ${admin_partials.table_certificate_requests__list(LetsencryptCertificateRequests, show_domains=True)}
    % else:
        No known certificate requests.
    % endif

</%block>
