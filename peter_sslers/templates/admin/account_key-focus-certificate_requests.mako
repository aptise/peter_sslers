<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/account-keys">Account Keys</a></li>
        <li><a href="${admin_prefix}/account-key/${LetsencryptAccountKey.id}">Focus [${LetsencryptAccountKey.id}]</a></li>
        <li class="active">Certificate Requests</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Account Key - Focus | Certificate Requests</h2>
</%block>


<%block name="content_main">

    % if LetsencryptCertificateRequests:
        ${admin_partials.nav_pagination(pager)}
        ${admin_partials.table_certificate_requests__list(LetsencryptCertificateRequests, show_domains=True)}
    % else:
        No known certificate requests.
    % endif

</%block>
