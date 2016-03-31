<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li><a href="/.well-known/admin/domains">Domains</a></li>
        <li><a href="/.well-known/admin/domain/${LetsencryptDomain.id}">Focus [${LetsencryptDomain.id}]</a></li>
        <li class="active">Certificate Requests</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Domain Focus - Certificate Requests</h2>
</%block>

    
<%block name="content_main">

    % if LetsencryptServerCertificates:
        ${admin_partials.nav_pagination(pager)}
        ${admin_partials.table_certificates__list(LetsencryptCertificateRequests, show_domains=True)}
    % else:
        No known certificates.
    % endif 

</%block>
