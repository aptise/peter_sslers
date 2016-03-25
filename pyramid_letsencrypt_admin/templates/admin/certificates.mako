<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li class="active">Certificates</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Certificates</h2>
</%block>
    

<%block name="content_main">
    % if LetsencryptServerCertificates:
        ${admin_partials.nav_pager(pager)}
        ${admin_partials.table_certificates__list(LetsencryptServerCertificates, show_domains=True)}
    % else:
        <em>
            No certificate_requests
        </em>
    % endif
</%block>
