<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li><a href="/.well-known/admin/ca_certificates">CA Certificates</a></li>
        <li><a href="/.well-known/admin/ca_certificate/${LetsencryptCACertificate.id}">Focus [${LetsencryptCACertificate.id}]</a></li>
        <li class="active">CA Certificates</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>CA Certificate - Focus - Signed Certificates</h2>
</%block>
    

<%block name="content_main">

    % if LetsencryptHttpsCertificates:
        ${admin_partials.nav_pager(pager)}
        ${admin_partials.table_certificates__list(LetsencryptHttpsCertificates, show_domains=True)}
    % else:
        No known certificates.
    % endif 
    
</%block>
