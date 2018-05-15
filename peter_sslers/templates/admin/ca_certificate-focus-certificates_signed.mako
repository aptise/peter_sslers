<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/ca-certificates">CA Certificates</a></li>
        <li><a href="${admin_prefix}/ca-certificate/${SslCaCertificate.id}">Focus [${SslCaCertificate.id}]</a></li>
        <li class="active">CA Certificates</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>CA Certificate - Focus - Signed Certificates</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if SslServerCertificates:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_certificates__list(SslServerCertificates, show_domains=True)}
            % else:
                No known certificates.
            % endif
        </div>
    </div>
</%block>
