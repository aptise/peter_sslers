<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/ca-certificates">CA Certificates</a></li>
        <li><a href="${admin_prefix}/ca-certificate/${CACertificate.id}">Focus [${CACertificate.id}]</a></li>
        <li class="active">CA Certificates</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>CA Certificate - Focus - ServerCertificates</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if ServerCertificates:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_ServerCertificates(ServerCertificates, show_domains=True)}
            % else:
                No known ServerCertificates.
            % endif
        </div>
    </div>
</%block>
