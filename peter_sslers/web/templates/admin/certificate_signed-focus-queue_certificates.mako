<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificate-signed">Server Certificates</a></li>
        <li><a href="${admin_prefix}/certificate-signed/${CertificateSigned.id}">Focus [${CertificateSigned.id}]</a></li>
        <li class="active">Queue Certificates</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>CertificateSigned Focus - Queue Certificates</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if QueueCertificates:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_QueueCertificates(QueueCertificates, perspective='CertificateSigned')}
            % else:
                No known QueueCertificates.
            % endif
        </div>
    </div>
</%block>
