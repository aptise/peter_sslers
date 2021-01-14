<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificate-cas">CertificateCAs</a></li>
        <li><a href="${admin_prefix}/certificate-ca/${CertificateCA.id}">Focus [${CertificateCA.id}]</a></li>
        <li class="active">CertificateCAs</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>CertificateCA - Focus - CertificateSigneds = Alt</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if CertificateSigneds:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_CertificateSigneds(CertificateSigneds, show_domains=True)}
            % else:
                No known CertificateSigneds.
            % endif
        </div>
    </div>
</%block>
