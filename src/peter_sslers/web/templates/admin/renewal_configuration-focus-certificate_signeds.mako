<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/renewal-configurations">RenewalConfiguration</a></li>
        <li><a href="${admin_prefix}/renewal-configuration/${RenewalConfiguration.id}">Focus [${RenewalConfiguration.id}]</a></li>
        <li class="active">Certificate Signeds</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>RenewalConfiguration Focus - Certificate Signeds</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            % if CertificateSigneds:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_CertificateSigneds(CertificateSigneds, perspective='RenewalConfiguration')}
            % else:
                No known CertificateSigneds
            % endif
        </div>
    </div>
</%block>
