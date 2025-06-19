<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificate-signeds">CertificateSigneds</a></li>
        <li class="active">Active Duplicates</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>CertificateSigneds - Active Duplicates</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/certificate-signeds/active-duplicates.json" class="label label-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % for pair in CertificateSignedsPairs:
            
                ${admin_partials.table_CertificateSigneds(pair, show_domains=True, show_days_to_expiry=True)}

            % endfor
        </div>
    </div>
</%block>
