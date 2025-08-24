<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/x509-certificates">X509Certificates</a></li>
        <li class="active">Active Duplicates</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>X509Certificates - Active Duplicates</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/x509-certificates/active-duplicates.json" class="label label-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % for pair in X509CertificatesPairs:
            
                ${admin_partials.table_X509Certificates(pair, show_domains=True, show_days_to_expiry=True)}

            % endfor
        </div>
    </div>
</%block>
