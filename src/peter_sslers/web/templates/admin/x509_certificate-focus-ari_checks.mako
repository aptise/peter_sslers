<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/x509-certificates">Server Certificates</a></li>
        <li><a href="${admin_prefix}/x509-certificate/${X509Certificate.id}">Focus [${X509Certificate.id}]</a></li>
        <li class="active">ARI Checks</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>X509Certificate Focus - ARI Checks</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/x509-certificate/${X509Certificate.id}/ari-check-history.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if AriChecks:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_AriChecks(AriChecks, perspective='X509Certificate')}
            % else:
                No known ArRI Checks
            % endif
        </div>
    </div>
</%block>
