<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Certificates</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Certificates</h2>
</%block>

<%block name="page_header_nav">
    <ul class="nav nav-pills nav-stacked">
      <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="${admin_prefix}/certificates">All Certificates</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'expiring' else ''}"><a href="${admin_prefix}/certificates/expiring">Expiring Certificates</a></li>
    </ul>
    <p class="pull-right">
        % if sidenav_option == 'expiring' :
            <a href="${admin_prefix}/certificates/expiring.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>    
                .json
            </a>
        % else:
            <a href="${admin_prefix}/certificates.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>    
                .json
            </a>
        % endif
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if expiring_days:
                <p>Certificates that will be expiring within `${expiring_days}` days.
                </p>
            % endif

            % if SslServerCertificates:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_certificates__list(SslServerCertificates, show_domains=True, show_expiring_days=True)}
            % else:
                <em>
                    No Server Certificates
                </em>
            % endif
        </div>
    </div>
</%block>
