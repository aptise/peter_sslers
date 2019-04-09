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
      <li role="presentation" class="${'active' if sidenav_option == 'active_only' else ''}"><a href="${admin_prefix}/certificates/active">Active Certificates</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'inactive_only' else ''}"><a href="${admin_prefix}/certificates/inactive">Inactive Certificates</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'expiring' else ''}"><a href="${admin_prefix}/certificates/expiring">Expiring Certificates</a></li>
    </ul>
    <p class="pull-right">
        <a  href="${admin_prefix}/certificate/upload"
            title="${request.text_library.info_UploadExistingCertificate[0]}"
            class="btn btn-xs btn-primary"
        >
        <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
        Upload: Certificate (Existing)</a>
        % if sidenav_option == 'expiring' :
            <a href="${admin_prefix}/certificates/expiring.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        % elif sidenav_option == 'active_only' :
            <a href="${admin_prefix}/certificates/active.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        % elif sidenav_option == 'inactive_only' :
            <a href="${admin_prefix}/certificates/inactive.json" class="btn btn-xs btn-info">
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
            % if sidenav_option == 'active_only' :
                <p>Active Certificates.
                </p>
            % elif sidenav_option == 'inactive_only' :
                <p>Inactive Certificates.
                </p>
            % else:
                % if expiring_days:
                    <p>Certificates that will be expiring within `${expiring_days}` days.
                    </p>
                % endif
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
