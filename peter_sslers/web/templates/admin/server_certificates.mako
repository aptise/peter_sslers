<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">ServerCertificates</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>ServerCertificates</h2>
</%block>


<%block name="page_header_nav">
    <ul class="nav nav-pills nav-stacked">
      <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="${admin_prefix}/server-certificates/all">All Certificates</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'active' else ''}"><a href="${admin_prefix}/server-certificates/active">Active Certificates</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'inactive' else ''}"><a href="${admin_prefix}/server-certificates/inactive">Inactive Certificates</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'expiring' else ''}"><a href="${admin_prefix}/server-certificates/expiring">Expiring Certificates</a></li>
    </ul>
    <p class="pull-right">
        <a  href="${admin_prefix}/server-certificate/upload"
            title="ServerCertificate - Upload"
            class="btn btn-xs btn-primary"
        >
        <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
        Upload: Certificate (Existing)</a>
        % if sidenav_option == 'expiring' :
            <a href="${admin_prefix}/server-certificates/expiring.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        % elif sidenav_option == 'active' :
            <a href="${admin_prefix}/server-certificates/active.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        % elif sidenav_option == 'inactive' :
            <a href="${admin_prefix}/server-certificates/inactive.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        % else:
            <a href="${admin_prefix}/server-certificates/all.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        % endif
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if sidenav_option == 'active' :
                <p>Active ServerCertificates.
                </p>
            % elif sidenav_option == 'inactive' :
                <p>Inactive ServerCertificates.
                </p>
            % else:
                % if expiring_days:
                    <p>ServerCertificates that will be expiring within `${expiring_days}` days.
                    </p>
                % endif
            % endif

            % if ServerCertificates:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_ServerCertificates(ServerCertificates, show_domains=True, show_expiring_days=True)}
            % else:
                <em>
                    No Server Certificates
                </em>
            % endif
        </div>
    </div>
</%block>
