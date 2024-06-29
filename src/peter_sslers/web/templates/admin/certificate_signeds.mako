<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">CertificateSigneds</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>CertificateSigneds</h2>
</%block>


<%block name="page_header_nav">
    <ul class="nav nav-pills nav-stacked">
      <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="${admin_prefix}/certificate-signeds/all">All Certificates</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'active' else ''}"><a href="${admin_prefix}/certificate-signeds/active">Active Certificates</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'inactive' else ''}"><a href="${admin_prefix}/certificate-signeds/inactive">Inactive Certificates</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'expiring' else ''}"><a href="${admin_prefix}/certificate-signeds/expiring">Expiring Certificates</a></li>
    </ul>
    <p class="pull-right">
        <a  href="${admin_prefix}/certificate-signed/upload"
            title="CertificateSigned - Upload"
            class="btn btn-xs btn-primary"
        >
        <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
        Upload: Certificate (Existing)</a>
        % if sidenav_option == 'expiring' :
            <a href="${admin_prefix}/certificate-signeds/expiring.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        % elif sidenav_option == 'active' :
            <a href="${admin_prefix}/certificate-signeds/active.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        % elif sidenav_option == 'inactive' :
            <a href="${admin_prefix}/certificate-signeds/inactive.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        % else:
            <a href="${admin_prefix}/certificate-signeds/all.json" class="btn btn-xs btn-info">
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
                <p>Active CertificateSigneds.
                </p>
            % elif sidenav_option == 'inactive' :
                <p>Inactive CertificateSigneds.
                </p>
            % else:
                % if expiring_days and sidenav_option != 'all':
                    <p>CertificateSigneds that will be expiring within `${expiring_days}` days.
                    </p>
                % endif
            % endif

            % if CertificateSigneds:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_CertificateSigneds(CertificateSigneds, show_domains=True, show_expiring_days=True)}
            % else:
                <em>
                    No Server Certificates
                </em>
            % endif
        </div>
    </div>
</%block>
