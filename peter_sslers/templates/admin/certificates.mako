<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li class="active">Certificates</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Certificates</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            % if expiring_days:
                <p>Certificates that will be expiring within `${expiring_days}` days.
                </p>
            % endif

            % if LetsencryptServerCertificates:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_certificates__list(LetsencryptServerCertificates, show_domains=True, show_expiring_days=True)}
            % else:
                <em>
                    No Server Certificates
                </em>
            % endif
        </div>
        <div class="col-sm-3">
            <ul class="nav nav-pills nav-stacked">
              <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="/.well-known/admin/certificates">All Certificates</a></li>
              <li role="presentation" class="${'active' if sidenav_option == 'expiring' else ''}"><a href="/.well-known/admin/certificates/expiring">Expiring Certificates</a></li>
            </ul>
        </div>
    </div>
</%block>
