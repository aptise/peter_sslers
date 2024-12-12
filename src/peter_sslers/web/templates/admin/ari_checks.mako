<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">ARIChecks</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>ARIChecks</h2>
</%block>


<%block name="page_header_nav">
    <ul class="nav nav-pills nav-stacked">
      <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="${admin_prefix}/ari-checks/all">All AriChecks</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'cert-latest' else ''}"><a href="${admin_prefix}/ari-checks/cert-latest">Latest AriChecks per Certificate</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'cert-latest-overdue' else ''}"><a href="${admin_prefix}/ari-checks/cert-latest-overdue">Latest AriChecks per Certificate (Overdue)</a></li>
    </ul>

    <p class="pull-right">
        <a href="${admin_prefix}/ari-checks/${sidenav_option}.json" class="btn btn-xs btn-info">
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
                ${admin_partials.table_AriChecks(AriChecks, perspective='AriChecks')}
            % else:
                <em>
                    No AriChecks
                </em>
            % endif
        </div>
    </div>
</%block>
