<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Renewal Configurations</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Renewal Configurations</h2>
    <p>A configuration is a renewable template for ACME Orders and Certificates</p>
</%block>


<%block name="page_header_nav">
    <ul class="nav nav-pills nav-stacked">
      <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="${admin_prefix}/renewal-configurations/all">All RenewalConfigurations</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'active' else ''}"><a href="${admin_prefix}/renewal-configurations/active">Active RenewalConfigurations</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'disabled' else ''}"><a href="${admin_prefix}/renewal-configurations/disabled">Disabled RenewalConfigurations</a></li>
    </ul>

    <p class="pull-right">
        <a  href="${admin_prefix}/renewal-configuration/new"
            title="Renewal Configuration - New"
            class="btn btn-xs btn-primary"
        >
        <span class="glyphicon glyphicon-wrench" aria-hidden="true"></span>
        New RenewalConfiguration</a>

        <a href="${admin_prefix}/renewal-configurations/${sidenav_option}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            ${admin_partials.handle_querystring_result()}

            % if RenewalConfigurations:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_RenewalConfigurations(RenewalConfigurations, perspective="RenewalConfiguration")}
            % else:
                <em>
                    No RenewalConfigurations
                </em>
            % endif
        </div>
    </div>
</%block>
