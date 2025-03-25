<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/domains">Domains</a></li>
        <li><a href="${admin_prefix}/domain/${Domain.id}">Focus [${Domain.id}-${Domain.domain_name}]</a></li>
        <li class="active">Renewal Configurations</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Domain Focus - Renewal Configurations</h2>
</%block>


<%block name="page_header_nav">
    <ul class="nav nav-pills nav-stacked">
      <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="${admin_prefix}/domain/${Domain.id}/renewal-configurations/all">All RenewalConfigurations</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'single' else ''}"><a href="${admin_prefix}/domain/${Domain.id}/renewal-configurations/single">Single RenewalConfigurations</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'multi' else ''}"><a href="${admin_prefix}/domain/${Domain.id}/renewal-configurations/multi">Multi RenewalConfigurations</a></li>
    </ul>

    <p class="pull-right">
        <a href="${admin_prefix}/domain/${Domain.id}/renewal-configurations/${sidenav_option}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>

<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            % if RenewalConfigurations:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_RenewalConfigurations(RenewalConfigurations, perspective='Domain')}
            % else:
                No known RenewalConfigurations
            % endif
        </div>
    </div>
</%block>
