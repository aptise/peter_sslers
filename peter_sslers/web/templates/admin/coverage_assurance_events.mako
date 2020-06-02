<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Coverage Assurance Events</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Coverage Assurance Events</h2>
</%block>


<%block name="page_header_nav">
    <ul class="nav nav-pills nav-stacked">
      <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="${admin_prefix}/coverage-assurance-events/all">All</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'unresolved' else ''}"><a href="${admin_prefix}/coverage-assurance-events/unresolved">Unresolved</a></li>
    </ul>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if CoverageAssuranceEvents:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_CoverageAssuranceEvents(CoverageAssuranceEvents)}
            % else:
                <em>
                    No CoverageAssuranceEvents
                </em>
            % endif
            </div>
        </div>
    </div>
</%block>
