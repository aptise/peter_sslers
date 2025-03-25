<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">RoutineExecutions</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>RoutineExecutions</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/routine-executions.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>

<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            % if RoutineExecutions:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_RoutineExecutions(RoutineExecutions)}
            % else:
                <em>
                    No RoutineExecutions
                </em>
            % endif
        </div>
        <div class="col-sm-3">
        </div>
    </div>
</%block>
