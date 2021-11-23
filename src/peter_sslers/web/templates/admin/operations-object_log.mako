<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Operations</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Object Log</h2>
    ${admin_partials.handle_querystring_result()}
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            % if OperationsObjectEvents:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_OperationsObjectEvents(OperationsObjectEvents, table_context='log_list')}
            % else:
                <em>
                    no events
                </em>
            % endif
    </div>
    <div class="row">
        <div class="col-sm-3">
            ${admin_partials.operations_options(enable_redis=enable_redis,
                                                enable_nginx=enable_nginx,
                                                )}
        </div>
    </div>
</%block>
