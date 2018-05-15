<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Operations</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Operations Log</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            % if SslOperationsEvents:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_SslOperationsEvents(SslOperationsEvents, show_event='event.id', event_type_listable=True, )}
            % else:
                <em>
                    no events
                </em>
            % endif
    </div>
    <div class="row">
        <div class="col-sm-3">
            % if event_type:
                <h5>Filtered to:</h5>
                <span class="label label-default">${event_type}</span>
                <hr/>
            % endif
            ${admin_partials.operations_options(enable_redis=enable_redis,
                                                enable_nginx=enable_nginx,
                                                as_list=True,
                                                active='/operations/log'
                                                )}
        </div>
    </div>
</%block>
