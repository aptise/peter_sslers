<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li class="active">Operations</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Operations Log</h2>
</%block>
    

<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            % if LetsencryptOperationsEvents:
                ${admin_partials.nav_pager(pager)}
                ${admin_partials.table_LetsencryptOperationsEvents(LetsencryptOperationsEvents, show_event='event.id')}
            % else:
                <em>
                    No events
                </em>
            % endif
    </div>
    <div class="row">
        <div class="col-sm-3">
            ${admin_partials.operations_options(enable_redis=enable_redis)}
        </div>
    </div>



</%block>


