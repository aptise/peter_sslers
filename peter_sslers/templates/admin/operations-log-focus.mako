<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/operations/log">Operations Events</a></li>
        <li class="active">Focus</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Operations Log</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            <table class="table table-striped table-condensed">
                <tr>
                    <th>id</th>
                    <td><span class="label label-default">${SslOperationsEvent.id}</span></td>
                </tr>
                <tr>
                    <th>event type</th>
                    <td><span class="label label-default">${SslOperationsEvent.event_type_text}</span></td>
                </tr>
                <tr>
                    <th>timestamp</th>
                    <td><timestamp>${SslOperationsEvent.timestamp_event}</timestamp></td>
                </tr>
                <tr>
                    <th>child of</th>
                    <td>
                        % if SslOperationsEvent.ssl_operations_event_id__child_of:
                            <a  href="${admin_prefix}/operations/log/item/${SslOperationsEvent.ssl_operations_event_id__child_of}"
                                class="label label-info"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ${SslOperationsEvent.ssl_operations_event_id__child_of}
                            </a>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>payload</th>
                    <td><code type="payload">${SslOperationsEvent.event_payload_json}</code></td>
                </tr>
            </table>
            
            <h4>Children</h4>
            ${admin_partials.table_SslOperationsEvents(SslOperationsEvent.children, show_event='event.id')}

            <h4>Operation Object Events?</h4>
            ${admin_partials.table_SslOperationsObjectEvents(SslOperationsEvent.object_events, table_context='log-focus')}
        </div>
        <div class="col-sm-3">
            ${admin_partials.operations_options(enable_redis=enable_redis,
                                                enable_nginx=enable_nginx,
                                                )}
        </div>
    </div>
</%block>


