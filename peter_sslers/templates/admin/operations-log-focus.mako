<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li><a href="/.well-known/admin/operations/log">Operations log</a></li>
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
                    <td><span class="label label-default">${LetsencryptOperationsEvent.id}</span></td>
                </tr>
                <tr>
                    <th>event type</th>
                    <td><span class="label label-default">${LetsencryptOperationsEvent.event_type_text}</span></td>
                </tr>
                <tr>
                    <th>timestamp</th>
                    <td><timestamp>${LetsencryptOperationsEvent.timestamp_operation}</timestamp></td>
                </tr>
                <tr>
                    <th>child of</th>
                    <td>
                        % if LetsencryptOperationsEvent.letsencrypt_operations_event_id__child_of:
                            <span class="label label-default">${LetsencryptOperationsEvent.letsencrypt_operations_event_id__child_of}</span>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>payload</th>
                    <td><code type="payload">${LetsencryptOperationsEvent.event_payload_json}</code></td>
                </tr>
            </table>
        </div>
        <div class="col-sm-3">
            ${admin_partials.operations_options(enable_redis=enable_redis,
                                                enable_nginx=enable_nginx,
                                                )}
        </div>
    </div>



</%block>


