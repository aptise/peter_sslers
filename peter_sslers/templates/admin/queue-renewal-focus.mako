<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/queue-renewals">Queue: Renewals</a></li>
        <li class="active">Focus [${RenewalQueueItem.id}]</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Queue: Renewals | Focus</h2>
</%block>


<%block name="content_main">
    <table class="table">
        <tr>
            <th>id</th>
            <td>
                <span class="label label-default">
                    ${RenewalQueueItem.id}
                </span>
            </td>
        </tr>
        <tr>
            <th>certificate_id</th>
            <td>
                <a class="label label-info"
                    href="${admin_prefix}/certificate/${RenewalQueueItem.ssl_server_certificate_id}"
                >
                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                    ${RenewalQueueItem.ssl_server_certificate_id}</a>
            </td>
        </tr>
        <tr>
            <th>ssl_unique_fqdn_set_id</th>
            <td>
                <a class="label label-info"
                    href="${admin_prefix}/unique-fqdn-set/${RenewalQueueItem.ssl_unique_fqdn_set_id}"
                >
                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                    ${RenewalQueueItem.ssl_unique_fqdn_set_id}</a>
            </td>
        </tr>
        <tr>
            <th>timestamp_entered</th>
            <td>
                <timestamp>${RenewalQueueItem.timestamp_entered or ''}</timestamp>
            </td>
        </tr>
        <tr>
            <th>timestamp_processed</th>
            <td>
                <timestamp>${RenewalQueueItem.timestamp_processed or ''}</timestamp>
            </td>
        </tr>
        <tr>
            <th>process_result</th>
            <td>
                ${RenewalQueueItem.process_result or ''}
            </td>
        </tr>
        ${admin_partials.table_tr_event_created(RenewalQueueItem.ssl_operations_event_id__child_of)}
        <tr>
            <th>operations event?</th>
            <td>
               % if RenewalQueueItem.operations_event:
                    <table class="table table-striped table-condensed">
                        <tr>
                            <th>event type</th>
                            <td>
                                <span class="label label-info">${RenewalQueueItem.operations_event.event_type_text}</span>
                            </td>
                        </tr>
                        <tr>
                            <th>timestamp_event</th>
                            <td>
                                <timestamp>${RenewalQueueItem.operations_event.timestamp_event or ''}</timestamp>
                            </td>
                        </tr>
                    </table>
               % endif
            </td>
        </tr>
    </table>
</%block>
