<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li>Peter SSLers</li>
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/queue-renewals">Queue: Renewals</a></li>
        <li class="active">Focus [${RenewalQueueItem.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Queue: Renewals | Focus</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
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
                    <th>is_active</th>
                    <td>
                        <span class="label label-${'success' if RenewalQueueItem.is_active else 'warning'}">
                            ${'Active' if RenewalQueueItem.is_active else 'inactive'}
                        </span>

                        % if RenewalQueueItem.is_active:
                            &nbsp;
                            <a  class="label label-warning"
                                href="${admin_prefix}/queue-renewal/${RenewalQueueItem.id}/mark?action=cancelled"
                            >
                                <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                cancel
                            </a>
                        % else:
                            <span class="label label-default">cancelled</span>
                        % endif
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
                        </hr/>
                        <code>${RenewalQueueItem.unique_fqdn_set.domains_as_string}</code>
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
                ${admin_partials.table_tr_event_created(RenewalQueueItem)}
            </table>
    
            <h4>Process History</h4>
            % if RenewalQueueItem.operations_object_events:
                ${admin_partials.table_SslOperationsObjectEvents(RenewalQueueItem.operations_object_events, table_context=None)}
            % endif
        </div>
    </div>
</%block>
