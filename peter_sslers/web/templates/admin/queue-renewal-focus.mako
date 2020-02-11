<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
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
            ${admin_partials.handle_querystring_result()}
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
                            <form action="${admin_prefix}/queue-renewal/${RenewalQueueItem.id}/mark" method="POST" style="display:inline;">
                                <input type="hidden" name="action" value="cancel"/>
                                <button class="label label-warning" type="submit">
                                    <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                    cancel
                                </button>
                            </form>
                        % else:
                            <span class="label label-default">cancelled</span>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>certificate_id - renewal of</th>
                    <td>
                        % if RenewalQueueItem.server_certificate_id:
                            <a class="label label-info"
                                href="${admin_prefix}/certificate/${RenewalQueueItem.server_certificate_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                cert-${RenewalQueueItem.server_certificate_id}</a>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>unique_fqdn_set_id</th>
                    <td>
                        <a class="label label-info"
                            href="${admin_prefix}/unique-fqdn-set/${RenewalQueueItem.unique_fqdn_set_id}"
                        >
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            UniqueFQDNSet-${RenewalQueueItem.unique_fqdn_set_id}</a>
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
                <tr>
                    <th>certificate_id - renewed</th>
                    <td>
                        % if RenewalQueueItem.server_certificate_id__renewed:
                            <a class="label label-info"
                                href="${admin_prefix}/certificate/${RenewalQueueItem.server_certificate_id__renewed}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                cert-${RenewalQueueItem.server_certificate_id__renewed}</a>
                        % endif
                    </td>
                </tr>
                ${admin_partials.table_tr_OperationsEventCreated(RenewalQueueItem)}
            </table>

            <h4>Process History</h4>
            % if RenewalQueueItem.operations_object_events:
                ${admin_partials.table_OperationsObjectEvents(RenewalQueueItem.operations_object_events, table_context=None)}
            % endif
        </div>
    </div>
</%block>
