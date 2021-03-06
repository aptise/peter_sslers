<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/queue-domains">Queue: Domains</a></li>
        <li class="active">Focus [${QueueDomainItem.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Queue: Domains | Focus</h2>
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
                            ${QueueDomainItem.id}
                        </span>
                    </td>
                </tr>
                <tr>
                    <th>domain_name</th>
                    <td>
                        <code>
                            ${QueueDomainItem.domain_name}
                        </code>
                    </td>
                </tr>
                <tr>
                    <th>is_active</th>
                    <td>
                        <span class="label label-${'success' if QueueDomainItem.is_active else 'warning'}">
                            ${'Active' if QueueDomainItem.is_active else 'inactive'}
                        </span>

                        % if QueueDomainItem.is_active:
                            &nbsp;
                            <form action="${admin_prefix}/queue-domain/${QueueDomainItem.id}/mark" method="POST" style="display:inline;">
                                <input type="hidden" name="action" value="cancel"/>
                                <button class="btn btn-xs btn-warning" type="submit">
                                    <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                    cancel
                                </button>
                            </form>
                        % else:
                            <span class="label label-default">cancelled</span>
                            <em>queue this domain again to activate it.</em>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>timestamp_created</th>
                    <td>
                        <timestamp>${QueueDomainItem.timestamp_created or ''}</timestamp>
                    </td>
                </tr>
                <tr>
                    <th>timestamp_processed</th>
                    <td>
                        <timestamp>${QueueDomainItem.timestamp_processed or ''}</timestamp>
                    </td>
                </tr>
                <tr>
                    <th>domain?</th>
                    <td>
                        % if QueueDomainItem.domain_id:
                            <a class="label label-info" href="${admin_prefix}/domain/${QueueDomainItem.domain_id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                Domain-${QueueDomainItem.domain_id}
                            </a>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>operations event?</th>
                    <td>
                       % if QueueDomainItem.operations_event__created:
                            <table class="table table-striped table-condensed">
                                <tr>
                                    <th>event</th>
                                    <td>
                                        <a class="label label-info" href="${admin_prefix}/operations/log/item/${QueueDomainItem.operations_event__created.id}">
                                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                            ${QueueDomainItem.operations_event__created.id}
                                        </a>
                                    </td>
                                </tr>
                                <tr>
                                    <th>event type</th>
                                    <td>
                                        <span class="label label-default">${QueueDomainItem.operations_event__created.event_type_text}</span>
                                    </td>
                                </tr>
                                <tr>
                                    <th>timestamp_event</th>
                                    <td>
                                        <timestamp>${QueueDomainItem.operations_event__created.timestamp_event or ''}</timestamp>
                                    </td>
                                </tr>
                            </table>
                       % endif
                    </td>
                </tr>
            </table>
            <hr/>

            <h4>Operation Object Events</h4>
            ${admin_partials.table_OperationsObjectEvents(QueueDomainItem.operations_object_events, table_context='domain')}
        </div>
    </div>
</%block>
