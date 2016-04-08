<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/operations">Operations</a></li>
        <li class="active">Redis</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Redis Operations</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            % if SslOperationsEvents:
                ${admin_partials.nav_pagination(pager)}
                <%
                    event_id = None
                    if show_event is not None:
                        event_id = request.params.get('event.id')
                %>
                <table class="table table-striped table-condensed">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>event timestamp</th>
                            <th>prime type</th>
                            <th>items primed</th>
                        </tr>
                    </thead>
                    <tbody>
                        % for event in SslOperationsEvents:
                            <tr class="${'success' if event_id == str(event.id) else ''}">
                                <td><span class="label label-default">${event.id}</span></td>
                                <td><timestamp>${event.timestamp_operation}</timestamp></td>
                                <td>
                                    % if 'prime_style' in event.event_payload_json:
                                        ${event.event_payload_json['prime_style']}
                                    % endif
                                </td>
                                <td>
                                    % if 'total_primed' in event.event_payload_json:
                                        <code class="payload">${event.event_payload_json['total_primed']}</code>
                                    % endif
                                </td>
                            </tr>
                        % endfor
                    </tbody>
                </table>
            % else:
                <em>
                    no events
                </em>
            % endif
    </div>
    <div class="row">
        <div class="col-sm-3">
            <div class="alert alert-info">
                <p>
                    Redis is enabled for this server.
                </p>
                <p>
                    The prime style is: <em>${request.registry.settings['redis.prime_style']}</em>
                </p>
            </div>
            <p>
                <a  href="${admin_prefix}/operations/redis/prime"
                    class="label label-primary"
                >
                    <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                    Prime Redis Cache
                </a>
            </p>
            <p>
                <a  href="${admin_prefix}/operations/log"
                    class="label label-info"
                >
                    <span class="glyphicon glyphicon-list-alt" aria-hidden="true"></span>
                    Full Operations Log
                </a>
            </p>
        </div>
    </div>

</%block>
