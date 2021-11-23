<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/operations">Operations</a></li>
        <li class="active">Redis</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Redis Operations</h2>
    ${admin_partials.handle_querystring_result()}
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            % if OperationsEvents:
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
                        % for event in OperationsEvents:
                            <tr class="${'success' if event_id == str(event.id) else ''}">
                                <td><span class="label label-default">${event.id}</span></td>
                                <td><timestamp>${event.timestamp_event}</timestamp></td>
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
                    The prime style is: <em>${request.registry.settings["app_settings"]['redis.prime_style']}</em>
                </p>
                <p>
                    The database is: <em>${request.registry.settings["app_settings"]['redis.url']}</em>
                </p>
            </div>
            <ul class="nav nav-pills nav-stacked">
                <li class="active">
                    <a  href="${admin_prefix}/operations/redis"
                    >
                        <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                        Redis Operations Log
                    </a>
                </li>
                <li>
                    <a  href="${admin_prefix}/api/redis/prime"
                    >
                        <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                        Prime Redis Cache
                    </a>
                </li>
                <li>
                    <a  href="${admin_prefix}/api/redis/prime.json"
                    >
                        <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                        Prime Redis Cache - JSON
                    </a>
                </li>
                <li>
                    <a  href="${admin_prefix}/operations/log"
                    >
                        <span class="glyphicon glyphicon-list-alt" aria-hidden="true"></span>
                        Full Operations Log
                    </a>
                </li>
            </ul>
        </div>
    </div>

</%block>
