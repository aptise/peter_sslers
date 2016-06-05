<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/operations">Operations</a></li>
        <li class="active">Nginx</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Nginx Operations</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-6">
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
                            <th>event type</th>
                            <th>payload</th>
                        </tr>
                    </thead>
                    <tbody>
                        % for event in SslOperationsEvents:
                            <tr class="${'success' if event_id == str(event.id) else ''}">
                                <td><span class="label label-default">${event.id}</span></td>
                                <td><timestamp>${event.timestamp_event}</timestamp></td>
                                <td><span class="label label-default">${event.event_type_text}</span></td>
                                <td>
                                    % if event.event_type_text == 'operations__nginx_cache_expire':
                                        <code class="payload">${event.event_payload_json}</code>
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
        <div class="col-sm-6">
            <div class="alert alert-info">
                <p>
                    Nginx is enabled for this server.
                </p>
            </div>
            <table class="table table-striped table-condensed">
                <tr>
                    <th>nginx.reset_servers</th>
                    <td>
                        % if request.registry.settings['nginx.reset_servers']:
                            <ul>
                                % for i in request.registry.settings['nginx.reset_servers']:
                                    <li>${i}</li>
                                % endfor
                            </ul>
                        % endif
                </tr>
                <tr>
                    <th>nginx.reset_path</th>
                    <td><code>${request.registry.settings['nginx.reset_path']}</code></td>
                </tr>
                <tr>
                    <th>redis enabled?</th>
                    <td>${'Yes' if request.registry.settings['enable_redis'] else 'No'}</td>
                </tr>
                <tr>
                    <th>redis prime style</th>
                    <td>
                        % if 'redis.prime_style' in request.registry.settings:
                            ${request.registry.settings['redis.prime_style']}
                        % endif
                    </td>
                </tr>
            </table>
            <hr/>

            <p>
                <a  href="${admin_prefix}/operations/nginx/cache-flush"
                    class="label label-primary"
                >
                    <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                    Flush nginx Cache
                </a>
                <br/>
                <em>
                This will clear the entire cache.  if you just want to clear a single domain, use the link off the domain interface.
                </em>
            </p>
            <hr/>

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
