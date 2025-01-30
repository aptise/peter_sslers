<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/operations">Operations</a></li>
        <li class="active">Nginx</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Nginx Operations</h2>
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
                            <th>event type</th>
                            <th>payload</th>
                        </tr>
                    </thead>
                    <tbody>
                        % for event in OperationsEvents:
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
        <div class="col-sm-3">
            <div class="alert alert-info">
                <p>
                    Nginx is enabled for this server.
                </p>
                <p>
                    Nginx integration is provided by the `<a href="https://github.com/aptise/peter_sslers-lua-resty" target="_blank">lua-resty-peter_sslers</a>` package available via the OpenResty OPM.
                </p>
            </div>
            <table class="table table-striped table-condensed">
                <tr>
                    <th>nginx.servers_pool</th>
                    <td>
                        % if request.registry.settings["app_settings"]['nginx.servers_pool']:
                            <ul>
                                % for i in request.registry.settings["app_settings"]['nginx.servers_pool']:
                                    <li>${i}</li>
                                % endfor
                            </ul>
                        % endif
                </tr>
                <tr>
                    <th>nginx.userpass</th>
                    <td>
                        % if request.registry.settings["app_settings"]['nginx.userpass']:
                            <code>${request.registry.settings["app_settings"]['nginx.userpass']}</code>
                        % else:
                            <code></code>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>nginx.reset_path</th>
                    <td><code>${request.registry.settings["app_settings"]['nginx.reset_path']}</code></td>
                </tr>
                <tr>
                    <th>nginx.status_path</th>
                    <td><code>${request.registry.settings["app_settings"]['nginx.status_path']}</code></td>
                </tr>
                <tr>
                    <th>nginx.ca_bundle_pem</th>
                    <td>
                        % if request.registry.settings["app_settings"]['nginx.ca_bundle_pem']:
                            <code>${request.registry.settings["app_settings"]['nginx.ca_bundle_pem']}</code>
                        % else
                            <code></code>                            
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>redis enabled?</th>
                    <td>${'Yes' if request.registry.settings["app_settings"]['enable_redis'] else 'No'}</td>
                </tr>
                <tr>
                    <th>redis prime style</th>
                    <td>
                        % if 'redis.prime_style' in request.registry.settings["app_settings"]:
                            ${request.registry.settings["app_settings"]['redis.prime_style']}
                        % endif
                    </td>
                </tr>
            </table>
            <hr/>

            <p>
                <span class="btn btn-group">
                    <form action="${admin_prefix}/api/nginx/cache-flush" method="POST">
                        <button class="btn btn-xs btn-primary" type="submit"  name="submit" value="submit">
                            <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                            Flush Nginx Cache
                        </button>
                    </form>
                    <form action="${admin_prefix}/api/nginx/cache-flush.json" method="POST">
                        <button class="btn btn-xs btn-primary" type="submit"  name="submit" value="submit">
                            <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                            JSON
                        </button>
                    </form>
                </span>
                <br/>
                <em>
                This will clear the entire cache.  if you just want to clear a single domain, use the link off the domain interface.
                </em>
            </p>
            <hr/>
            <ul class="nav nav-pills nav-stacked">
                <li class="active">
                    <a  href="${admin_prefix}/operations/nginx"
                    >
                        <span class="glyphicon glyphicon-list-alt" aria-hidden="true"></span>
                        Nginx Operations Log
                    </a>
                </li>
                <li>
                    <form action="${admin_prefix}/api/nginx/status.json" method="POST">
                        <button class="btn btn-xs btn-primary" type="submit"  name="submit" value="submit">
                            <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                            Nginx Status (JSON)
                        </button>
                    </form>
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
