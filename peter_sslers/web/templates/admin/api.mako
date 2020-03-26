<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">API</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>API</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <p>
                Many endpoints handle JSON requests, however the `/api` endpoints offer some deeper logic and ONLY respond to JSON requests
            </p>
            <p>Endpoints assume the prefix: <em>${admin_prefix}</em>
            </p>
            <hr/>

            <h4>Refresher</h4>
            <p>If not using scripts to access the API, you can use `curl`</p>
            <code>curl --form "domain_names=example.com" ${request.admin_url}/api/domain/enable</code>
            <hr/>

            <h4>Dedicated API Endpoints</h4>
            <table class="table table-striped table-condensed">
                <thead>
                    <tr>
                        <th>Endpoint</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    % for (enp_name, ep) in sorted(api_endpoints.items()):
                        <tr>
                            <td><code>${ep['endpoint']}</code></td>
                            <td>${ep['about']}</td>
                        </tr>
                        <tr>
                            <td></td>
                            <td>
                                <ul class="list">
                                    <li>
                                        <b>GET:</b>
                                        % if ep['GET'] is True:
                                            <span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span>
                                        % elif ep['GET'] is None:
                                            <span class="label label-warning"><span class="glyphicon glyphicon-exclamation-sign" aria-hidden="true"></span></span>
                                        % endif
                                    </li>
                                    <li>
                                        <b>POST:</b>
                                        % if ep['POST']:
                                            <span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span>
                                        % endif
                                        <br/>
                                    </li>
                                    % if ep['args']:
                                        <li>
                                            <b>Args:</b>
                                                <ul>
                                                % for (k, v) in ep['args'].items():
                                                    <li>
                                                        <code>${k}</code>
                                                        <em>${v}</em>
                                                    </li>
                                                % endfor
                                            </ul>
                                        </li>
                                    % endif
                                </ul>
                                % if ep.get('example') or ep.get('examples'):
                                    <b>Examples:</b>
                                    <br/>
                                    % if ep.get('example'):
                                        <code>${ep.get('example').replace('{ADMIN_PREFIX}', request.admin_url)}</code>
                                    % endif
                                    % if ep.get('examples'):
                                        % for idx, example in enumerate(ep.get('examples')):
                                            % if idx >= 1:
                                                <hr/>
                                            % endif
                                            <code>${example.replace('{ADMIN_PREFIX}', request.admin_url)}</code>
                                        % endfor
                                    % endif
                                % endif
                                % if ep.get('GET-button'):
                                    <a href="${request.admin_url}${ep['endpoint']}"
                                       target="_blank"
                                       class="btn btn-xs btn-info"
                                    >
                                        <i class="glyphicon glyphicon-link"></i>
                                        GET
                                    </a>                                
                                % endif
                                % if ep.get('POST-button'):
                                    <form action="${request.admin_url}${ep['endpoint']}" method="POST">
                                        <button class="btn btn-xs btn-info">
                                            <i class="glyphicon glyphicon-link"></i>
                                            POST
                                        </button>
                                    </form>
                                % endif
                            </td>
                        </tr>
                    % endfor
                </tbody>
            </table>

            <h4>JSON Capable Endpoints</h4>
            <%
                sections = {}
                for ep in json_capable.values():
                    if ep["section"] not in sections:
                        sections[ep["section"]] = []
                    sections[ep["section"]].append(ep)
            %>
            
            <ul>
                % for section in sorted(sections.keys()):            
                    <li><a href="#${section}">${section}</a></li>
                % endfor
            </ul>
            
            <table class="table table-striped table-condensed">
                <thead>
                    <tr>
                        <th>Endpoint</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    % for section in sorted(sections.keys()):
                        <tr>
                            <th colspan="5"><a name="${section}"></a>${section}</th>
                        </tr>
                        % for ep in sections[section]:
                            <tr>
                                <td><code>${ep['endpoint']}</code></td>
                                <td>${ep['about']}</td>
                            </tr>
                            <tr>
                                <td></td>
                                <td>
                                    <ul class="list">
                                        <li>
                                            <b>GET:</b>
                                            % if ep['GET'] is True:
                                                <span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span>
                                            % elif ep['GET'] is None:
                                                <span class="label label-warning"><span class="glyphicon glyphicon-exclamation-sign" aria-hidden="true"></span></span>
                                            % endif
                                        </li>
                                        <li>
                                            <b>Post:</b>
                                            % if ep['POST']:
                                                <span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span>
                                            % endif
                                        </li>
                                        % if ep['args']:
                                            <li>
                                                <b>Args:</b>
                                                ${ep['args']}
                                            </li>
                                        % endif
                                        % if ep.get('GET-SELF-DOCUMENTING'):
                                            <li><em>This route is self-documenting on GET requests</em></li>
                                        % endif
                                    </ul>                                        
                                    % if ep.get('example') or ep.get('examples'):
                                        <b>Examples:</b>
                                        <br/>
                                        % if ep.get('example'):
                                            <code>${ep.get('example').replace('{ADMIN_PREFIX}', request.admin_url)}</code>
                                        % endif
                                        % if ep.get('examples'):
                                            % for idx, example in enumerate(ep.get('examples')):
                                                % if idx >= 1:
                                                    <hr/>
                                                % endif
                                                <code>${example.replace('{ADMIN_PREFIX}', request.admin_url)}</code>
                                            % endfor
                                        % endif
                                    % endif
                                </td>
                            </tr>
                        % endfor
                    % endfor
                </tbody>
            </table>
        </div>
    </div>

</%block>
