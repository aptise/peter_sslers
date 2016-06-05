<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Programmatic API</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Programmatic API</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            <p>
                Many endpoints handle JSON requests, however the `/api` endpoints offer some deeper logic and ONLY respond to JSON requests
            </p>
            <p>Endpoints assume the prefix: <em>${admin_prefix}</em>
            </p>
            <hr/>
            
            <h4>Refresher</h4>
            <code>curl --form "domain_names=example.com" ${admin_server}${admin_prefix}/api/domain/enable</code>
            <hr/>
            
            <h4>Endpoints</h4>
            <table class="table table-striped table-condensed">
                <thead>
                    <tr>
                        <th>Endpoint</th>
                        <th>About</th>
                        <th>POST</th>
                        <th>GET</th>
                        <th>Args</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><code>/api/domain/enable</code></td>
                        <td>Enables domain(s) for management.
                            Currently this proxies calls to `/admin/queue-domains`
                            </td>
                        <td><span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span></td>
                        <td></td>
                        <td>
                            <ul>
                                <li>
                                    <code>domain_names</code>
                                    <em>A comma (,) separated list of domain names
                                    </em>
                                </li>
                            </ul>
                        </td>
                    </tr>
                    <tr>
                        <td><code>/api/domain/disable</code></td>
                        <td>Disables domain(s) for management
                            </td>
                        <td><span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span></td>
                        <td></td>
                        <td>
                            <ul>
                                <li>
                                    <code>domain_names</code>
                                    <em>A comma (,) separated list of domain names
                                    </em>
                                </li>
                            </ul>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

</%block>
