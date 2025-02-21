<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Acme Servers</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Acme Servers</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-servers.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">

            <p>
                The following servers are known to this installation.
            </p>
            <p>
                New servers can be added with the `register_acme_servers` script.
            </p>

            % if AcmeServers:
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>name</th>
                            <th>server</th>
                            <th>url</th>
                        </tr>
                    </thead>
                    <tbody>
                    % for provider_data in AcmeServers:
                        <tr>
                            <td>
                                <a class="label label-info" href="${admin_prefix}/acme-server/${provider_data.id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeServer-${provider_data.id}</a>
                            </td>
                            <td><code>${provider_data.name}</code></td>
                            <td><code>${provider_data.server}</code></td>
                            <td><code>${provider_data.url}</code></td>
                        </tr>
                    % endfor
                    </tbody>
                </table>
            % endif
        </div>
    </div>
</%block>
