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
                If a provider is not enabled, it can not be used to Authenticate or Create new accounts.
            </p>
            <p>
                Only the default provider can be used to set a default AcmeAccount. Changing the provider requires a restart.
            </p>
            
            <p>
                The Default AcmeServer is specified in the application's active environment file.
                Additional AcmeServers can be enabled via the environment file as well.
                AcmeServers can be disabled with a console script that is distributed with this application.
            </p>
        
            % if AcmeServers:
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>is default</th>
                            <th>id</th>
                            <th>name</th>
                            <th>enabled?</th>
                            <th>server</th>
                            <th>ARI?</th>
                            <th>url</th>
                        </tr>
                    </thead>
                    <tbody>
                    % for provider_data in AcmeServers:
                        <tr>
                            <td>
                                % if provider_data.is_default:
                                    <span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span>
                                % endif
                            </td>
                            <td>
                                <a class="label label-info" href="${admin_prefix}/acme-server/${provider_data.id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeServer-${provider_data.id}</a>
                            </td>
                            <td><code>${provider_data.name}</code></td>
                            <td><code>${"True" if provider_data.is_enabled else "False"}</code></td>
                            <td><code>${provider_data.server}</code></td>
                            <td><code>${provider_data.is_supports_ari__version or ''}</code></td>
                            <td><code>${provider_data.url}</code></td>
                        </tr>
                    % endfor
                    </tbody>
                </table>
            % endif
        </div>
    </div>
</%block>
