<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Acme Providers</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Acme Providers</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-account-providers.json" class="btn btn-xs btn-info">
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
                Only the default provider can be used to set a default AcmeAccountKey. Changing the provider requires a restart.
            </p>
        
            % if AcmeAccountProviders:
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>is default</th>
                            <th>id</th>
                            <th>name</th>
                            <th>enabled?</th>
                            <th>server</th>
                            <th>url</th>
                        </tr>
                    </thead>
                    <tbody>
                    % for provider_data in AcmeAccountProviders:
                        <tr>
                            <td>
                                % if provider_data.is_default:
                                    <span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span>
                                % endif
                            </td>
                            <td><code>${provider_data.id}</code></td>
                            <td><code>${provider_data.name}</code></td>
                            <td><code>${"True" if provider_data.is_enabled else "False"}</code></td>
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
