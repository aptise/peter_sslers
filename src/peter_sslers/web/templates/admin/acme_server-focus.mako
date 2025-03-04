<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-servers">Acme Servers</a></li>
        <li class="active">Focus ${AcmeServer.id}</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Acme Server: Focus</h2>
    ${admin_partials.handle_querystring_result()}
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-server/${AcmeServer.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>

        <a href="${admin_prefix}/acme-server/${AcmeServer.id}/acme-accounts" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
            AcmeAccounts
        </a>
        <a href="${admin_prefix}/acme-server/${AcmeServer.id}/acme-server-configurations" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
            AcmeServerConfigurations
        </a>

        <a href="${admin_prefix}/acme-account/new?acme-server-id=${AcmeServer.id}" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
            New Account
        </a>

    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">

            <table class="table table-striped table-condensed">
                <tr>
                    <th>id</th>
                    <td>
                        <span class="label label-info">
                            ${AcmeServer.id}
                        </span>
                    </td>
                </tr>
                <tr>
                    <th>timestamp_created</th>
                    <td>
                        <timestamp>${AcmeServer.timestamp_created}</timestamp>
                    </td>
                </tr>
                <tr>
                    <th>name</th>
                    <td>
                        <code>${AcmeServer.name}</code>
                    </td>
                </tr>
                <tr>
                    <th>directory</th>
                    <td>
                        <code>${AcmeServer.directory}</code>
                    </td>
                </tr>
                <tr>
                    <th>directory example</th>
                    <td>
                        % if AcmeServer.directory_latest:
                            <timestamp>${AcmeServer.directory_latest.timestamp_created_isoformat}</timestamp>
                            <p>
                            <code>${AcmeServer.directory_latest.directory_pretty}</code>
                            </p>
                        % endif

                        <form action="${admin_prefix}/acme-server/${AcmeServer.id}/check-support" method="POST" style="display:inline;" id="form-check_support">
                            <input type="hidden" name="action" value="active"/>
                            <button class="btn btn-xs btn-primary" type="submit">
                                <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                Refresh
                            </button>
                        </form>
                    </td>
                </tr>
                <tr>
                    <th>profiles</th>
                    <td>
                        <code>${AcmeServer.profiles or ""}</code>
                    </td>
                </tr>
                <tr>
                    <th>server</th>
                    <td>
                        <code>${AcmeServer.server}</code>
                    </td>
                </tr>
                <tr>
                    <th>is_default</th>
                    <td>
                        <code>${AcmeServer.is_default}</code>
                    </td>
                </tr>
                <tr>
                    <th>is_supports_ari__version</th>
                    <td>
                        <code>${AcmeServer.is_supports_ari__version}</code>
                    </td>
                </tr>
                ## <tr>
                ##     <th>is_enabled</th>
                ##     <td>
                ##         <code>${AcmeServer.is_enabled}</code>
                ##     </td>
                ## </tr>
                <tr>
                    <th>protocol</th>
                    <td>
                        <code>${AcmeServer.protocol}</code>
                    </td>
                </tr>
                <tr>
                    <th>is_unlimited_pending_authz</th>
                    <td>
                        <code>${AcmeServer.is_unlimited_pending_authz}</code>
                        <p>If the server supports unlimited pending authz, automatic cleanup of pending authz will be disabled <em>even if configured</em></p>
                        
                        % if not AcmeServer.is_unlimited_pending_authz:
                            <form action="${admin_prefix}/acme-server/${AcmeServer.id}/mark" method="POST" style="display:inline;" id="form-mark">
                                <input type="hidden" name="action" value="is_unlimited_pending_authz-true"/>
                                <button class="btn btn-xs btn-info" type="submit">
                                    <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                    set
                                </button>
                            </form>
                        % else:
                            <form action="${admin_prefix}/acme-server/${AcmeServer.id}/mark" method="POST" style="display:inline;" id="form-mark">
                                <input type="hidden" name="action" value="is_unlimited_pending_authz-false"/>
                                <button class="btn btn-xs btn-danger" type="submit">
                                    <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                    unset
                                </button>
                            </form>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>server_ca_cert_bundle</th>
                    <td>
                        <code>${AcmeServer.server_ca_cert_bundle}</code>
                    </td>
                </tr>
            </table>

        </div>
    </div>
</%block>
