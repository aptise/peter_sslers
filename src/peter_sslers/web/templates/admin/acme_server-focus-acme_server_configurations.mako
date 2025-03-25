<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-servers">Acme Servers</a></li>
        <li><a href="${admin_prefix}/acme-server/${AcmeServer.id}">Focus ${AcmeServer.id}</a></li>
        <li class="active">AcmeServerConfigurations</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Acme Server: Focus - AcmeServerConfigurations</h2>
    ${admin_partials.handle_querystring_result()}
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if AcmeServerConfigurations:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped table-condensed">
                    <thead>
                        <tr>
                            <th>is_active</th>
                            <th>id</th>
                            <th>timestamp_created</th>
                            <th>directory</th>
                        </tr>
                    </thead>
                    <tbody>
                        % for item in AcmeServerConfigurations:
                            <tr>
                                <td>
                                    % if item.is_active:
                                        <span class="label label-success">
                                            <span class="glyphicon glyphicon-check" aria-hidden="true"></span>
                                        </span>
                                    % endif
                                </td>
                                <td>
                                    <span class="label label-default">
                                        ${item.id}
                                    </span>
                                </td>
                                <td><timestamp>${item.timestamp_created}</timestamp></td>
                                <td><code>${item.directory_pretty}</code></td>
                            </tr>
                        % endfor
                    </tbody>
                </table>
            % else:
                No known AcmeServerConfigurations.
            % endif
        </div>
    </div>
</%block>

