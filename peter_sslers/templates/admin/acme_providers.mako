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
        <a href="${admin_prefix}/acme-providers.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>    
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if AcmeProviders:
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>is default</th>
                            <th>id</th>
                            <th>name</th>
                            <th>endpoint</th>
                        </tr>
                    </thead>
                    <tbody>
                    % for provider_data in AcmeProviders:
                        <tr>
                            <td>
                                % if provider_data['is_default']:
                                    <span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span>
                                % endif
                            </td>
                            <td><code>${provider_data['id']}</code></td>
                            <td><code>${provider_data['name']}</code></td>
                            <td><code>${provider_data['endpoint']}</code></td>
                        </tr>
                    % endfor
                    </tbody>
                </table>
            % endif
        </div>
    </div>
</%block>
