<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Acme-Dns Servers</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>acme-dns Servers</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-dns-server/new" class="btn btn-xs btn-primary">
            <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
            new
        </a>
        <a href="${admin_prefix}/acme-dns-servers.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if AcmeDnsServers:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>active?</th>
                            <th>global default?</th>
                            <th>api_url</th>
                        </tr>
                    </thead>
                    <tbody>
                    % for item in AcmeDnsServers:
                        <tr>
                            <td>
                                <a class="label label-info" href="${admin_prefix}/acme-dns-server/${item.id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeDnsServer-${item.id}</a>
                            </td>
                            <td><code>${item.is_active}</td>
                            <td><code>${item.is_global_default}</td>
                            <td><code>${item.api_url}</td>
                        </tr>
                    % endfor
                    </tbody>
                </table>
            % else:
                <em>
                    No AcmeDnsServers
                </em>
            % endif
        </div>
    </div>
</%block>
