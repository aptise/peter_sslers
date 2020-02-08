<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">ACME Authorizations</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>ACME Authorizations</h2>
</%block>


<%block name="page_header_nav">
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if AcmeAuthorizations:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>domain</th>
                            <th>timestamp_created</th>
                            <th>status</th>
                            <th>timestamp_expires</th>
                            <th>timestamp_updated</th>
                        </tr>
                    </thead>
                    <tbody>
                    % for acme_authorization in AcmeAuthorizations:
                        <tr>
                            <td><a class="label label-info" href="${admin_prefix}/acme-authorization/${acme_authorization.id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeAuthorization-${acme_authorization.id}</a></td>
                            <td><a class="label label-info" href="${admin_prefix}/domain/${acme_authorization.domain_id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                Domain-${acme_authorization.domain_id}</a></td>
                            <td><timestamp>${acme_authorization.timestamp_created or ''}</timestamp></td>
                            <td><code>${acme_authorization.status or ''}</code></td>
                            <td><timestamp>${acme_authorization.timestamp_expires or ''}</timestamp></td>
                            <td><timestamp>${acme_authorization.timestamp_updated or ''}</timestamp></td>
                        </tr>
                    % endfor
                    </tbody>
                </table>
            % else:
                <em>
                    No ACME Authorizations
                </em>
            % endif
        </div>
    </div>
</%block>
