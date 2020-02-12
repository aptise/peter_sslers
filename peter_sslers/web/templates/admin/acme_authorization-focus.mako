<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-authorizations">ACME Authorization</a></li>
        <li class="active">Focus [${AcmeAuthorization.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>ACME Authorization - Focus</h2>
    ${admin_partials.standard_error_display()}
</%block>


<%block name="page_header_nav">
</%block>


<%block name="content_main">
    ${admin_partials.handle_querystring_result()}
    
    <div class="row">
        <div class="col-sm-12">


            <table class="table">
                <thead>
                    <tr>
                        <th colspan="2">
                            Core Details
                        </th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <th>id</th>
                        <td>
                            <span class="label label-default">
                                ${AcmeAuthorization.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>authorization_url</th>
                        <td><code>${AcmeAuthorization.authorization_url or ''}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>timestamp_created</th>
                        <td><timestamp>${AcmeAuthorization.timestamp_created  or ''}</timestamp>
                        </td>
                    </tr>
                    <tr>
                        <th>domain</th>
                        <td>
                            % if AcmeAuthorization.domain_id:
                                <a class="label label-info" href="${admin_prefix}/domain/${AcmeAuthorization.domain_id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                Domain-${AcmeAuthorization.domain_id}</a>
                                <code>${AcmeAuthorization.domain.domain_name}</code>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>timestamp_expires</th>
                        <td><timestamp>${AcmeAuthorization.timestamp_expires  or ''}</timestamp>
                        </td>
                    </tr>
                    <tr>
                        <th>status</th>
                        <td><code>${AcmeAuthorization.status_text or ''}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>timestamp_updated</th>
                        <td><timestamp>${AcmeAuthorization.timestamp_updated  or ''}</timestamp>
                        </td>
                    </tr>
                    <tr>
                        <th>wildcard</th>
                        <td><code>${AcmeAuthorization.wildcard  or ''}</code>
                        </td>
                    </tr>
                </tbody>
                <thead>
                    <tr>
                        <th colspan="2">
                        <hr/>
                        </th>
                    </tr>
                    <tr>
                        <th colspan="2">
                            Relations Library
                        </th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <th>AcmeOrder(s)</th>
                        <td>
                            ${admin_partials.table_AcmeOrders(AcmeAuthorization.acme_orders__5, perspective="AcmeAuthorization")}
                            % if AcmeAuthorization.acme_orders__5:
                                ${admin_partials.nav_pager("%s/acme-authorization/%s/acme-orders" % (admin_prefix, AcmeAuthorization.id))}
                            % endif
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</%block>
