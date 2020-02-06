<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">ACME Orders</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>ACME Orders</h2>
    <p>${request.text_library.info_AcmeOrders[1]}</p>
</%block>


<%block name="page_header_nav">
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if SslAcmeOrders:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>timestamp_created</th>
                            <th>timestamp_finalized</th>
                        </tr>
                    </thead>
                    <tbody>
                    % for order in SslAcmeOrders:
                        <tr>
                            <td><a class="label label-info" href="${admin_prefix}/acme-order/${order.id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ${order.id}</a></td>
                            <td><timestamp>${key.timestamp_created}</timestamp></td>
                            <td><timestamp>${key.timestamp_finalized}</timestamp></td>
                        </tr>
                    % endfor
                    </tbody>
                </table>
            % else:
                <em>
                    No ACME Orders
                </em>
            % endif
        </div>
    </div>
</%block>
