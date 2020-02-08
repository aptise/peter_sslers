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
            % if AcmeOrders:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>timestamp_created</th>
                            <th>status</th>
                            <th>timestamp_finalized</th>
                        </tr>
                    </thead>
                    <tbody>
                    % for acme_order in AcmeOrders:
                        <tr>
                            <td><a class="label label-info" href="${admin_prefix}/acme-order/${acme_order.id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ${acme_order.id}</a></td>
                            <td><timestamp>${acme_order.timestamp_created or ''}</timestamp></td>
                            <td><code>${acme_order.status or ''}</code></td>
                            <td><timestamp>${acme_order.timestamp_finalized or ''}</timestamp></td>
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
