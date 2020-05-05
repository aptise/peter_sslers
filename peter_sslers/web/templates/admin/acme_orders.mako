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
    <%
        active_only = True if request.params.get("status") == 'active' else False
        sidenav_option = 'active' if active_only else 'all'
    %>
    <ul class="nav nav-pills nav-stacked">
      <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="${admin_prefix}/acme-orders">All AcmeOrders</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'active' else ''}"><a href="${admin_prefix}/acme-orders?status=active">Active AcmeOrders</a></li>
    </ul>

    <p class="pull-right">
        <a  href="${admin_prefix}/acme-order/new/automated"
            title="${request.text_library.info_AcmeOrder_new_Automated[0]}"
            class="btn btn-xs btn-primary"
        >
        <span class="glyphicon glyphicon-wrench" aria-hidden="true"></span>
        New ACME Order: Automated</a>

        <a href="${admin_prefix}/acme-orders.json${'?status=active' if sidenav_option == 'pending' else ''}" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            ${admin_partials.handle_querystring_result()}

            % if AcmeOrders:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_AcmeOrders(AcmeOrders, perspective="AcmeOrders")}
            % else:
                <em>
                    No ACME Orders
                </em>
            % endif
        </div>
    </div>
</%block>
