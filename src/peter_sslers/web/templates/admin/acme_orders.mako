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
    <p>An ACME order is essentially a "Certificate Signing Request".</p>
</%block>


<%block name="page_header_nav">
    <ul class="nav nav-pills nav-stacked">
      <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="${admin_prefix}/acme-orders/all">All AcmeOrders</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'active' else ''}"><a href="${admin_prefix}/acme-orders/active">Active AcmeOrders</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'finished' else ''}"><a href="${admin_prefix}/acme-orders/finished">Finished AcmeOrders</a></li>
    </ul>

    <p class="pull-right">
        <a  href="${admin_prefix}/acme-order/new/freeform"
            title="ACME Order - new freeform"
            class="btn btn-xs btn-primary"
        >
        <span class="glyphicon glyphicon-wrench" aria-hidden="true"></span>
        New ACME Order: Automated</a>

        <a href="${admin_prefix}/acme-orders/${sidenav_option}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    
        % if sidenav_option == 'active':
            <p></p>
            <p></p>
            <form action="${admin_prefix}/acme-orders/active/acme-server/sync" id="acme_orders-acme_server_sync" method="POST" style="display:inline-block;">
                <button class="btn btn-xs btn-primary"
                    <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                    Sync Active Orders
                </button>
            </form>
        % endif

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
