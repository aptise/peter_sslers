<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/uniquely-challenged-fqdn-sets">Uniquely Challenged FQDN Sets</a></li>
        <li><a href="${admin_prefix}/uniquely-challenged-fqdn-set/${UniquelyChallengedFQDNSet.id}">Focus [${UniquelyChallengedFQDNSet.id}]</a></li>
        <li class="active">ACME Orders</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Uniquely Challenged FQDN Set Focus - ACME Orders</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if AcmeOrders:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_AcmeOrders(AcmeOrders, perspective="UniquelyChallengedFQDNSet")}
            % else:
                No known AcmeOrders.
            % endif
        </div>
    </div>
</%block>
