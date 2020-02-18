<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-orders">AcmeOrder</a></li>
        <li><a href="${admin_prefix}/acme-order/${AcmeOrder.id}">Focus [${AcmeOrder.id}</a></li>
        <li class="active">Events</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>ACME Order - Focus - Acme Event Logs</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">

            % if AcmeEventLogs:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_AcmeEventLogs(AcmeEventLogs, perspective="AcmeOrder")}
            % else:
                No AcmeEventLogs
            % endif

        </div>
    </div>
</%block>
