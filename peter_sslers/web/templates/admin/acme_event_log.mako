<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Acme Event Logs</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Acme Event Log</h2>
</%block>



<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if AcmeEventLogs:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_AcmeEventLogs(AcmeEventLogs, perspective=None)}
            % else:
                <em>
                    No Logs
                </em>
            % endif
        </div>
    </div>
</%block>
