<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">SystemConfigurations</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>SystemConfigurations</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/system-configurations.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>

<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if SystemConfigurations:
                ${admin_partials.table_SystemConfigurations(SystemConfigurations, perspective="SystemConfigurations")}
            % else:
                <em>
                    No SystemConfigurations
                </em>
            % endif
        </div>
    </div>
</%block>
