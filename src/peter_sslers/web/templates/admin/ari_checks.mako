<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">ARIChecks</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>ARIChecks</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/ari-checks.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if AriChecks:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_AriChecks(AriChecks, perspective='AriChecks')}
            % else:
                <em>
                    No AriChecks
                </em>
            % endif
        </div>
    </div>
</%block>
