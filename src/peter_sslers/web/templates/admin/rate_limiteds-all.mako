<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Rate Limiteds: All</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Rate Limiteds: All</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/rate-limiteds/all.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            ${admin_partials.handle_querystring_result()}
            % if RateLimiteds:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_RateLimiteds(RateLimiteds, perspective="RateLimited")}
            % else:
                <em>
                    No RateLimiteds
                </em>
            % endif
        </div>
    </div>
</%block>
