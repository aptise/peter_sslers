<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Uniquely Challenged FQDN Sets</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Uniquely Challenged FQDN Sets</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/uniquely-challenged-fqdn-sets.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
        <a href="${admin_prefix}/uniquely-challenged-fqdn-set/new" class="btn btn-xs btn-primary">
            <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
            new
        </a>
    </p>
</%block>

<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            % if UniquelyChallengedFQDNSets:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_UniquelyChallengedFQDNSets(UniquelyChallengedFQDNSets, perspective="UniquelyChallengedFQDNSet")}
            % else:
                <em>
                    No UniquelyChallengedFQDNSets
                </em>
            % endif
        </div>
        <div class="col-sm-3">
        </div>
    </div>
</%block>
