<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/unique-fqdn-sets">Unique FQDN Sets</a></li>
        <li><a href="${admin_prefix}/unique-fqdn-set/${UniqueFQDNSet.id}">Focus [${UniqueFQDNSet.id}]</a></li>
        <li class="active">Uniquely Challenged FQDN Sets</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Unique FQDN Set Focus - Uniquely Challenged FQDN Sets</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if UniquelyChallengedFQDNSets:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_UniquelyChallengedFQDNSets(UniquelyChallengedFQDNSets, perspective="UniqueFQDNSet")}
            % else:
                No known UniquelyChallengedFQDNSets.
            % endif
        </div>
    </div>
</%block>
