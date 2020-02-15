<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/domains">Domains</a></li>
        <li><a href="${admin_prefix}/domain/${Domain.id}">Focus [${Domain.id}]</a></li>
        <li class="active">AcmeOrderlessChallenges</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Domain Focus - AcmeOrderlessChallenges</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            % if AcmeOrderlessChallenges:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_AcmeOrderlessChallenges(AcmeOrderlessChallenges, perspective="Domain")}
            % else:
                No known AcmeOrderlessChallenges
            % endif
        </div>
    </div>
</%block>
