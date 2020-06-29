<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Domain Autocerts</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Domain Autocerts</h2>
    History of Autocert
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a  class="btn btn-xs btn-info"
            href="${admin_prefix}/domain-autocerts.json"
        >
            <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
            .json</a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if DomainAutocerts:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_DomainAutocerts(DomainAutocerts, "DomainAutocert")}
            % else:
                <em>
                    No DomainAutocerts
                </em>
            % endif
        </div>
    </div>
</%block>
