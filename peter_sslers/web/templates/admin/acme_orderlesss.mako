<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">AcmeOrderless</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>AcmeOrderless</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        % if request.registry.settings["app_settings"]['enable_acme_flow']:
            <a  href="${admin_prefix}/acme-orderless/new"
                title="ACME Orderless"
                class="btn btn-xs btn-primary"
            >
            <span class="glyphicon glyphicon-wrench" aria-hidden="true"></span>
            New: AcmeOrderless Flow</a>
        % endif
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if AcmeOrderlesss:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_AcmeOrderlesss(AcmeOrderlesss, perspective="AcmeOrderlesss")}
            % else:
                <em>
                    No AcmeOrderlesss
                </em>
            % endif
        </div>
    </div>
</%block>
