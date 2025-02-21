<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">ACME Authorization Potentials</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>ACME Authorization Potentials</h2>
    <p>These are local objects used for blocking and throttling. Once an AcmeAuthorization is synced to the server they are deleted in favor of the AcmeAuthorization and AcmeChallenge objects.</p>
</%block>


<%block name="page_header_nav">
    <ul class="nav nav-pills nav-stacked">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-authz-potentials.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if AcmeAuthorizationPotentials:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_AcmeAuthorizationPotentials(AcmeAuthorizationPotentials, perspective="AcmeAuthorizationPotentials")}
            % else:
                <em>
                    No ACME AcmeAuthorizationPotentials
                </em>
            % endif
        </div>
    </div>
</%block>
