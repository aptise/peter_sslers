<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Root Stores</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Root Stores</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/root-stores.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>

<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            <p>This feature is experiemental and under development.</p>
            <p>The `cert_utils` library tracks Root Store compatibility for CAs like <a href="https://letsencrypt.org/docs/certificate-compatibility/">ISRG/LetsEncrypt</a>. The information is standardized in that library, and updated into this database to be cross-referenced against active certs.</p>
            <p>The goal of this feature is to eventually automate root selection when configuring servers or obtaining new certificates.</p>
            % if RootStores:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_RootStores(RootStores)}
            % else:
                <em>
                    No Root Stores
                </em>
            % endif
        </div>
        <div class="col-sm-3">
        </div>
    </div>
</%block>
