<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Private Keys</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Private Keys</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a  href="${admin_prefix}/private-key/upload"
            title="Private Key - Upload"
            class="btn btn-xs btn-primary"
        >
            <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
            Upload: Private Key
        </a>

        <a  href="${admin_prefix}/private-key/new"
            title="New"
            class="btn btn-xs btn-primary"
        >
            <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
            New Private Key
        </a>

        <a href="${admin_prefix}/private-keys.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if PrivateKeys:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_PrivateKeys(PrivateKeys, perspective="PrivateKeys")}
            % else:
                <em>
                    No PrivateKeys
                </em>
            % endif
        </div>
    </div>
</%block>
