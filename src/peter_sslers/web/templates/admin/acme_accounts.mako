<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">AcmeAccounts</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>AcmeAccounts</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a  href="${admin_prefix}/acme-account/upload"
            title="If you need to upload a LetEncrypt AccountKey"
            class="btn btn-xs btn-primary"
        >
        <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
        Upload: New</a>

        <a  href="${admin_prefix}/acme-account/new"
            title="New"
            class="btn btn-xs btn-primary"
        >
        <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
        New Acme Account</a>
        <a href="${admin_prefix}/acme-accounts.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>

    % if pager._current == 1:
        <table class="table table-condensed">
            <tr>
                <th>Global SystemConfiguration</th>
                <td>
                    <a class="label label-info" href="${admin_prefix}/system-configuration/${SystemConfiguration_global.slug}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        SystemConfiguration-${SystemConfiguration_global.slug}</a>
                </td>
            </tr>
            <tr>
                <th>Default AcmeAccount</th>
                <td>
                    % if SystemConfiguration_global.acme_account__primary:
                        <a class="label label-info" href="${admin_prefix}/acme-account/${SystemConfiguration_global.acme_account_id__primary}">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            AcmeAccount-${SystemConfiguration_global.acme_account_id__primary}</a>
                    % else:
                        <span class="label label-warning">
                            <span class="glyphicon glyphicon-warning-sign" aria-hidden="true"></span>
                            Please Configure
                        </span>
                    % endif            
                </td>
            </tr>
            <tr>
                <th>Backup AcmeAccount</th>
                <td>
                    % if SystemConfiguration_global.acme_account_id__backup:
                        <a class="label label-info" href="${admin_prefix}/acme-account/${SystemConfiguration_global.acme_account_id__backup}">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            AcmeAccount-${SystemConfiguration_global.acme_account_id__backup}</a>
                    % else:
                        <span class="label label-warning">
                            <span class="glyphicon glyphicon-warning-sign" aria-hidden="true"></span>
                            Please Configure
                        </span>
                    % endif            
                </td>
            </tr>
        </table>
    % endif
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if AcmeAccounts:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_AcmeAccounts(AcmeAccounts, perspective="AcmeAccounts")}
            % else:
                <em>
                    No AcmeAccounts
                </em>
            % endif
        </div>
    </div>
</%block>
