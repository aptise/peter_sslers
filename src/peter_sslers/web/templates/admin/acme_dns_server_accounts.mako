<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Acme-Dns Server Accounts</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>acme-dns Server Accounts</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <form action="${admin_prefix}/acme-dns-server-accounts/all.csv" method="POST">
            <button class="btn btn-xs btn-primary" type="submit"  name="submit" value="submit">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                all.csv
            </button>
        </form>
        <form action="${admin_prefix}/acme-dns-server-accounts/all.json" method="POST">
            <button class="btn btn-xs btn-primary" type="submit"  name="submit" value="submit">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                all.json
            </button>
        </form>
        <a href="${admin_prefix}/acme-dns-server-accounts.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if AcmeDnsServerAccounts:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_AcmeDnsServerAccounts(AcmeDnsServerAccounts, perspective="AcmeDnsServerAccounts")}
            % else:
                <em>
                    No AcmeDnsServerAccounts
                </em>
            % endif
        </div>
    </div>
</%block>
