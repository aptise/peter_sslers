<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-accounts">AcmeAccounts</a></li>
        <li><a href="${admin_prefix}/acme-account/${AcmeAccount.id}">Focus [${AcmeAccount.id}]</a></li>
        <li class="active">X509Certificates</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>AcmeAccount - Focus | X509Certificates</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if X509Certificates:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_X509Certificates(X509Certificates, show_domains=True, show_days_to_expiry=True)}
            % else:
                No known X509Certificates.
            % endif
        </div>
    </div>
</%block>
