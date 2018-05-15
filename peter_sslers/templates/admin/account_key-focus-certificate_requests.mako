<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li>Peter SSLers</li>
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/account-keys">Account Keys</a></li>
        <li><a href="${admin_prefix}/account-key/${SslLetsEncryptAccountKey.id}">Focus [${SslLetsEncryptAccountKey.id}]</a></li>
        <li class="active">Certificate Requests</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Account Key - Focus | Certificate Requests</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if SslCertificateRequests:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_certificate_requests__list(SslCertificateRequests, show_domains=True)}
            % else:
                No known certificate requests.
            % endif
        </div>
    </div>
</%block>
