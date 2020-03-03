<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/private-keys">Private Keys</a></li>
        <li><a href="${admin_prefix}/private-key/${PrivateKey.id}">Focus [${PrivateKey.id}]</a></li>
        <li class="active">ServerCertificates</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Private Key - Focus | ServerCertificates</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if ServerCertificates:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_ServerCertificates(ServerCertificates, show_domains=True, show_expiring_days=True)}
            % else:
                No known certificates.
            % endif
        </div>
    </div>
</%block>