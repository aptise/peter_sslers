<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/private-keys">Private Keys</a></li>
        <li><a href="${admin_prefix}/private-key/${LetsencryptPrivateKey.id}">Focus [${LetsencryptPrivateKey.id}]</a></li>
        <li class="active">Certificates</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Private Key - Focus | Certificates</h2>
</%block>


<%block name="content_main">

    % if LetsencryptServerCertificates:
        ${admin_partials.nav_pagination(pager)}
        ${admin_partials.table_certificates__list(LetsencryptServerCertificates, show_domains=True, show_expiring_days=True)}
    % else:
        No known certificates.
    % endif

</%block>
