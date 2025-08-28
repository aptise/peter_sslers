<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/x509-certificate-trusteds">X509CertificateTrusteds</a></li>
        <li><a href="${admin_prefix}/x509-certificate-trusted/${X509CertificateTrusted.id}">Focus [${X509CertificateTrusted.id}]</a></li>
        <li class="active">X509CertificateTrustChains - ${accessor}</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>X509CertificateTrusted - Focus - X509CertificateTrustChains = ${accessor}</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if X509CertificateTrustChains:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_X509CertificateTrustChains(X509CertificateTrustChains)}
            % else:
                No known X509CertificateTrustChains.
            % endif
        </div>
    </div>
</%block>
