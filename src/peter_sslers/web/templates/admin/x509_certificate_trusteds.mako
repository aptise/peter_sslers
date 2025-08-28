<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">X509CertificateTrusteds</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>X509CertificateTrusteds</h2>
    <p>
        X509CertificateTrusteds can be initialized and updated by probing the LetsEncrypt service;
        see <a class="btn btn-xs btn-warning" href="${admin_prefix}/api">Api Endpoints</a>.
    
    </p>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a  href="${admin_prefix}/x509-certificate-trust-chain"
            title="X509CertificateTrustChains"
            class="btn btn-xs btn-info"
        >
            <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
            X509CertificateTrustChains</a>
        <a  href="${admin_prefix}/x509-certificate-trusted/upload-cert"
            title="X509CertificateTrusted - Upload Cert"
            class="btn btn-xs btn-primary"
        >
            <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
            Upload: X509CertificateTrusted</a>
        <a  href="${admin_prefix}/x509-certificate-trust-preference-policys"
            title="X509CertificateTrusteds - Preference Policys"
            class="btn btn-xs btn-info"
        >
            <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
            List: Preferred</a>
        <a href="${admin_prefix}/x509-certificate-trusteds.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json</a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if X509CertificateTrusteds:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>count active certificates (signed)</th>
                            <th>issuer</th>
                            <th>subject</th>
                            <th>name</th>
                            <th>timestamp_created</th>
                            <th>fingerprint_sha1</th>
                            <th>cert_pem_md5</th>
                        </tr>
                    </thead>
                    % for cert in X509CertificateTrusteds:
                        <tr>
                            <td><a class="label label-info" href="${admin_prefix}/x509-certificate-trusted/${cert.id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                X509CertificateTrusted-${cert.id}</a>
                            </td>
                            <td><span class="badge">${cert.count_active_certificates or ''}</span></td>
                            <td><code>${cert.cert_subject}</code></td>
                            <td><code>${cert.cert_issuer}</code></td>
                            <td>${cert.display_name or ''}</td>
                            <td><timestamp>${cert.timestamp_created}</timestamp></td>
                            <td><code>${cert.fingerprint_sha1_preview|n}</code></td>
                            <td><code>${cert.cert_pem_md5}</code></td>
                        </tr>
                    % endfor
                </table>
            % else:
                <em>
                    No Certificate Authority Certificates
                </em>
            % endif
        </div>
    </div>
</%block>
