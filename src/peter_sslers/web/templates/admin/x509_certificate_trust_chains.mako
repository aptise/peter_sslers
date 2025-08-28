<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">X509CertificateTrustChains</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>X509CertificateTrustChains</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a  href="${admin_prefix}/certificate-ca-chain/upload-chain"
            title="X509CertificateTrustChain - Upload"
            class="btn btn-xs btn-primary"
        >
            <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
            Upload: X509CertificateTrustChain</a>
        <a href="${admin_prefix}/x509-certificate-trust-chain.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if X509CertificateTrustChains:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>chain_pem_md5</th>
                            <th>display_name</th>
                        </tr>
                    </thead>
                    % for chain in X509CertificateTrustChains:
                        <tr>
                            <td><a class="label label-info" href="${admin_prefix}/certificate-ca-chain/${chain.id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                X509CertificateTrustChain-${chain.id}</a>
                            </td>
                            <td><code>${chain.chain_pem_md5}</code></td>
                            <td><code>${chain.display_name}</code></td>
                        </tr>
                    % endfor
                </table>
            % else:
                <em>
                    No Certificate Authority Chains
                </em>
            % endif
        </div>
    </div>
</%block>
