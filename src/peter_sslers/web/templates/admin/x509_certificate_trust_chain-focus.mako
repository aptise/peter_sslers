<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/x509-certificate-trust-chain">X509CertificateTrustChains</a></li>
        <li class="active">Focus [${X509CertificateTrustChain.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>X509CertificateTrustChain - Focus</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/certificate-trust-chain/${X509CertificateTrustChain.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <table class="table table-striped table-condensed">
                <thead>
                    <tr>
                        <th colspan="2">
                            Core Details
                        </th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <th>id</th>
                        <td>
                            <span class="label label-default">
                                ${X509CertificateTrustChain.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>chain_pem_md5</th>
                        <td><code>${X509CertificateTrustChain.chain_pem_md5}</code></td>
                    </tr>

                    <tr>
                        <th>x509_certificate_trusted_0</th>
                        <td>
                            The first item in the chain (signed a cert)<br/>
                            ${X509CertificateTrustChain.x509_certificate_trusted_0.button_view|n}
                        </td>
                    </tr>
                    <tr>
                        <th>x509_certificate_trusted_n</th>
                        <td>
                            The last item in the chain (signed by a root)<br/>
                            ${X509CertificateTrustChain.x509_certificate_trusted_n.button_view|n}
                        </td>
                    </tr>
                    <tr>
                        <th>chain item ids</th>
                        <td>
                            ids of X509CertificateTrusteds in this chain<br/>
                            <code>${X509CertificateTrustChain.x509_certificate_trusted_ids_string}</code>
                            <ul style="list list-unstyled">
                                % for x509_certificate_trusted in X509CertificateTrustChain.x509_certificate_trusteds_all:
                                    <li>${x509_certificate_trusted.button_view|n}</li>
                                % endfor
                            </ul>
                        </td>
                    </tr>
                    <tr>
                        <th>download</th>
                        <td>
                            <a class="label label-info" href="${admin_prefix}/certificate-trust-chain/${X509CertificateTrustChain.id}/chain.pem.txt">chain.pem.txt</a>
                            <a class="label label-info" href="${admin_prefix}/certificate-trust-chain/${X509CertificateTrustChain.id}/chain.pem">chain.pem</a>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

</%block>
