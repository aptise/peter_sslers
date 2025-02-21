<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificate-ca-chains">CertificateCAChains</a></li>
        <li class="active">Focus [${CertificateCAChain.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>CertificateCAChain - Focus</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/certificate-ca-chain/${CertificateCAChain.id}.json" class="btn btn-xs btn-info">
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
                                ${CertificateCAChain.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>chain_pem_md5</th>
                        <td><code>${CertificateCAChain.chain_pem_md5}</code></td>
                    </tr>

                    <tr>
                        <th>certificate_ca_0</th>
                        <td>
                            The first item in the chain (signed a cert)<br/>
                            ${CertificateCAChain.certificate_ca_0.button_view|n}
                        </td>
                    </tr>
                    <tr>
                        <th>certificate_ca_n</th>
                        <td>
                            The last item in the chain (signed by a root)<br/>
                            ${CertificateCAChain.certificate_ca_n.button_view|n}
                        </td>
                    </tr>
                    <tr>
                        <th>chain item ids</th>
                        <td>
                            ids of CertificateCAs in this chain<br/>
                            <code>${CertificateCAChain.certificate_ca_ids_string}</code>
                            <ul style="list list-unstyled">
                                % for certificate_ca in CertificateCAChain.certificate_cas_all:
                                    <li>${certificate_ca.button_view|n}</li>
                                % endfor
                            </ul>
                        </td>
                    </tr>
                    <tr>
                        <th>download</th>
                        <td>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-ca-chain/${CertificateCAChain.id}/chain.pem.txt">chain.pem.txt</a>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-ca-chain/${CertificateCAChain.id}/chain.pem">chain.pem</a>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

</%block>
