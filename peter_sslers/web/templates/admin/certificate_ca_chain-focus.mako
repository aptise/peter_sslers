<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificate-cas">CertificateCAs</a></li>
        <li class="active">Focus [${CertificateCA.id}]</li>
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
            <table class="table">
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
                </tbody>
            </table>
        </div>
    </div>

</%block>
