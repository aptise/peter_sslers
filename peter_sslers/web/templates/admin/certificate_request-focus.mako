<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificate-requests">Certificate Requests</a></li>
        <li class="active">Focus [${CertificateRequest.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Certificate Request - Focus</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/certificate-request/${CertificateRequest.id}.json" class="btn btn-xs btn-info">
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
                                ${CertificateRequest.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>is_active</th>
                        <td>
                            <span class="label label-${'success' if CertificateRequest.is_active else 'warning'}">
                                ${'Active' if CertificateRequest.is_active else 'inactive'}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>certificate_request_source</th>
                        <td>
                            <span class="label label-default">${CertificateRequest.certificate_request_source}</span>
                        </td>
                    </tr>
                    <tr>
                        <th>is issued?</th>
                        <td>
                            % if CertificateRequest.server_certificates__5:
                                <span class="label label-success">Yes</span>&nbsp;
                                ${admin_partials.table_ServerCertificates(CertificateRequest.server_certificates__5, perspective='CertificateRequest')}
                            % else:
                                <span class="label label-default">No</span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>is renewal?</th>
                        <td>
                            % if CertificateRequest.server_certificate_id__renewal_of:
                                <span class="label label-success">Yes</span>&nbsp;
                                renewal of Certificate
                                <a class="label label-info" href="${admin_prefix}/certificate/${CertificateRequest.server_certificate_id__renewal_of}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    cert-${CertificateRequest.server_certificate_id__renewal_of}</a>
                            % else:
                                <span class="label label-default">No</span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>private_key_id</th>
                        <td>
                            % if CertificateRequest.private_key_id:
                                % if CertificateRequest.private_key.is_compromised:
                                    <a class="label label-danger" href="${admin_prefix}/private-key/${CertificateRequest.private_key_id}">
                                        <span class="glyphicon glyphicon-warning-sign" aria-hidden="true"></span>
                                        PrivateKey-${CertificateRequest.private_key_id}</a>
                                % else:
                                    <a class="label label-info" href="${admin_prefix}/private-key/${CertificateRequest.private_key_id}">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        PrivateKey-${CertificateRequest.private_key_id}</a>
                                % endif
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>timestamp_created</th>
                        <td><timestamp>${CertificateRequest.timestamp_created}</timestamp></td>
                    </tr>
                    <tr>
                        <th>csr_pem_md5</th>
                        <td><code>${CertificateRequest.csr_pem_md5 or ''}</code></td>
                    </tr>
                    <tr>
                        <th>csr_pem_modulus_md5</th>
                        <td>
                            % if CertificateRequest.csr_pem_modulus_md5:
                                <code>${CertificateRequest.csr_pem_modulus_md5}</code>
                                <a
                                    class="btn btn-xs btn-info"
                                    href="${admin_prefix}/search?${CertificateRequest.csr_pem_modulus_search}"
                                >
                                    <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                                </a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>csr_pem</th>
                        <td>
                            % if CertificateRequest.csr_pem:
                                ## <textarea class="form-control">${CertificateRequest.csr_pem}</textarea>
                                <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-request/${CertificateRequest.id}/csr.pem">csr.pem</a>
                                <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-request/${CertificateRequest.id}/csr.pem.txt">csr.pem.txt</a>
                                <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-request/${CertificateRequest.id}/csr.csr">csr.csr [pem format]</a>
                            % else:
                                <em>pem is not tracked</em>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>unique fqdn set</th>
                        <td>
                            <a class="label label-info" href="${admin_prefix}/unique-fqdn-set/${CertificateRequest.unique_fqdn_set_id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                UniqueFQDNSet-${CertificateRequest.unique_fqdn_set_id}</a>
                        </td>
                    </tr>
                    <tr>
                        <th>domains (via UniqueFQDNSet)</th>
                        <td>
                            ${admin_partials.table_UniqueFQDNSet_Domains(CertificateRequest.unique_fqdn_set, perspective='CertificateRequest')}
                        </td>
                    </tr>
                </tbody>
                <thead>
                    <tr>
                        <th colspan="2">
                        <hr/>
                        </th>
                    </tr>
                    <tr>
                        <th colspan="2">
                            Relations Library
                        </th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <th>latest acme order</th>
                        <td>
                            % if CertificateRequest.latest_acme_order:
                                <a
                                    href="${admin_prefix}/acme-order/${CertificateRequest.latest_acme_order.id}"
                                    class="label label-info"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeOrder-${CertificateRequest.latest_acme_order.id}
                                </a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>acme order history history</th>
                        <td>
                            <a
                                href="${admin_prefix}/certificate-request/${CertificateRequest.id}/acme-orders"
                                class="label label-info"
                            >
                                <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                                AcmeOrder History
                            </a>
                        </td>
                    </tr>
                </tbody>
            </table>

            % if CertificateRequest.is_active and CertificateRequest.certificate_request_source_is('acme flow'):
                <a
                    href="${admin_prefix}/certificate-request/${CertificateRequest.id}/acme-flow/manage"
                    class="btn btn-info"
                >
                    <span class="glyphicon glyphicon-wrench" aria-hidden="true"></span>
                    Edit Codes
                </a>
                <a
                    href="${admin_prefix}/certificate-request/${CertificateRequest.id}/acme-flow/deactivate"
                    class="btn btn-primary"
                >
                    <span class="glyphicon glyphicon-play-circle" aria-hidden="true"></span>
                    deactivate
                </a>
            % endif




        </div>
    </div>
</%block>
