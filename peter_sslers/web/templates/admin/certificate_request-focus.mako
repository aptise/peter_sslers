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
                    <th>is_error</th>
                    <td>
                        <span class="label label-${'danger' if CertificateRequest.is_error else 'default'}">
                            ${'Error' if CertificateRequest.is_error else 'ok'}
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
                        % if CertificateRequest.server_certificate:
                            <span class="label label-success">Yes</span>&nbsp;
                            <a class="label label-info" href="${admin_prefix}/certificate/${CertificateRequest.server_certificate.id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                cert-${CertificateRequest.server_certificate.id}</a>
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
                    <th>acme_account_key_id</th>
                    <td>
                        % if CertificateRequest.acme_account_key_id:
                            <a class="label label-info" href="${admin_prefix}/account-key/${CertificateRequest.acme_account_key_id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                account-${CertificateRequest.acme_account_key_id}</a>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>private_key_id__signed_by</th>
                    <td>
                        % if CertificateRequest.private_key_id__signed_by:
                            % if CertificateRequest.private_key__signed_by.is_compromised:
                                <a class="label label-danger" href="${admin_prefix}/private-key/${CertificateRequest.private_key_id__signed_by}">
                                    <span class="glyphicon glyphicon-warning-sign" aria-hidden="true"></span>
                                    pkey-${CertificateRequest.private_key_id__signed_by}</a>
                            % else:
                                <a class="label label-info" href="${admin_prefix}/private-key/${CertificateRequest.private_key_id__signed_by}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    pkey-${CertificateRequest.private_key_id__signed_by}</a>
                            % endif
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>unique fqdn set</th>
                    <td>
                        <a class="label label-info" href="${admin_prefix}/unique-fqdn-set/${CertificateRequest.unique_fqdn_set_id}">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            fqdnset-${CertificateRequest.unique_fqdn_set_id}</a>
                    </td>
                </tr>
                <tr>
                    <th>timestamp_started</th>
                    <td>${CertificateRequest.timestamp_started}</td>
                </tr>
                <tr>
                    <th>timestamp_finished</th>
                    <td>${CertificateRequest.timestamp_finished or ''}</td>
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
                    <th>domains</th>
                    <td>
                        ${admin_partials.table_CertificateRequest2Domain(CertificateRequest.unique_fqdn_set.to_domains,
                                                                            request_inactive = (False if CertificateRequest.is_active else True),
                                                                            perspective='certificate_request')}
                    </td>
                </tr>
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
