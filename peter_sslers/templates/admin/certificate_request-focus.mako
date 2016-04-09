<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificate-requests">Certificate Requests</a></li>
        <li class="active">Focus [${SslCertificateRequest.id}]</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Certificate Request - Focus</h2>
</%block>


<%block name="content_main">

    <table class="table">
        <tr>
            <th>id</th>
            <td>
                <span class="label label-default">
                    ${SslCertificateRequest.id}
                </span>
            </td>
        </tr>
        <tr>
            <th>is_active</th>
            <td>
                <span class="label label-${'success' if SslCertificateRequest.is_active else 'warning'}">
                    ${'Active' if SslCertificateRequest.is_active else 'inactive'}
                </span>
            </td>
        </tr>
        <tr>
            <th>is_error</th>
            <td>
                <span class="label label-${'danger' if SslCertificateRequest.is_error else 'default'}">
                    ${'Error' if SslCertificateRequest.is_error else 'ok'}
                </span>
            </td>
        </tr>
        <tr>
            <th>certificate_request_type</th>
            <td>
                <span class="label label-default">${SslCertificateRequest.certificate_request_type}</span>
            </td>
        </tr>
        <tr>
            <th>is issued?</th>
            <td>
                % if SslCertificateRequest.signed_certificate:
                    <span class="label label-success">Yes</span>&nbsp;
                    <a class="label label-info" href="${admin_prefix}/certificate/${SslCertificateRequest.signed_certificate.id}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        ${SslCertificateRequest.signed_certificate.id}</a>
                % else:
                    <span class="label label-default">No</span>
                % endif
            </td>
        </tr>
        <tr>
            <th>is renewal?</th>
            <td>
                % if SslCertificateRequest.ssl_server_certificate_id__renewal_of:
                    <span class="label label-success">Yes</span>&nbsp;
                    <a class="label label-info" href="${admin_prefix}/certificate/${SslCertificateRequest.ssl_server_certificate_id__renewal_of}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        ${SslCertificateRequest.ssl_server_certificate_id__renewal_of}</a>
                % else:
                    <span class="label label-default">No</span>
                % endif
            </td>
        </tr>
        <tr>
            <th>ssl_letsencrypt_account_key_id</th>
            <td>
                % if SslCertificateRequest.ssl_letsencrypt_account_key_id:
                    <a class="label label-info" href="${admin_prefix}/account-key/${SslCertificateRequest.ssl_letsencrypt_account_key_id}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        ${SslCertificateRequest.ssl_letsencrypt_account_key_id}</a>
                % endif
            </td>
        </tr>
        <tr>
            <th>ssl_private_key_id__signed_by</th>
            <td>
                % if SslCertificateRequest.ssl_private_key_id__signed_by:
                    % if SslCertificateRequest.private_key__signed_by.is_compromised:
                        <a class="label label-danger" href="${admin_prefix}/private-key/${SslCertificateRequest.ssl_private_key_id__signed_by}">
                            <span class="glyphicon glyphicon-warning-sign" aria-hidden="true"></span>
                            ${SslCertificateRequest.ssl_private_key_id__signed_by}</a>
                    % else:
                        <a class="label label-info" href="${admin_prefix}/private-key/${SslCertificateRequest.ssl_private_key_id__signed_by}">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            ${SslCertificateRequest.ssl_private_key_id__signed_by}</a>
                    % endif
                % endif
            </td>
        </tr>
        <tr>
            <th>unique fqdn set</th>
            <td>
                <a class="label label-info" href="${admin_prefix}/unique-fqdn-set/${SslCertificateRequest.ssl_unique_fqdn_set_id}">
                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                    ${SslCertificateRequest.ssl_unique_fqdn_set_id}</a>
            </td>
        </tr>
        <tr>
            <th>timestamp_started</th>
            <td>${SslCertificateRequest.timestamp_started}</td>
        </tr>
        <tr>
            <th>timestamp_finished</th>
            <td>${SslCertificateRequest.timestamp_finished or ''}</td>
        </tr>
        <tr>
            <th>csr_pem_md5</th>
            <td><code>${SslCertificateRequest.csr_pem_md5 or ''}</code></td>
        </tr>
        <tr>
            <th>csr_pem_modulus_md5</th>
            <td>
                <code>${SslCertificateRequest.csr_pem_modulus_md5 or ''}</code>
                <a
                    class="btn btn-xs btn-info"
                    href="${admin_prefix}/search?${SslCertificateRequest.csr_pem_modulus_search}"
                >
                    <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                </a>
            </td>
        </tr>
        <tr>
            <th>csr_pem</th>
            <td>
                % if SslCertificateRequest.csr_pem:
                    ## <textarea class="form-control">${SslCertificateRequest.csr_pem}</textarea>
                    <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-request/${SslCertificateRequest.id}/csr.pem">csr.pem</a>
                    <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-request/${SslCertificateRequest.id}/csr.pem.txt">csr.pem.txt</a>
                    <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-request/${SslCertificateRequest.id}/csr.csr">csr.csr [pem format]</a>
                % else:
                    <em>pem is not tracked</em>
                % endif
            </td>
        </tr>
        <tr>
            <th>domains</th>
            <td>
                ${admin_partials.table_SslCertificateRequest2SslDomain(SslCertificateRequest.certificate_request_to_domains,
                                                                                     request_inactive = (False if SslCertificateRequest.is_active else True),
                                                                                     perspective='certificate_request')}
            </td>
        </tr>
    </table>

    % if SslCertificateRequest.is_active and SslCertificateRequest.certificate_request_type_is('acme flow'):
        <a
            href="${admin_prefix}/certificate-request/${SslCertificateRequest.id}/process"
            class="btn btn-info"
        >
            <span class="glyphicon glyphicon-wrench" aria-hidden="true"></span>
            Edit Codes
        </a>
        <a
            href="${admin_prefix}/certificate-request/${SslCertificateRequest.id}/deactivate"
            class="btn btn-primary"
        >
            <span class="glyphicon glyphicon-play-circle" aria-hidden="true"></span>
            deactivate
        </a>
    % endif
</%block>
