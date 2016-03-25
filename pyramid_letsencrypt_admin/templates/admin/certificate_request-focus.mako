<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li><a href="/.well-known/admin/certificate_requests">Certificate Requests</a></li>
        <li class="active">Focus [${LetsencryptCertificateRequest.id}]</li>
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
                    ${LetsencryptCertificateRequest.id}
                </span>
            </td>
        </tr>
        <tr>
            <th>is_active</th>
            <td>
                <span class="label label-${'success' if LetsencryptCertificateRequest.is_active else 'warning'}">
                    ${'Active' if LetsencryptCertificateRequest.is_active else 'inactive'}
                </span>
            </td>
        </tr>
        <tr>
            <th>is_error</th>
            <td>
                <span class="label label-${'danger' if LetsencryptCertificateRequest.is_error else 'default'}">
                    ${'Error' if LetsencryptCertificateRequest.is_error else 'ok'}
                </span>
            </td>
        </tr>
        <tr>
            <th>certificate_request_type</th>
            <td>
                <span class="label label-info">${LetsencryptCertificateRequest.certificate_request_type}</span>
            </td>
        </tr>
        <tr>
            <th>letsencrypt_account_key_id</th>
            <td>
                % if LetsencryptCertificateRequest.letsencrypt_account_key_id:
                    <a class="label label-default" href="/.well-known/admin/account_key/${LetsencryptCertificateRequest.letsencrypt_account_key_id}">&gt; ${LetsencryptCertificateRequest.letsencrypt_account_key_id}</a>
                % endif
            </td>
        </tr>
        <tr>
            <th>letsencrypt_private_key_id__signed_by</th>
            <td>
                % if LetsencryptCertificateRequest.letsencrypt_private_key_id__signed_by:
                    <a class="label label-default" href="/.well-known/admin/private_key/${LetsencryptCertificateRequest.letsencrypt_private_key_id__signed_by}">&gt; ${LetsencryptCertificateRequest.letsencrypt_private_key_id__signed_by}</a>
                % endif
            </td>
        </tr>
        <tr>
            <th>timestamp_started</th>
            <td>${LetsencryptCertificateRequest.timestamp_started}</td>
        </tr>
        <tr>
            <th>timestamp_finished</th>
            <td>${LetsencryptCertificateRequest.timestamp_finished}</td>
        </tr>
        <tr>
            <th>csr_pem_md5</th>
            <td><code>${LetsencryptCertificateRequest.csr_pem_md5}</code></td>
        </tr>
        <tr>
            <th>csr_pem_modulus_md5</th>
            <td><code>${LetsencryptCertificateRequest.csr_pem_modulus_md5}</code></td>
        </tr>
        <tr>
            <th>csr_pem</th>
            <td>
                ## <textarea class="form-control">${LetsencryptCertificateRequest.key_pem}</textarea>
                <a class="btn btn-xs btn-info" href="/.well-known/admin/certificate_request/${LetsencryptCertificateRequest.id}/csr.pem">csr.pem</a>
                <a class="btn btn-xs btn-info" href="/.well-known/admin/certificate_request/${LetsencryptCertificateRequest.id}/csr.pem.txt">csr.pem.txt</a>
                <a class="btn btn-xs btn-info" href="/.well-known/admin/certificate_request/${LetsencryptCertificateRequest.id}/csr.csr">csr.csr [pem format]</a>
            </td>
        </tr>
        <tr>
            <th>domains</th>
            <td>
                ${admin_partials.table_LetsencryptCertificateRequest2LetsencryptDomain(LetsencryptCertificateRequest.certificate_request_to_domains,
                                                                                     request_inactive = (False if LetsencryptCertificateRequest.is_active else True),
                                                                                     perspective='certificate_request')}
            </td>
        </tr>
    </table>
    
    % if LetsencryptCertificateRequest.is_active and LetsencryptCertificateRequest.certificate_request_type_is('flow'):
        <a 
            href="/.well-known/admin/certificate_request/${LetsencryptCertificateRequest.id}/process"
            class="btn btn-info"
        >
            Edit Codes
        </a>
        <a 
            href="/.well-known/admin/certificate_request/${LetsencryptCertificateRequest.id}/deactivate"
            class="btn btn-info"
        >
            deactivate
        </a>
    % endif
</%block>
