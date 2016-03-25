<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li><a href="/.well-known/admin/certificates">Certificates</a></li>
        <li class="active">Focus [${LetsencryptServerCertificate.id}]</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Certificate - Focus</h2>
</%block>
    

<%block name="content_main">

    <table class="table">
        <tr>
            <th>id</th>
            <td>
                <span class="label label-default">
                    ${LetsencryptServerCertificate.id}
                </span>
            </td>
        </tr>
        <tr>
            <th>is_active</th>
            <td>
                <span class="label label-${'success' if LetsencryptServerCertificate.is_active else 'warning'}">
                    ${'Active' if LetsencryptServerCertificate.is_active else 'inactive'}
                </span>
            </td>
        </tr>
        <tr>
            <th>is_single_domain_cert</th>
            <td>
                % if LetsencryptServerCertificate.is_single_domain_cert is True:
                    <span class="label label-default">
                        single domain certificate
                    </span>
                % elif LetsencryptServerCertificate.is_single_domain_cert is False:
                    <span class="label label-default">
                        multiple domain certificate
                    </span>
                % endif
            </td>
        </tr>
        <tr>
            <th>timestamp_signed</th>
            <td><timestamp>${LetsencryptServerCertificate.timestamp_signed}</timestamp></td>
        </tr>
        <tr>
            <th>timestamp_expires</th>
            <td><timestamp>${LetsencryptServerCertificate.timestamp_expires}</timestamp></td>
        </tr>
        <tr>
            <th>letsencrypt_ca_certificate_id__signed_by</th>
            <td>
                <a class="label label-default" href="/.well-known/admin/ca_certificate/${LetsencryptServerCertificate.letsencrypt_ca_certificate_id__signed_by}">&gt; ${LetsencryptServerCertificate.letsencrypt_ca_certificate_id__signed_by}</a>
            </td>
        </tr>
        <tr>
            <th>letsencrypt_certificate_request_id</th>
            <td>
                % if LetsencryptServerCertificate.letsencrypt_certificate_request_id:
                    <a class="label label-default" href="/.well-known/admin/certificate_request/${LetsencryptServerCertificate.letsencrypt_certificate_request_id}">&gt; ${LetsencryptServerCertificate.letsencrypt_certificate_request_id}</a>
                % endif
            </td>
        </tr>
        <tr>
            <th>cert_pem_md5</th>
            <td><code>${LetsencryptServerCertificate.cert_pem_md5}</code></td>
        </tr>
        <tr>
            <th>cert_pem_modulus_md5</th>
            <td><code>${LetsencryptServerCertificate.cert_pem_modulus_md5}</code></td>
        </tr>
        <tr>
            <th>cert_pem</th>
            <td>
                ## <textarea class="form-control">${LetsencryptServerCertificate.key_pem}</textarea>
                <a class="btn btn-xs btn-info" href="/.well-known/admin/certificate/${LetsencryptServerCertificate.id}/cert.pem">cert.pem</a>
                <a class="btn btn-xs btn-info" href="/.well-known/admin/certificate/${LetsencryptServerCertificate.id}/cert.pem.txt">cert.pem.txt</a>
                <a class="btn btn-xs btn-info" href="/.well-known/admin/certificate/${LetsencryptServerCertificate.id}/cert.crt">cert.crt (der)</a>
            </td>
        </tr>
        <tr>
            <th>cert_subject</th>
            <td><code>${LetsencryptServerCertificate.cert_subject_hash}</code><br/>
                <samp>${LetsencryptServerCertificate.cert_subject}</samp>
                </td>
        </tr>
        <tr>
            <th>cert_issuer</th>
            <td><code>${LetsencryptServerCertificate.cert_issuer_hash}</code><br/>
                <samp>${LetsencryptServerCertificate.cert_issuer}</samp>
                </td>
        </tr>
        <tr>
            <th>domains</th>
            <td>
                <table class="table table-striped table-condensed">
                    <thead>
                        <tr>
                            <th></th>
                            <th>domain</th>
                            <th>is latest cert?</th>
                        </tr>
                    </thead>
                    <tbody>
                        % for to_d in LetsencryptServerCertificate.certificate_to_domains:
                            <tr>
                                <td>
                                    <a class="label label-default" href="/.well-known/admin/domain/${to_d.domain.id}">&gt; ${to_d.domain.id}</a>
                                </td>
                                <td>
                                    ${to_d.domain.domain_name}
                                </td>
                                <td>
                                    % if LetsencryptServerCertificate.id in (to_d.domain.letsencrypt_server_certificate_id__latest_single, to_d.domain.letsencrypt_server_certificate_id__latest_multi):
                                        <span class="label label-default">
                                            % if LetsencryptServerCertificate.id == to_d.domain.letsencrypt_server_certificate_id__latest_single:
                                                single
                                            % endif
                                            % if LetsencryptServerCertificate.id == to_d.domain.letsencrypt_server_certificate_id__latest_multi:
                                                multi
                                            % endif
                                        </span>
                                    % endif
                                </td>
                                <td>
                                    ${to_d.domain.domain_name}
                                </td>
                            </tr>
                        % endfor
                    </tbody>
                </table>
            </td>
        </tr>
    </table>
    
</%block>
