<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/ca-certificates">CA Certificates</a></li>
        <li class="active">Focus [${SslCaCertificate.id}]</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>CA Certificate - Focus</h2>
    <p>${request.text_library.info_CACertificates[1]}</p>
</%block>


<%block name="content_main">

    <table class="table">
        <tr>
            <th>id</th>
            <td>
                <span class="label label-default">
                    ${SslCaCertificate.id}
                </span>
            </td>
        </tr>
        <tr>
            <th>name</th>
            <td>${SslCaCertificate.name}</td>
        </tr>
        <tr>
            <th>le_authority_name</th>
            <td>${SslCaCertificate.le_authority_name or ''}</td>
        </tr>
        <tr>
            <th>is_ca_certificate</th>
            <td>
                % if SslCaCertificate.is_ca_certificate:
                    <label class="label label-success">Y</label>
                % endif
            </td>
        </tr>
        <tr>
            <th>is_authority_certificate</th>
            <td>
                % if SslCaCertificate.is_authority_certificate:
                    <label class="label label-success">Y</label>
                % endif
            </td>
        </tr>
        <tr>
            <th>is_cross_signed_authority_certificate</th>
            <td>
                % if SslCaCertificate.is_cross_signed_authority_certificate:
                    <label class="label label-success">Y</label>
                % endif
            </td>
        </tr>
        <tr>
            <th>id_cross_signed_of</th>
            <td>${SslCaCertificate.id_cross_signed_of or ''}</td>
        </tr>
        <tr>
            <th>timestamp_signed</th>
            <td><timestamp>${SslCaCertificate.timestamp_signed  or ''}</timestamp></td>
        </tr>
        <tr>
            <th>timestamp_expires</th>
            <td><timestamp>${SslCaCertificate.timestamp_expires  or ''}</timestamp></td>
        </tr>
        <tr>
            <th>timestamp_first_seen</th>
            <td><timestamp>${SslCaCertificate.timestamp_first_seen  or ''}</timestamp></td>
        </tr>
        <tr>
            <th>count_active_certificates</th>
            <td><span class="badge">${SslCaCertificate.count_active_certificates  or ''}</span></td>
        </tr>
        <tr>
            <th>cert_pem_md5</th>
            <td><code>${SslCaCertificate.cert_pem_md5}</code></td>
        </tr>
        <tr>
            <th>cert_pem_modulus_md5</th>
            <td>
                <code>${SslCaCertificate.cert_pem_modulus_md5}</code>
                <a
                    class="btn btn-xs btn-info"
                    href="${admin_prefix}/search?${SslCaCertificate.cert_pem_modulus_search}"
                >
                    <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                </a>
            </td>
        </tr>
        ## <tr>
        ##    <th>cert_pem</th>
        ##    <td><code>${SslCaCertificate.cert_pem}</code></td>
        ## </tr>
        <tr>
            <th>download</th>
            <td>
                <a class="btn btn-xs btn-info" href="${admin_prefix}/ca-certificate/${SslCaCertificate.id}/chain.pem.txt">chain.pem.txt</a>
                <a class="btn btn-xs btn-info" href="${admin_prefix}/ca-certificate/${SslCaCertificate.id}/chain.pem">chain.pem</a>

                <a class="btn btn-xs btn-info" href="${admin_prefix}/ca-certificate/${SslCaCertificate.id}/chain.cer">chain.cer (der)</a>
                <a class="btn btn-xs btn-info" href="${admin_prefix}/ca-certificate/${SslCaCertificate.id}/chain.crt">chain.crt (der)</a>
                <a class="btn btn-xs btn-info" href="${admin_prefix}/ca-certificate/${SslCaCertificate.id}/chain.der">chain.der (der)</a>

            </td>
        </tr>
        <tr>
            <th>cert_subject</th>
            <td><code>${SslCaCertificate.cert_subject_hash}</code><br/>
                <samp>${SslCaCertificate.cert_subject}</samp>
                </td>
        </tr>
        <tr>
            <th>cert_issuer</th>
            <td><code>${SslCaCertificate.cert_issuer_hash}</code><br/>
                <samp>${SslCaCertificate.cert_issuer}</samp>
                </td>
        </tr>
        ${admin_partials.table_tr_event_created(SslCaCertificate.ssl_operations_event_id__created)}
        <tr>
            <th>Signed Certificates</th>
            <td>
                % if SslServerCertificates:
                    ${admin_partials.table_certificates__list(SslServerCertificates, show_domains=True)}
                    ${admin_partials.nav_pager("%s/ca-certificate/%s/server_certificates" % (admin_prefix, SslCaCertificate.id))}
                % else:
                    No known certificates.
                % endif
            </td>
        </tr>

    </table>



</%block>
