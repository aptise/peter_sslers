<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/ca-certificates">CA Certificates</a></li>
        <li class="active">Focus [${LetsencryptCACertificate.id}]</li>
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
                    ${LetsencryptCACertificate.id}
                </span>
            </td>
        </tr>
        <tr>
            <th>name</th>
            <td>${LetsencryptCACertificate.name}</td>
        </tr>
        <tr>
            <th>le_authority_name</th>
            <td>${LetsencryptCACertificate.le_authority_name or ''}</td>
        </tr>
        <tr>
            <th>is_ca_certificate</th>
            <td>
                % if LetsencryptCACertificate.is_ca_certificate:
                    <label class="label label-success">Y</label>
                % endif
            </td>
        </tr>
        <tr>
            <th>is_authority_certificate</th>
            <td>
                % if LetsencryptCACertificate.is_authority_certificate:
                    <label class="label label-success">Y</label>
                % endif
            </td>
        </tr>
        <tr>
            <th>is_cross_signed_authority_certificate</th>
            <td>
                % if LetsencryptCACertificate.is_cross_signed_authority_certificate:
                    <label class="label label-success">Y</label>
                % endif
            </td>
        </tr>
        <tr>
            <th>id_cross_signed_of</th>
            <td>${LetsencryptCACertificate.id_cross_signed_of or ''}</td>
        </tr>
        <tr>
            <th>timestamp_signed</th>
            <td><timestamp>${LetsencryptCACertificate.timestamp_signed  or ''}</timestamp></td>
        </tr>
        <tr>
            <th>timestamp_expires</th>
            <td><timestamp>${LetsencryptCACertificate.timestamp_expires  or ''}</timestamp></td>
        </tr>
        <tr>
            <th>timestamp_first_seen</th>
            <td><timestamp>${LetsencryptCACertificate.timestamp_first_seen  or ''}</timestamp></td>
        </tr>
        <tr>
            <th>count_active_certificates</th>
            <td><span class="badge">${LetsencryptCACertificate.count_active_certificates  or ''}</span></td>
        </tr>
        <tr>
            <th>cert_pem_md5</th>
            <td><code>${LetsencryptCACertificate.cert_pem_md5}</code></td>
        </tr>
        <tr>
            <th>cert_pem_modulus_md5</th>
            <td>
                <code>${LetsencryptCACertificate.cert_pem_modulus_md5}</code>
                <a
                    class="btn btn-xs btn-info"
                    href="${admin_prefix}/search?${LetsencryptCACertificate.cert_pem_modulus_search}"
                >
                    <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                </a>
            </td>
        </tr>
        ## <tr>
        ##    <th>cert_pem</th>
        ##    <td><code>${LetsencryptCACertificate.cert_pem}</code></td>
        ## </tr>
        <tr>
            <th>download</th>
            <td>
                <a class="btn btn-xs btn-info" href="${admin_prefix}/ca-certificate/${LetsencryptCACertificate.id}/chain.pem.txt">chain.pem.txt</a>
                <a class="btn btn-xs btn-info" href="${admin_prefix}/ca-certificate/${LetsencryptCACertificate.id}/chain.pem">chain.pem</a>

                <a class="btn btn-xs btn-info" href="${admin_prefix}/ca-certificate/${LetsencryptCACertificate.id}/chain.cer">chain.cer (der)</a>
                <a class="btn btn-xs btn-info" href="${admin_prefix}/ca-certificate/${LetsencryptCACertificate.id}/chain.crt">chain.crt (der)</a>
                <a class="btn btn-xs btn-info" href="${admin_prefix}/ca-certificate/${LetsencryptCACertificate.id}/chain.der">chain.der (der)</a>

            </td>
        </tr>
        <tr>
            <th>cert_subject</th>
            <td><code>${LetsencryptCACertificate.cert_subject_hash}</code><br/>
                <samp>${LetsencryptCACertificate.cert_subject}</samp>
                </td>
        </tr>
        <tr>
            <th>cert_issuer</th>
            <td><code>${LetsencryptCACertificate.cert_issuer_hash}</code><br/>
                <samp>${LetsencryptCACertificate.cert_issuer}</samp>
                </td>
        </tr>
        <tr>
            <th>Signed Certificates</th>
            <td>
                % if LetsencryptServerCertificates:
                    ${admin_partials.table_certificates__list(LetsencryptServerCertificates, show_domains=True)}
                    ${admin_partials.nav_pager("%s/ca-certificate/%s/signed_certificates" % (admin_prefix, LetsencryptCACertificate.id))}
                % else:
                    No known certificates.
                % endif
            </td>
        </tr>

    </table>



</%block>
