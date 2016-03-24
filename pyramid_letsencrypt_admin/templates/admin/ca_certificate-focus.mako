<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li><a href="/.well-known/admin/ca_certificates">CA Certificates</a></li>
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
            <td>${LetsencryptCACertificate.is_ca_certificate or ''}</td>
        </tr>
        <tr>
            <th>is_authority_certificate</th>
            <td>${LetsencryptCACertificate.is_authority_certificate or ''}</td>
        </tr>
        <tr>
            <th>is_cross_signed_authority_certificate</th>
            <td>${LetsencryptCACertificate.is_cross_signed_authority_certificate or ''}</td>
        </tr>
        <tr>
            <th>id_cross_signed_of</th>
            <td>${LetsencryptCACertificate.id_cross_signed_of or ''}</td>
        </tr>
        <tr>
            <th>timestamp_signed</th>
            <td>${LetsencryptCACertificate.timestamp_signed  or ''}</td>
        </tr>
        <tr>
            <th>timestamp_expires</th>
            <td>${LetsencryptCACertificate.timestamp_expires  or ''}</td>
        </tr>
        <tr>
            <th>timestamp_first_seen</th>
            <td>${LetsencryptCACertificate.timestamp_first_seen  or ''}</td>
        </tr>
        <tr>
            <th>cert_pem_md5</th>
            <td><code>${LetsencryptCACertificate.cert_pem_md5}</code></td>
        </tr>
        <tr>
            <th>cert_pem_modulus_md5</th>
            <td><code>${LetsencryptCACertificate.cert_pem_modulus_md5}</code></td>
        </tr>
        ## <tr>
        ##    <th>cert_pem</th>
        ##    <td><code>${LetsencryptCACertificate.cert_pem}</code></td>
        ## </tr>
        <tr>
            <th>download</th>
            <td>
                <a  class="btn btn-xs btn-info"
                    href="/.well-known/admin/ca_certificate/${LetsencryptCACertificate.id}/chain.pem">
                    chain.pem
                </a>
                <a  class="btn btn-xs btn-info"
                    href="/.well-known/admin/ca_certificate/${LetsencryptCACertificate.id}/chain.pem.txt">
                    chain.pem.txt
                </a>
                <a  class="btn btn-xs btn-info"
                    href="/.well-known/admin/ca_certificate/${LetsencryptCACertificate.id}/chain.der">
                    chain.der
                </a>
                <a  class="btn btn-xs btn-info"
                    href="/.well-known/admin/ca_certificate/${LetsencryptCACertificate.id}/chain.cer">
                    chain.cer (der)
                </a>
            </td>
        </tr>
        <tr>
            <th>Signed Certificates</th>
            <td>
                % if LetsencryptHttpsCertificates:
                    ${admin_partials.table_certificates__list(LetsencryptHttpsCertificates, show_domains=True)}
                    <nav>
                      <ul class="pager">
                        <li>
                            <a 
                                href="/.well-known/admin/ca_certificate/${LetsencryptCACertificate.id}/signed_certificates"
                            >See All</a>
                        </li>
                      </ul>
                    </nav>
                % else:
                    No known certificates.
                % endif 
            </td>
        </tr>
        
    </table>


    
</%block>
