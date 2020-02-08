<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/ca-certificates">CA Certificates</a></li>
        <li class="active">Focus [${CaCertificate.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>CA Certificate - Focus</h2>
    <p>${request.text_library.info_CACertificates[1]}</p>
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
                                ${CaCertificate.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>name</th>
                        <td>${CaCertificate.name}</td>
                    </tr>
                    <tr>
                        <th>le_authority_name</th>
                        <td>${CaCertificate.le_authority_name or ''}</td>
                    </tr>
                    <tr>
                        <th>is_ca_certificate</th>
                        <td>
                            % if CaCertificate.is_ca_certificate:
                                <label class="label label-success">Y</label>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>is_authority_certificate</th>
                        <td>
                            % if CaCertificate.is_authority_certificate:
                                <label class="label label-success">Y</label>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>is_cross_signed_authority_certificate</th>
                        <td>
                            % if CaCertificate.is_cross_signed_authority_certificate:
                                <label class="label label-success">Y</label>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>id_cross_signed_of</th>
                        <td>${CaCertificate.id_cross_signed_of or ''}</td>
                    </tr>
                    <tr>
                        <th>timestamp_signed</th>
                        <td><timestamp>${CaCertificate.timestamp_signed  or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>timestamp_expires</th>
                        <td><timestamp>${CaCertificate.timestamp_expires  or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>timestamp_first_seen</th>
                        <td><timestamp>${CaCertificate.timestamp_first_seen  or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>count_active_certificates</th>
                        <td><span class="badge">${CaCertificate.count_active_certificates  or ''}</span></td>
                    </tr>
                    <tr>
                        <th>cert_pem_md5</th>
                        <td><code>${CaCertificate.cert_pem_md5}</code></td>
                    </tr>
                    <tr>
                        <th>cert_pem_modulus_md5</th>
                        <td>
                            <code>${CaCertificate.cert_pem_modulus_md5}</code>
                            <a
                                class="btn btn-xs btn-info"
                                href="${admin_prefix}/search?${CaCertificate.cert_pem_modulus_search}"
                            >
                                <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                            </a>
                        </td>
                    </tr>
                    ## <tr>
                    ##    <th>cert_pem</th>
                    ##    <td><code>${CaCertificate.cert_pem}</code></td>
                    ## </tr>
                    <tr>
                        <th>download</th>
                        <td>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/ca-certificate/${CaCertificate.id}/chain.pem.txt">chain.pem.txt</a>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/ca-certificate/${CaCertificate.id}/chain.pem">chain.pem</a>

                            <a class="btn btn-xs btn-info" href="${admin_prefix}/ca-certificate/${CaCertificate.id}/chain.cer">chain.cer (der)</a>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/ca-certificate/${CaCertificate.id}/chain.crt">chain.crt (der)</a>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/ca-certificate/${CaCertificate.id}/chain.der">chain.der (der)</a>

                        </td>
                    </tr>
                    <tr>
                        <th>cert_subject</th>
                        <td><code>${CaCertificate.cert_subject_hash}</code><br/>
                            <samp>${CaCertificate.cert_subject}</samp>
                            </td>
                    </tr>
                    <tr>
                        <th>cert_issuer</th>
                        <td><code>${CaCertificate.cert_issuer_hash}</code><br/>
                            <samp>${CaCertificate.cert_issuer}</samp>
                            </td>
                    </tr>
                    ${admin_partials.table_tr_event_created(CaCertificate)}
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
                        <th>Signed Certificates</th>
                        <td>
                            % if ServerCertificates:
                                ${admin_partials.table_certificates__list(ServerCertificates, show_domains=True)}
                                ${admin_partials.nav_pager("%s/ca-certificate/%s/certificates-signed" % (admin_prefix, CaCertificate.id))}
                            % else:
                                No known certificates.
                            % endif
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

</%block>
