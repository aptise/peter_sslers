<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/ca-certificates">CA Certificates</a></li>
        <li class="active">Focus [${CACertificate.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>CA Certificate - Focus</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/ca-certificate/${CACertificate.id}.json" class="btn btn-xs btn-info">
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
                                ${CACertificate.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>name</th>
                        <td>${CACertificate.name}</td>
                    </tr>
                    <tr>
                        <th>le_authority_name</th>
                        <td>${CACertificate.le_authority_name or ''}</td>
                    </tr>
                    <tr>
                        <th>is_ca_certificate</th>
                        <td>
                            % if CACertificate.is_ca_certificate:
                                <label class="label label-success">Y</label>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>is_authority_certificate</th>
                        <td>
                            % if CACertificate.is_authority_certificate:
                                <label class="label label-success">Y</label>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>is_cross_signed_authority_certificate</th>
                        <td>
                            % if CACertificate.is_cross_signed_authority_certificate:
                                <label class="label label-success">Y</label>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>id_cross_signed_of</th>
                        <td>${CACertificate.id_cross_signed_of or ''}</td>
                    </tr>
                    <tr>
                        <th>timestamp_not_before</th>
                        <td><timestamp>${CACertificate.timestamp_not_before or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>timestamp_not_after</th>
                        <td><timestamp>${CACertificate.timestamp_not_after or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>timestamp_created</th>
                        <td><timestamp>${CACertificate.timestamp_created or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>count_active_certificates</th>
                        <td><span class="badge">${CACertificate.count_active_certificates or ''}</span></td>
                    </tr>
                    <tr>
                        <th>cert_pem_md5</th>
                        <td><code>${CACertificate.cert_pem_md5}</code></td>
                    </tr>
                    <tr>
                        <th>cert_pem_modulus_md5</th>
                        <td>
                            <code>${CACertificate.cert_pem_modulus_md5}</code>
                            <a
                                class="btn btn-xs btn-info"
                                href="${admin_prefix}/search?${CACertificate.cert_pem_modulus_search}"
                            >
                                <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                            </a>
                        </td>
                    </tr>
                    ## <tr>
                    ##    <th>cert_pem</th>
                    ##    <td><code>${CACertificate.cert_pem}</code></td>
                    ## </tr>
                    <tr>
                        <th>download</th>
                        <td>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/ca-certificate/${CACertificate.id}/chain.pem.txt">chain.pem.txt</a>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/ca-certificate/${CACertificate.id}/chain.pem">chain.pem</a>

                            <a class="btn btn-xs btn-info" href="${admin_prefix}/ca-certificate/${CACertificate.id}/chain.cer">chain.cer (der)</a>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/ca-certificate/${CACertificate.id}/chain.crt">chain.crt (der)</a>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/ca-certificate/${CACertificate.id}/chain.der">chain.der (der)</a>

                        </td>
                    </tr>
                    <tr>
                        <th>cert_subject</th>
                        <td><samp>${CACertificate.cert_subject}</samp>
                            </td>
                    </tr>
                    <tr>
                        <th>cert_issuer</th>
                        <td><samp>${CACertificate.cert_issuer}</samp>
                            </td>
                    </tr>
                    ${admin_partials.table_tr_OperationsEventCreated(CACertificate)}
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
                        <th>ServerCertificates</th>
                        <td>
                            % if ServerCertificates:
                                ${admin_partials.table_ServerCertificates(ServerCertificates, show_domains=True)}
                                ${admin_partials.nav_pager("%s/ca-certificate/%s/server-certificates" % (admin_prefix, CACertificate.id))}
                            % else:
                                No known ServerCertificates.
                            % endif
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

</%block>
