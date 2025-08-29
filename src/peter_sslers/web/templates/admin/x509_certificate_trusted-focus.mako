<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/x509-certificate-trusteds">X509CertificateTrusteds</a></li>
        <li class="active">Focus [${X509CertificateTrusted.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>X509CertificateTrusted - Focus</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/x509-certificate-trusted/${X509CertificateTrusted.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>

<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <table class="table table-striped table-condensed">
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
                                ${X509CertificateTrusted.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>display_name</th>
                        <td><samp>${X509CertificateTrusted.display_name or ""}</samp></td>
                    </tr>
                    <tr>
                        <th>is_trusted_root</th>
                        <td>
                            % if X509CertificateTrusted.is_trusted_root:
                                <label class="label label-success">Y</label>
                                <h4>Root Stores</h4>
                                % if X509CertificateTrusted.to_root_store_versions:
                                    <% root_store_versions = [to_root_store_version.root_store_version for to_root_store_version in X509CertificateTrusted.to_root_store_versions] %>
                                    ${admin_partials.table_RootStoreVersions(root_store_versions, perspective="X509CertificateTrusted")}
                                % endif
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>timestamp_not_before</th>
                        <td><timestamp>${X509CertificateTrusted.timestamp_not_before or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>timestamp_not_after</th>
                        <td><timestamp>${X509CertificateTrusted.timestamp_not_after or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>timestamp_created</th>
                        <td><timestamp>${X509CertificateTrusted.timestamp_created or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>count_active_certificates</th>
                        <td><span class="badge">${X509CertificateTrusted.count_active_certificates or ''}</span></td>
                    </tr>
                    <tr>
                        <th>fingerprint_sha1</th>
                        <td>
                            <code>${X509CertificateTrusted.fingerprint_sha1_preview|n}</code><br/>
                            <code>${X509CertificateTrusted.fingerprint_sha1}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>cert_pem_md5</th>
                        <td><code>${X509CertificateTrusted.cert_pem_md5}</code></td>
                    </tr>
                    <tr>
                        <th>spki_sha256</th>
                        <td>
                            <code>${X509CertificateTrusted.spki_sha256}</code>
                            ${X509CertificateTrusted.button_search_spki|n} <i>[Search for Compatible]</i>
                        </td>
                    </tr>
                    <tr>
                        <th>cert_issuer_uri</th>
                        <td><code>${X509CertificateTrusted.cert_issuer_uri or ''}</code></td>
                    </tr>
                    <tr>
                        <th>cert_authority_key_identifier</th>
                        <td><code>${X509CertificateTrusted.cert_authority_key_identifier or ''}</code></td>
                    </tr>
                    <tr>
                        <th>download</th>
                        <td>
                            <a class="label label-info" href="${admin_prefix}/x509-certificate-trusted/${X509CertificateTrusted.id}/cert.pem.txt">cert.pem.txt (PEM)</a>
                            <a class="label label-info" href="${admin_prefix}/x509-certificate-trusted/${X509CertificateTrusted.id}/cert.pem">cert.pem (PEM)</a>

                            <a class="label label-info" href="${admin_prefix}/x509-certificate-trusted/${X509CertificateTrusted.id}/cert.cer">cert.cer (DER)</a>
                            <a class="label label-info" href="${admin_prefix}/x509-certificate-trusted/${X509CertificateTrusted.id}/cert.crt">cert.crt (DER)</a>
                            <a class="label label-info" href="${admin_prefix}/x509-certificate-trusted/${X509CertificateTrusted.id}/cert.der">cert.der (DER)</a>
                        </td>
                    </tr>
                    <tr>
                        <th>cert_subject</th>
                        <td><samp>${X509CertificateTrusted.cert_subject}</samp>
                            </td>
                    </tr>
                    <tr>
                        <th>cert_issuer</th>
                        <td><samp>${X509CertificateTrusted.cert_issuer}</samp>
                            </td>
                    </tr>
                    <tr>
                        <th>Reconciliation</th>
                        <td>
                            <table class="table table-striped table-condensed">
                                <tr>
                                    <th>cert_issuer__reconciled</th>
                                    <td>Has a reconciliation been attempted?<br/> ${X509CertificateTrusted.cert_issuer__reconciled or ""}</td>
                                </tr>
                                <tr>
                                    <th>cert_issuer__x509_certificate_trusted_id</th>
                                    <td>via reconciliation:
                                        % if X509CertificateTrusted.cert_issuer__x509_certificate_trusted_id:
                                            ${X509CertificateTrusted.cert_issuer__x509_certificate_trusted.button_view|n}
                                        % endif
                                    </td>
                                </tr>
                                <tr>
                                    <th>reconciled_uris</th>
                                    <td>This certificate was served by the following urls during reconciliation processes: ${X509CertificateTrusted.reconciled_uris or ""}</td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    ${admin_partials.table_tr_OperationsEventCreated(X509CertificateTrusted)}
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
                        <th>X509CertificateTrustChains0</th>
                        <td>
                            % if X509CertificateTrustChains0:
                                ${admin_partials.table_X509CertificateTrustChains(X509CertificateTrustChains0)}
                                ${admin_partials.nav_pager("%s/x509-certificate-trusted/%s/x509-certificate-trust-chain-0" % (admin_prefix, X509CertificateTrusted.id))}
                            % else:
                                No known X509CertificateTrustChains.
                            % endif
                        </td>
                    </tr>
                </tbody>
                <tbody>
                    <tr>
                        <th>X509CertificateTrustChainsN</th>
                        <td>
                            % if X509CertificateTrustChainsN:
                                ${admin_partials.table_X509CertificateTrustChains(X509CertificateTrustChainsN)}
                                ${admin_partials.nav_pager("%s/x509-certificate-trusted/%s/x509-certificate-trust-chain-n" % (admin_prefix, X509CertificateTrusted.id))}
                            % else:
                                No known X509CertificateTrustChains.
                            % endif
                        </td>
                    </tr>
                </tbody>
                <tbody>
                    <tr>
                        <th>X509Certificates</th>
                        <td>
                            % if X509Certificates:
                                ${admin_partials.table_X509Certificates(X509Certificates, show_domains=True)}
                                ${admin_partials.nav_pager("%s/x509-certificate-trusted/%s/x509-certificates" % (admin_prefix, X509CertificateTrusted.id))}
                            % else:
                                No known X509Certificates.
                            % endif
                        </td>
                    </tr>
                </tbody>
                <tbody>
                    <tr>
                        <th>X509Certificates - Alt</th>
                        <td>
                            % if X509Certificates_Alt:
                                ${admin_partials.table_X509Certificates(X509Certificates_Alt, show_domains=True)}
                                ${admin_partials.nav_pager("%s/x509-certificate-trusted/%s/x509-certificates-alt" % (admin_prefix, X509CertificateTrusted.id))}
                            % else:
                                No known X509Certificates.
                            % endif
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

</%block>
