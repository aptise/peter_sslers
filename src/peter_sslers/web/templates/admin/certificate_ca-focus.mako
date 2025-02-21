<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificate-cas">CertificateCAs</a></li>
        <li class="active">Focus [${CertificateCA.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>CertificateCA - Focus</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/certificate-ca/${CertificateCA.id}.json" class="btn btn-xs btn-info">
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
                                ${CertificateCA.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>display_name</th>
                        <td><samp>${CertificateCA.display_name or ""}</samp></td>
                    </tr>
                    <tr>
                        <th>is_trusted_root</th>
                        <td>
                            % if CertificateCA.is_trusted_root:
                                <label class="label label-success">Y</label>
                            % endif
                            % if CertificateCA.to_root_store_versions:
                                <ul class="list list-unstyled">
                                    % for to_root_store_version in CertificateCA.to_root_store_versions:
                                        <li>
                                            <a href="${admin_prefix}/root-store-version/${to_root_store_version.root_store_version.id}"
                                               class="label label-info"
                                            >
                                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                RootStoreVersion-${to_root_store_version.root_store_version.id}
                                            </a>
                                            <code>${to_root_store_version.root_store_version.root_store.name}</code>&nbsp;
                                            <code>${to_root_store_version.root_store_version.version_string}</code>
                                        </li>
                                    % endfor
                                </ul>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>timestamp_not_before</th>
                        <td><timestamp>${CertificateCA.timestamp_not_before or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>timestamp_not_after</th>
                        <td><timestamp>${CertificateCA.timestamp_not_after or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>timestamp_created</th>
                        <td><timestamp>${CertificateCA.timestamp_created or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>count_active_certificates</th>
                        <td><span class="badge">${CertificateCA.count_active_certificates or ''}</span></td>
                    </tr>
                    <tr>
                        <th>fingerprint_sha1</th>
                        <td>
                            <code>${CertificateCA.fingerprint_sha1_preview|n}</code><br/>
                            <code>${CertificateCA.fingerprint_sha1}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>cert_pem_md5</th>
                        <td><code>${CertificateCA.cert_pem_md5}</code></td>
                    </tr>
                    <tr>
                        <th>spki_sha256</th>
                        <td>
                            <code>${CertificateCA.spki_sha256}</code>
                            ${CertificateCA.button_search_spki|n} <i>[Search for Compatible]</i>
                        </td>
                    </tr>
                    <tr>
                        <th>cert_issuer_uri</th>
                        <td><code>${CertificateCA.cert_issuer_uri or ''}</code></td>
                    </tr>
                    <tr>
                        <th>cert_authority_key_identifier</th>
                        <td><code>${CertificateCA.cert_authority_key_identifier or ''}</code></td>
                    </tr>
                    <tr>
                        <th>download</th>
                        <td>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-ca/${CertificateCA.id}/cert.pem.txt">cert.pem.txt (PEM)</a>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-ca/${CertificateCA.id}/cert.pem">cert.pem (PEM)</a>

                            <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-ca/${CertificateCA.id}/cert.cer">cert.cer (DER)</a>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-ca/${CertificateCA.id}/cert.crt">cert.crt (DER)</a>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-ca/${CertificateCA.id}/cert.der">cert.der (DER)</a>
                        </td>
                    </tr>
                    <tr>
                        <th>cert_subject</th>
                        <td><samp>${CertificateCA.cert_subject}</samp>
                            </td>
                    </tr>
                    <tr>
                        <th>cert_issuer</th>
                        <td><samp>${CertificateCA.cert_issuer}</samp>
                            </td>
                    </tr>
                    <tr>
                        <th>Reconciliation</th>
                        <td>
                            <table class="table table-striped table-condensed">
                                <tr>
                                    <th>cert_issuer__reconciled</th>
                                    <td>Has a reconciliation been attempted?<br/> ${CertificateCA.cert_issuer__reconciled or ""}</td>
                                </tr>
                                <tr>
                                    <th>cert_issuer__certificate_ca_id</th>
                                    <td>via reconciliation:
                                        % if CertificateCA.cert_issuer__certificate_ca_id:
                                            ${CertificateCA.cert_issuer__certificate_ca.button_view|n}
                                        % endif
                                    </td>
                                </tr>
                                <tr>
                                    <th>reconciled_uris</th>
                                    <td>This certificate was served by the following urls during reconciliation processes: ${CertificateCA.reconciled_uris or ""}</td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    ${admin_partials.table_tr_OperationsEventCreated(CertificateCA)}
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
                        <th>CertificateCAChains0</th>
                        <td>
                            % if CertificateCAChains0:
                                ${admin_partials.table_CertificateCAChains(CertificateCAChains0)}
                                ${admin_partials.nav_pager("%s/certificate-ca/%s/certificate-ca-chains-0" % (admin_prefix, CertificateCA.id))}
                            % else:
                                No known CertificateCAChains.
                            % endif
                        </td>
                    </tr>
                </tbody>
                <tbody>
                    <tr>
                        <th>CertificateCAChainsN</th>
                        <td>
                            % if CertificateCAChainsN:
                                ${admin_partials.table_CertificateCAChains(CertificateCAChainsN)}
                                ${admin_partials.nav_pager("%s/certificate-ca/%s/certificate-ca-chains-n" % (admin_prefix, CertificateCA.id))}
                            % else:
                                No known CertificateCAChains.
                            % endif
                        </td>
                    </tr>
                </tbody>
                <tbody>
                    <tr>
                        <th>CertificateSigneds</th>
                        <td>
                            % if CertificateSigneds:
                                ${admin_partials.table_CertificateSigneds(CertificateSigneds, show_domains=True)}
                                ${admin_partials.nav_pager("%s/certificate-ca/%s/certificate-signeds" % (admin_prefix, CertificateCA.id))}
                            % else:
                                No known CertificateSigneds.
                            % endif
                        </td>
                    </tr>
                </tbody>
                <tbody>
                    <tr>
                        <th>CertificateSigneds - Alt</th>
                        <td>
                            % if CertificateSigneds_Alt:
                                ${admin_partials.table_CertificateSigneds(CertificateSigneds_Alt, show_domains=True)}
                                ${admin_partials.nav_pager("%s/certificate-ca/%s/certificate-signeds-alt" % (admin_prefix, CertificateCA.id))}
                            % else:
                                No known CertificateSigneds.
                            % endif
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

</%block>
