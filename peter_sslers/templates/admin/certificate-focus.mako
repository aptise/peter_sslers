<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%! enable_search = False %>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificates">Certificates</a></li>
        <li class="active">Focus [${SslServerCertificate.id}]</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Certificate - Focus</h2>

    ${admin_partials.standard_error_display()}

</%block>


<%block name="content_main">

    <table class="table">
        <tr>
            <th>id</th>
            <td>
                <span class="label label-default">
                    ${SslServerCertificate.id}
                </span>
            </td>
        </tr>
        <tr>
            <th>is_active</th>
            <td>
                <span class="label label-${'success' if SslServerCertificate.is_active else 'warning'}">
                    ${'Active' if SslServerCertificate.is_active else 'inactive'}
                </span>
                % if SslServerCertificate.is_active:
                    &nbsp;
                    <a  class="label label-warning"
                        href="${admin_prefix}/certificate/${SslServerCertificate.id}/mark?action=inactive"
                    >
                        <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                        deactivate
                    </a>
                    &nbsp;
                    <a  class="label label-warning"
                        href="${admin_prefix}/certificate/${SslServerCertificate.id}/mark?action=revoked"
                    >
                        <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                        mark revoked
                    </a>
                % else:
                    % if SslServerCertificate.is_deactivated or SslServerCertificate.is_revoked:
                        &nbsp;
                        reason:
                        % if SslServerCertificate.is_deactivated:
                            &nbsp;
                            <span class="label label-warning">inactive</span>
                        % endif
                        % if SslServerCertificate.is_revoked:
                            &nbsp;
                            <span class="label label-warning">revoked</span>
                        % endif

                        % if not SslServerCertificate.is_revoked:
                            <a  class="label label-success"
                                href="${admin_prefix}/certificate/${SslServerCertificate.id}/mark?action=active"
                            >
                                <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                activate
                            </a>
                        % endif

                    % endif
                % endif
            </td>
        </tr>
        <tr>
            <th>is_single_domain_cert</th>
            <td>
                % if SslServerCertificate.is_single_domain_cert is True:
                    <span class="label label-default">
                        single domain certificate
                    </span>
                % elif SslServerCertificate.is_single_domain_cert is False:
                    <span class="label label-default">
                        multiple domain certificate
                    </span>
                % endif
            </td>
        </tr>
        <tr>
            <th>timestamp_signed</th>
            <td><timestamp>${SslServerCertificate.timestamp_signed}</timestamp></td>
        </tr>
        <tr>
            <th>timestamp_expires</th>
            <td><timestamp>${SslServerCertificate.timestamp_expires}</timestamp></td>
        </tr>
        <tr>
            <th>expires in days</th>
            <td>
                <span class="label label-${SslServerCertificate.expiring_days_label}">
                    ${SslServerCertificate.expiring_days} days
                </span>
                &nbsp;
                <a  href="${admin_prefix}/certificate/${SslServerCertificate.id}/renew/custom"
                    span class="label label-primary"
                >
                    <span class="glyphicon glyphicon-wrench" aria-hidden="true"></span>
                    Custom Renewal
                </form>
            </td>
        </tr>
        <tr>
            <th>ssl_ca_certificate_id__upchain</th>
            <td>
                <a class="label label-info" href="${admin_prefix}/ca-certificate/${SslServerCertificate.ssl_ca_certificate_id__upchain}">
                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                    ${SslServerCertificate.ssl_ca_certificate_id__upchain}</a>
            </td>
        </tr>
        <tr>
            <th>ssl_private_key_id__signed_by</th>
            <td>
                % if not SslServerCertificate.private_key.is_compromised:
                    <a class="label label-info" href="${admin_prefix}/private-key/${SslServerCertificate.ssl_private_key_id__signed_by}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        ${SslServerCertificate.ssl_private_key_id__signed_by}</a>
                % else:
                    <a class="label label-danger" href="${admin_prefix}/private-key/${SslServerCertificate.ssl_private_key_id__signed_by}">
                        <span class="glyphicon glyphicon-warning-sign" aria-hidden="true"></span>
                        ${SslServerCertificate.ssl_private_key_id__signed_by}</a>
                % endif
            </td>
        </tr>
        <tr>
            <th>ssl_certificate_request_id</th>
            <td>
                % if SslServerCertificate.ssl_certificate_request_id:
                    <a class="label label-info" href="${admin_prefix}/certificate-request/${SslServerCertificate.ssl_certificate_request_id}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        ${SslServerCertificate.ssl_certificate_request_id}</a>
                % endif
            </td>
        </tr>
        <tr>
            <th>unique fqdn set</th>
            <td>
                <a  class="label label-info"
                    href="${admin_prefix}/unique-fqdn-set/${SslServerCertificate.ssl_unique_fqdn_set_id}"
                    >
                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                    ${SslServerCertificate.ssl_unique_fqdn_set_id}
                </a>
                <%
                    latest_certificate = SslServerCertificate.unique_fqdn_set.latest_certificate
                    latest_active_certificate = SslServerCertificate.unique_fqdn_set.latest_active_certificate
                    latest_certificate_same = True if latest_certificate and latest_certificate.id == SslServerCertificate.id else False
                    latest_active_certificate_same = True if latest_active_certificate and latest_active_certificate.id == SslServerCertificate.id else False
                %>
                <table class="table table-striped table-condensed">
                    <thead>
                        <tr>
                            <th>Cert</th>
                            <th>id</th>
                            <th>is active?</th>
                            <th>days left</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <th>Latest Certificate</th>
                            % if latest_certificate:
                                <td>
                                    % if latest_certificate_same:
                                        <span class="label label-default">${latest_certificate.id}</span>
                                    % else:
                                        <a  class="label label-info"
                                            href="${admin_prefix}/certificate/${latest_certificate.id}"
                                            >
                                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                            ${latest_certificate.id}
                                        </a>
                                    % endif
                                </td>
                                <td>
                                    <span class="label label-${'success' if latest_certificate.is_active else 'warning'}">
                                        ${'Active' if latest_certificate.is_active else 'inactive'}
                                    </span>
                                </td>
                                <td>
                                    <span class="label label-${latest_certificate.expiring_days_label}">
                                        ${latest_certificate.expiring_days} days
                                    </span>
                                </td>
                            % endif
                        </tr>
                        <tr>
                            <th>Latest Active Certificate</th>
                            % if latest_active_certificate:
                                <td>
                                    % if latest_active_certificate_same:
                                        <span class="label label-default">${latest_active_certificate.id}</span>
                                    % else:
                                        <a  class="label label-info"
                                            href="${admin_prefix}/certificate/${latest_active_certificate.id}"
                                            >
                                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                            ${latest_active_certificate.id}
                                        </a>
                                    % endif
                                </td>
                                <td>
                                    <span class="label label-${'success' if latest_active_certificate.is_active else 'warning'}">
                                        ${'Active' if latest_active_certificate.is_active else 'inactive'}
                                    </span>
                                </td>
                                <td>
                                    <span class="label label-${latest_active_certificate.expiring_days_label}">
                                        ${latest_active_certificate.expiring_days} days
                                    </span>
                                </td>
                            % endif
                        </tr>
                    </tbody>
                </table>
            </td>
        </tr>
        ${admin_partials.table_tr_event_created(SslServerCertificate.ssl_operations_event_id__created)}
        <tr>
            <th>is renewal?</th>
            <td>
                % if SslServerCertificate.ssl_server_certificate_id__renewal_of:
                    <span class="label label-success">Yes</span>&nbsp;
                    <a class="label label-info" href="${admin_prefix}/certificate/${SslServerCertificate.ssl_server_certificate_id__renewal_of}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        ${SslServerCertificate.ssl_server_certificate_id__renewal_of}</a>
                % else:
                    <span class="label label-default">No</span>
                % endif
            </td>
        </tr>
        <tr>
            <th>cert_pem_md5</th>
            <td><code>${SslServerCertificate.cert_pem_md5}</code></td>
        </tr>
        <tr>
            <th>cert_pem_modulus_md5</th>
            <td>
                <code>${SslServerCertificate.cert_pem_modulus_md5}</code>
                <a
                    class="btn btn-xs btn-info"
                    href="${admin_prefix}/search?${SslServerCertificate.cert_pem_modulus_search}"
                >
                    <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                </a>
            </td>
        </tr>
        <tr>
            <th>cert_pem</th>
            <td>
                ## <textarea class="form-control">${SslServerCertificate.key_pem}</textarea>
                <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate/${SslServerCertificate.id}/cert.pem">
                    <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                    cert.pem</a>
                <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate/${SslServerCertificate.id}/cert.pem.txt">
                    <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                    cert.pem.txt</a>
                <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate/${SslServerCertificate.id}/cert.crt">
                    <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                    cert.crt (der)</a>
            </td>
        </tr>
        <tr>
            <th>json payload</th>
            <td>
                <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate/${SslServerCertificate.id}/config.json">
                    <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                    config.json</a><br/>
                <em>designed for downstream http config</em>
            </td>
        </tr>
        % if request.registry.settings['enable_nginx']:
            <tr>
                <th>nginx cache</th>
                <td>
                    <a  class="btn btn-xs btn-primary"
                        href="${admin_prefix}/certificate/${SslServerCertificate.id}/nginx-cache-expire"
                    >
                        <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                        nginx-cache-expire</a>
                    <a  class="btn btn-xs btn-primary"
                        href="${admin_prefix}/certificate/${SslServerCertificate.id}/nginx-cache-expire.json"
                    >
                        <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                        nginx-cache-expire.json</a>
                </td>
            </tr>
        % endif
        <tr>
            <th>related payloads</th>
            <td>
                <table class="table table-condensed">
                    <thead>
                        <tr>
                            <th>related</th>
                            <th>payloads</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>chain (upstream)</td>
                            <td>
                                <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate/${SslServerCertificate.id}/chain.pem.txt">
                                    <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                    chain.pem.txt</a>
                                <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate/${SslServerCertificate.id}/chain.pem">
                                    <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                    chain.pem</a>
                                <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate/${SslServerCertificate.id}/chain.cer">
                                    <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                    chain.cer (der)</a>
                                <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate/${SslServerCertificate.id}/chain.crt">
                                    <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                    chain.crt (der)</a>
                                <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate/${SslServerCertificate.id}/chain.der">
                                    <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                    chain.der (der)</a>
                            </td>
                        </tr>
                        <tr>
                            <td>fullchain (cert+upstream chain)</td>
                            <td>
                                <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate/${SslServerCertificate.id}/fullchain.pem.txt">
                                    <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                    fullchain.pem.txt</a>
                                <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate/${SslServerCertificate.id}/fullchain.pem">
                                    <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                    fullchain.pem</a>
                            </td>
                        </tr>
                        <tr>
                            <td>privatekey</td>
                            <td>
                                <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate/${SslServerCertificate.id}/privkey.pem.txt">
                                    <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                    privkey.pem.txt</a>
                                <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate/${SslServerCertificate.id}/privkey.pem">
                                    <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                    privkey.pem</a>
                                <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate/${SslServerCertificate.id}/privkey.key">
                                    <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                    privkey.key (der)</a>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </td>
        </tr>
        <tr>
            <th>cert_subject</th>
            <td>
                <code>${SslServerCertificate.cert_subject_hash}</code>
                <a
                    class="btn btn-xs btn-info"
                    href="${admin_prefix}/search?${SslServerCertificate.cert_subject_hash_search}"
                >
                    <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                </a>
                <br/>
                <samp>${SslServerCertificate.cert_subject}</samp>
            </td>
        </tr>
        <tr>
            <th>cert_issuer</th>
            <td>
                <code>${SslServerCertificate.cert_issuer_hash}</code>
                <a
                    class="btn btn-xs btn-info"
                    href="${admin_prefix}/search?${SslServerCertificate.cert_issuer_hash_search}"
                >
                    <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                </a>
                <br/>

                <samp>${SslServerCertificate.cert_issuer}</samp>
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
                        % for to_d in SslServerCertificate.unique_fqdn_set.to_domains:
                            <tr>
                                <td>
                                    <a class="label label-info" href="${admin_prefix}/domain/${to_d.domain.id}">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        ${to_d.domain.id}</a>
                                </td>
                                <td>
                                    ${to_d.domain.domain_name}
                                </td>
                                <td>
                                    % if SslServerCertificate.id in (to_d.domain.ssl_server_certificate_id__latest_single, to_d.domain.ssl_server_certificate_id__latest_multi):
                                        <span class="label label-default">
                                            % if SslServerCertificate.id == to_d.domain.ssl_server_certificate_id__latest_single:
                                                single
                                            % endif
                                            % if SslServerCertificate.id == to_d.domain.ssl_server_certificate_id__latest_multi:
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
        <tr>
            <th>renewal requests</th>
            <td>
                ${admin_partials.table_certificate_requests__list(SslServerCertificate.certificate_request__renewals, show_domains=False, show_certificate=True)}
            </td>
        </tr>
        <tr>
            <th>renewal queue</th>
            <td>
                ${admin_partials.table_queue_renewal__list(SslServerCertificate.queue_renewal, )}
            </td>
        </tr>
    </table>

</%block>
