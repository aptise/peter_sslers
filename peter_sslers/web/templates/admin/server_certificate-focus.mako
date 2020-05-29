<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%! enable_search = False %>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/server-certificates">ServerCertificates</a></li>
        <li class="active">Focus [${ServerCertificate.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>ServerCertificate - Focus</h2>
    ${admin_partials.standard_error_display()}

    <%
        operation = request.params.get('operation', None)
    %>
    % if operation in ('nginx_cache_expire', ):
        <%
            result = request.params.get('result', None)
            if result != 'success':
                result = 'result'
            event_id = request.params.get('event.id', None)
        %>
        <div class="alert alert-${result}">
            <p>
                Result of <b>${operation}</b>: ${result}
            </p>
            % if event_id:
                <p>
                    Event ID:
                    <a href="${admin_prefix}/operations/log/item/${event_id}"
                       class="label label-info"
                    >
                        <span class="glyphicon glyphicon-list-alt" aria-hidden="true"></span>
                        ${event_id}
                    </a>
                </p>
            % endif
        </div>
    % endif
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/server-certificate/${ServerCertificate.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        ${admin_partials.handle_querystring_result()}
        <div class="col-sm-9">
            <table class="table">
                <thead>
                    <tr>
                        <th colspan="2">Core Details</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <th>id</th>
                        <td>
                            <span class="label label-default">
                                ${ServerCertificate.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>is_active</th>
                        <td>
                            <span class="label label-${'success' if ServerCertificate.is_active else 'warning'}">
                                ${'Active' if ServerCertificate.is_active else 'inactive'}
                            </span>
                            &nbsp;
                            % if ServerCertificate.is_active:
                                <form action="${admin_prefix}/server-certificate/${ServerCertificate.id}/mark" method="POST" style="display:inline;">
                                    <input type="hidden" name="action" value="inactive"/>
                                    <button class="btn btn-xs btn-warning" type="submit">
                                        <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                        deactivate
                                    </button>
                                </form>
                                &nbsp;
                                <form action="${admin_prefix}/server-certificate/${ServerCertificate.id}/mark" method="POST" style="display:inline;">
                                    <input type="hidden" name="action" value="revoked"/>
                                    <button class="btn btn-xs btn-danger" type="submit">
                                        <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                        mark revoked
                                    </button>
                                </form>
                            % else:
                                ## show a reason
                                % if ServerCertificate.is_revoked:
                                    Reason: <code>revoked</code>
                                % elif ServerCertificate.is_deactivated:
                                    Reason: <code>deactivated</code>
                                % endif
                                % if not ServerCertificate.is_deactivated:
                                    &nbsp;
                                    Actions:
                                    ## % if ServerCertificate.is_revoked:
                                    ##     <form action="${admin_prefix}/server-certificate/${ServerCertificate.id}/mark" method="POST" style="display:inline;">
                                    ##         <input type="hidden" name="action" value="unrevoke"/>
                                    ##         <button class="btn btn-xs btn-warning" type="submit">
                                    ##             <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                    ##             unrevoke
                                    ##         </button>
                                    ##     </form>
                                    ## % endif
                                    % if not ServerCertificate.is_revoked:
                                        <form action="${admin_prefix}/server-certificate/${ServerCertificate.id}/mark" method="POST" style="display:inline;">
                                            <input type="hidden" name="action" value="active"/>
                                            <button class="btn btn-xs btn-success" type="submit">
                                                <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                                activate
                                            </button>
                                        </form>
                                        <form action="${admin_prefix}/server-certificate/${ServerCertificate.id}/mark" method="POST" style="display:inline;">
                                            <input type="hidden" name="action" value="revoked"/>
                                            <button class="btn btn-xs btn-danger" type="submit">
                                                <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                                mark revoked
                                            </button>
                                        </form>
                                    % endif
                                % endif
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>Renewal Strategy</th>
                        <td>
                            <code>${ServerCertificate.renewals_managed_by}</code>
                            % if ServerCertificate.renewals_managed_by == "AcmeOrder":
                                % if ServerCertificate.acme_order.is_auto_renew:
                                    <span class="label label-success">auto-renew enabled</span>
                                % else:
                                    <span class="label label-danger">auto-renew disabled</span>
                                % endif
                                <a class="label label-info" href="${admin_prefix}/acme-order/${ServerCertificate.acme_order.id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeOrder-${ServerCertificate.acme_order.id}
                                </a>
                            % elif ServerCertificate.renewals_managed_by == "ServerCertificate":
                                % if ServerCertificate.is_auto_renew:
                                    <span class="label label-success">auto-renew enabled</span>
                                    <form action="${admin_prefix}/server-certificate/${ServerCertificate.id}/mark" method="POST" style="display:inline;" id="server_certificate-mark-autorenew-off">
                                        <input type="hidden" name="action" value="renew_manual"/>
                                        <button class="btn btn-xs btn-danger" type="submit" name="submit" value="submit">
                                            <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                            deactivate auto-renew
                                        </button>
                                    </form>
                                % else:
                                    <span class="label label-danger">auto-renew disabled</span>
                                    <form action="${admin_prefix}/server-certificate/${ServerCertificate.id}/mark" method="POST" style="display:inline;" id="server_certificate-mark-autorenew-on">
                                        <input type="hidden" name="action" value="renew_auto"/>
                                        <button class="btn btn-xs btn-success" type="submit" name="submit" value="submit">
                                            <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                            activate auto-renew
                                        </button>
                                    </form>
                                % endif
                            % endif
                        </td>
                    </tr>


                    <tr>
                        <th>is_compromised_private_key</th>
                        <td>
                            % if ServerCertificate.is_compromised_private_key is not None:
                                <span class="label label-danger">
                                    COMPROMISED PRIVATE KEY
                                </span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>is_revoked_upstream</th>
                        <td>
                            % if ServerCertificate.timestamp_revoked_upstream is not None:
                                <span class="label label-danger">
                                    revoked upstream @ ${ServerCertificate.timestamp_revoked_upstream_isoformat}
                                </span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>is_single_domain_cert</th>
                        <td>
                            % if ServerCertificate.is_single_domain_cert is True:
                                <span class="label label-default">
                                    single domain certificate
                                </span>
                            % elif ServerCertificate.is_single_domain_cert is False:
                                <span class="label label-default">
                                    multiple domain certificate
                                </span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>timestamp_signed</th>
                        <td><timestamp>${ServerCertificate.timestamp_signed}</timestamp></td>
                    </tr>
                    <tr>
                        <th>timestamp_expires</th>
                        <td><timestamp>${ServerCertificate.timestamp_expires}</timestamp></td>
                    </tr>
                    <tr>
                        <th>expires in days</th>
                        <td>
                            <span class="label label-${ServerCertificate.expiring_days_label}">
                                ${ServerCertificate.expiring_days} days
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>CA Certificate</th>
                        <td>
                            <a class="label label-info" href="${admin_prefix}/ca-certificate/${ServerCertificate.ca_certificate_id__upchain}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                CACertificate-${ServerCertificate.ca_certificate_id__upchain}</a>
                            <br/>
                            <em>The ServerCertificate is signed by this CACertificate.</em>
                        </td>
                    </tr>
                    <tr>
                        <th>PrivateKey</th>
                        <td>
                            % if not ServerCertificate.private_key.is_compromised:
                                <a class="label label-info" href="${admin_prefix}/private-key/${ServerCertificate.private_key_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    PrivateKey-${ServerCertificate.private_key_id}</a>
                            % else:
                                <a class="label label-danger" href="${admin_prefix}/private-key/${ServerCertificate.private_key_id}">
                                    <span class="glyphicon glyphicon-warning-sign" aria-hidden="true"></span>
                                    PrivateKey-${ServerCertificate.private_key_id}</a>
                            % endif
                            <br/>
                            <em>The ServerCertificate is signed by this PrivateKey.</em>
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeAccount</th>
                        <td>
                            % if ServerCertificate.acme_order and ServerCertificate.acme_order.acme_account_id:
                                <a class="label label-info" href="${admin_prefix}/acme-account/${ServerCertificate.acme_order.acme_account_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeAccount-${ServerCertificate.acme_order.acme_account_id}</a>
                                <br/>
                                <em>The ServerCertificate belongs to this AcmeAccount.</em>
                            % else:
                                <em>The ServerCertificate is not associated with an AcmeAccount.</em>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeOrder</th>
                        <td>
                            % if ServerCertificate.acme_order:
                                <a class="label label-info" href="${admin_prefix}/acme-order/${ServerCertificate.acme_order.id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeOrder-${ServerCertificate.acme_order.id}</a>
                                <br/>
                                <em>The ServerCertificate belongs to this AcmeOrder.</em>
                            % else:
                                <em>The ServerCertificate is not associated with an AcmeOrder.</em>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>CertificateRequest</th>
                        <td>
                            % if ServerCertificate.certificate_request_id:
                                <a class="label label-info" href="${admin_prefix}/certificate-request/${ServerCertificate.certificate_request_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    CertificateRequest-${ServerCertificate.certificate_request_id}</a>
                                <br/>
                                <em>The ServerCertificate is the result of this CertificateSigningRequest.</em>
                            % else:
                                <em>The ServerCertificate is not associated with a CertificateSigningRequest.</em>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>UniqueFQDNSet</th>
                        <td>
                            <a  class="label label-info"
                                href="${admin_prefix}/unique-fqdn-set/${ServerCertificate.unique_fqdn_set_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                UniqueFQDNSet-${ServerCertificate.unique_fqdn_set_id}
                            </a>
                            <br/>
                            <em>The ServerCertificate covers the domains in this UniqueFQDNSet.</em>
                            <br/>
                            <%
                                latest_certificate = ServerCertificate.unique_fqdn_set.latest_certificate
                                latest_active_certificate = ServerCertificate.unique_fqdn_set.latest_active_certificate
                                latest_certificate_same = True if latest_certificate and latest_certificate.id == ServerCertificate.id else False
                                latest_active_certificate_same = True if latest_active_certificate and latest_active_certificate.id == ServerCertificate.id else False
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
                                                        href="${admin_prefix}/server-certificate/${latest_certificate.id}"
                                                        >
                                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                        ServerCertificate-${latest_certificate.id}
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
                                                        href="${admin_prefix}/server-certificate/${latest_active_certificate.id}"
                                                        >
                                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                        ServerCertificate-${latest_active_certificate.id}
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
                    ${admin_partials.table_tr_OperationsEventCreated(ServerCertificate)}
                    <tr>
                        <th>cert_pem_md5</th>
                        <td><code>${ServerCertificate.cert_pem_md5}</code></td>
                    </tr>
                    <tr>
                        <th>cert_pem_modulus_md5</th>
                        <td>
                            <code>${ServerCertificate.cert_pem_modulus_md5}</code>
                            <a
                                class="btn btn-xs btn-info"
                                href="${admin_prefix}/search?${ServerCertificate.cert_pem_modulus_search}"
                            >
                                <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                            </a>
                        </td>
                    </tr>
                    <tr>
                        <th>cert_pem</th>
                        <td>
                            ## <textarea class="form-control">${ServerCertificate.key_pem}</textarea>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/server-certificate/${ServerCertificate.id}/cert.pem">
                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                cert.pem</a>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/server-certificate/${ServerCertificate.id}/cert.pem.txt">
                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                cert.pem.txt</a>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/server-certificate/${ServerCertificate.id}/cert.crt">
                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                cert.crt (der)</a>
                        </td>
                    </tr>
                    <tr>
                        <th>json payload</th>
                        <td>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/server-certificate/${ServerCertificate.id}/config.json">
                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                config.json</a><br/>
                            <em>designed for downstream http config</em>
                        </td>
                    </tr>
                    % if request.registry.settings["app_settings"]['enable_nginx']:
                        <tr>
                            <th>Nginx cache</th>
                            <td>
                                <span class="btn-group">
                                    <a  class="btn btn-xs btn-primary"
                                        href="${admin_prefix}/server-certificate/${ServerCertificate.id}/nginx-cache-expire"
                                    >
                                        <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                        nginx-cache-expire</a>
                                    <a  class="btn btn-xs btn-primary"
                                        href="${admin_prefix}/server-certificate/${ServerCertificate.id}/nginx-cache-expire.json"
                                        target="_blank"
                                    >
                                        <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                        .json</a>
                                </span>
                            </td>
                        </tr>
                    % endif

                    <tr>
                        <th>Renew?</th>
                        <td>
                            &nbsp;
                            <a  class="btn btn-xs btn-primary"
                                href="${admin_prefix}/queue-certificate/new/structured?queue_source=ServerCertificate&server_certificate=${ServerCertificate.id}"
                                title="Queue a ServerCertificate"
                            >
                                <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                Queue a Renewal
                            </a>

                        </td>
                    </tr>


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
                                            <a class="btn btn-xs btn-info" href="${admin_prefix}/server-certificate/${ServerCertificate.id}/chain.pem.txt">
                                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                chain.pem.txt</a>
                                            <a class="btn btn-xs btn-info" href="${admin_prefix}/server-certificate/${ServerCertificate.id}/chain.pem">
                                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                chain.pem</a>
                                            <a class="btn btn-xs btn-info" href="${admin_prefix}/server-certificate/${ServerCertificate.id}/chain.cer">
                                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                chain.cer (der)</a>
                                            <a class="btn btn-xs btn-info" href="${admin_prefix}/server-certificate/${ServerCertificate.id}/chain.crt">
                                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                chain.crt (der)</a>
                                            <a class="btn btn-xs btn-info" href="${admin_prefix}/server-certificate/${ServerCertificate.id}/chain.der">
                                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                chain.der (der)</a>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td>fullchain (cert+upstream chain)</td>
                                        <td>
                                            <a class="btn btn-xs btn-info" href="${admin_prefix}/server-certificate/${ServerCertificate.id}/fullchain.pem.txt">
                                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                fullchain.pem.txt</a>
                                            <a class="btn btn-xs btn-info" href="${admin_prefix}/server-certificate/${ServerCertificate.id}/fullchain.pem">
                                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                fullchain.pem</a>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td>privatekey</td>
                                        <td>
                                            <a class="btn btn-xs btn-info" href="${admin_prefix}/server-certificate/${ServerCertificate.id}/privkey.pem.txt">
                                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                privkey.pem.txt</a>
                                            <a class="btn btn-xs btn-info" href="${admin_prefix}/server-certificate/${ServerCertificate.id}/privkey.pem">
                                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                privkey.pem</a>
                                            <a class="btn btn-xs btn-info" href="${admin_prefix}/server-certificate/${ServerCertificate.id}/privkey.key">
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
                            <code>${ServerCertificate.cert_subject_hash}</code>
                            <a
                                class="btn btn-xs btn-info"
                                href="${admin_prefix}/search?${ServerCertificate.cert_subject_hash_search}"
                            >
                                <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                            </a>
                            <br/>
                            <samp>${ServerCertificate.cert_subject}</samp>
                        </td>
                    </tr>
                    <tr>
                        <th>cert_issuer</th>
                        <td>
                            <code>${ServerCertificate.cert_issuer_hash}</code>
                            <a
                                class="btn btn-xs btn-info"
                                href="${admin_prefix}/search?${ServerCertificate.cert_issuer_hash_search}"
                            >
                                <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                            </a>
                            <br/>

                            <samp>${ServerCertificate.cert_issuer}</samp>
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
                                    % for to_d in ServerCertificate.unique_fqdn_set.to_domains:
                                        <tr>
                                            <td>
                                                <a class="label label-info" href="${admin_prefix}/domain/${to_d.domain.id}">
                                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                    Domain-${to_d.domain.id}</a>
                                            </td>
                                            <td>
                                                <code>${to_d.domain.domain_name}</code>
                                            </td>
                                            <td>
                                                % if ServerCertificate.id in (to_d.domain.server_certificate_id__latest_single, to_d.domain.server_certificate_id__latest_multi):
                                                    <span class="label label-default">
                                                        % if ServerCertificate.id == to_d.domain.server_certificate_id__latest_single:
                                                            single
                                                        % endif
                                                        % if ServerCertificate.id == to_d.domain.server_certificate_id__latest_multi:
                                                            multi
                                                        % endif
                                                    </span>
                                                % endif
                                            </td>
                                        </tr>
                                    % endfor
                                </tbody>
                            </table>
                        </td>
                    </tr>
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
                        <th>QueueCertificates</th>
                        <td>
                            ${admin_partials.table_QueueCertificates(ServerCertificate.queue_certificates__5, perspective="ServerCertificate")}
                            % if ServerCertificate.queue_certificates__5:
                                ${admin_partials.nav_pager("%s/server-certificate/%s/queue-certificates" % (admin_prefix, ServerCertificate.id))}
                            % endif
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</%block>
