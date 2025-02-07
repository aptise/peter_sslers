<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%! enable_search = False %>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificate-signeds">CertificateSigneds</a></li>
        <li class="active">Focus [${CertificateSigned.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>CertificateSigned - Focus</h2>
    ${admin_partials.handle_querystring_result()}

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
        <a href="${admin_prefix}/certificate-signed/${CertificateSigned.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
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
                                ${CertificateSigned.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>is_active</th>
                        <td>
                            <span class="label label-${'success' if CertificateSigned.is_active else 'warning'}">
                                ${'Active' if CertificateSigned.is_active else 'inactive'}
                            </span>
                            &nbsp;
                            % if CertificateSigned.is_active:
                                <form 
                                    action="${admin_prefix}/certificate-signed/${CertificateSigned.id}/mark" 
                                    method="POST" 
                                    style="display:inline;" 
                                    id="form-certificate_signed-mark-inactive"
                                >
                                    <input type="hidden" name="action" value="inactive"/>
                                    <button class="btn btn-xs btn-warning" type="submit">
                                        <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                        deactivate
                                    </button>
                                </form>
                                &nbsp;
                                <form
                                    action="${admin_prefix}/certificate-signed/${CertificateSigned.id}/mark" 
                                    method="POST" 
                                    style="display:inline;" 
                                    id="form-certificate_signed-mark-revoked"
                                >
                                    <input type="hidden" name="action" value="revoked"/>
                                    <button class="btn btn-xs btn-danger" type="submit">
                                        <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                        mark revoked
                                    </button>
                                </form>
                            % else:
                                ## show a reason
                                % if CertificateSigned.is_revoked:
                                    Reason: <code>revoked</code>
                                % elif CertificateSigned.is_deactivated:
                                    Reason: <code>deactivated</code>
                                % endif
                                % if not CertificateSigned.is_deactivated:
                                    &nbsp;
                                    Actions:
                                    ## % if CertificateSigned.is_revoked:
                                    ##     <form action="${admin_prefix}/certificate-signed/${CertificateSigned.id}/mark" method="POST" style="display:inline;">
                                    ##         <input type="hidden" name="action" value="unrevoke"/>
                                    ##         <button class="btn btn-xs btn-warning" type="submit">
                                    ##             <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                    ##             unrevoke
                                    ##         </button>
                                    ##     </form>
                                    ## % endif
                                    % if not CertificateSigned.is_revoked:
                                        <form
                                            action="${admin_prefix}/certificate-signed/${CertificateSigned.id}/mark"
                                            method="POST"
                                            style="display:inline;"
                                            id="form-certificate_signed-mark-active"
                                        >
                                            <input type="hidden" name="action" value="active"/>
                                            <button class="btn btn-xs btn-success" type="submit">
                                                <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                                activate
                                            </button>
                                        </form>
                                        <form
                                            action="${admin_prefix}/certificate-signed/${CertificateSigned.id}/mark"
                                            method="POST"
                                            style="display:inline;"
                                            id="form-certificate_signed-mark-revoked"
                                        >
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
                        <th>Renewals Managed by</th>
                        <td>
                            % if CertificateSigned.acme_order:
                                <a class="label label-info" href="${admin_prefix}/renewal-configuration/${CertificateSigned.acme_order.renewal_configuration_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    RenewalConfiguration-${CertificateSigned.acme_order.renewal_configuration_id}</a>
                                % if CertificateSigned.acme_order:
                                    % if CertificateSigned.acme_order.renewal_configuration.is_active:
                                        <span class="label label-success">auto-renew active</span>
                                    % else:
                                        <span class="label label-danger">auto-renew disabled</span>
                                    % endif
                                % endif
                            % else:
                                <span class="label label-warning">
                                    unavailable
                                </span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>Renew?</th>
                        <td>
                            % if CertificateSigned.acme_order:
                                <a  class="btn btn-xs btn-primary"
                                    href="${admin_prefix}/renewal-configuration/${CertificateSigned.acme_order.renewal_configuration.id}/new-order"
                                    title="Renew Quick"
                                >
                                    <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                    Renew Quick
                                </a>
                                <a  class="btn btn-xs btn-primary"
                                    href="${admin_prefix}/renewal-configuration/${CertificateSigned.acme_order.renewal_configuration.id}/new-configuration"
                                    title="Renew Custom"
                                >
                                    <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                    Renew Custom
                                </a>
                            % else:
                                <a  class="btn btn-xs btn-primary"
                                    href="${admin_prefix}/renewal-configuration/new?domain_names_http01=${CertificateSigned.domains_as_string}"
                                    title="Renew Custom"
                                >
                                    <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                    New RenewalConfiguration
                                </a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>is_compromised_private_key</th>
                        <td>
                            % if CertificateSigned.is_compromised_private_key is not None:
                                <span class="label label-danger">
                                    COMPROMISED PRIVATE KEY
                                </span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>is_revoked_upstream</th>
                        <td>
                            % if CertificateSigned.timestamp_revoked_upstream is not None:
                                <span class="label label-danger">
                                    revoked upstream @ ${CertificateSigned.timestamp_revoked_upstream_isoformat}
                                </span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>is_single_domain_cert</th>
                        <td>
                            % if CertificateSigned.is_single_domain_cert is True:
                                <span class="label label-default">
                                    single domain certificate
                                </span>
                            % elif CertificateSigned.is_single_domain_cert is False:
                                <span class="label label-default">
                                    multiple domain certificate
                                </span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>certificate_type</th>
                        <td><code>${CertificateSigned.certificate_type}</code></td>
                    </tr>
                    <tr>
                        <th>cert_serial</th>
                        <td><code>${CertificateSigned.cert_serial}</code></td>
                    </tr>
                    <tr>
                        <th>timestamp_not_before</th>
                        <td><timestamp>${CertificateSigned.timestamp_not_before}</timestamp></td>
                    </tr>
                    <tr>
                        <th>timestamp_not_after</th>
                        <td><timestamp>${CertificateSigned.timestamp_not_after}</timestamp></td>
                    </tr>
                    <tr>
                        <th>expires in days</th>
                        <td>
                            <span class="label label-${CertificateSigned.expiring_days_label}">
                                ${CertificateSigned.expiring_days} days
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>ARI</th>
                        <td>
                            <code>${CertificateSigned.ari_identifier}</code>
                            % if CertificateSigned.is_ari_supported:
                                <table>
                                    <tr>
                                        <th>Latest ARI Check</th>
                                        <td>
                                            % if CertificateSigned.ari_check__latest:
                                                <a class="label label-info" href="${admin_prefix}/ari-check/${CertificateSigned.ari_check__latest.id}">
                                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                    ${CertificateSigned.ari_check__latest.id}
                                                    ARI Check Latest
                                                </a>
                                                % if CertificateSigned.ari_check__latest.ari_check_status:
                                                    <table>
                                                        <tr>
                                                            <th>Timestamp</th>
                                                            <td><timestamp>${CertificateSigned.ari_check__latest.timestamp_created}</timestamp></td>
                                                        </tr>
                                                        <tr>
                                                            <th>Suggested Window Start</th>
                                                            <td><timestamp>${CertificateSigned.ari_check__latest.suggested_window_start}</timestamp></td>
                                                        </tr>
                                                        <tr>
                                                            <th>Suggested Window End</th>
                                                            <td><timestamp>${CertificateSigned.ari_check__latest.suggested_window_end}</timestamp></td>
                                                        </tr>
                                                        <tr>
                                                            <th>Retry After</th>
                                                            <td><timestamp>${CertificateSigned.ari_check__latest.timestamp_retry_after}</timestamp></td>
                                                        </tr>
                                                    </table>
                                                % else:
                                                    <p>ERROR on Last ARI Check</p>
                                                    <table>
                                                        <tr>
                                                            <th>Timestamp</th>
                                                            <td><timestamp>${CertificateSigned.ari_check__latest.timestamp_created}</timestamp></td>
                                                        </tr>
                                                        <tr>
                                                            <th>Response</th>
                                                            <td><code>${CertificateSigned.ari_check__latest.raw_response}</code></td>
                                                        </tr>
                                                    </table>
                                                % endif
                                            % endif
                                        </td>
                                    </tr>
                                    <tr>
                                        <th>Historical Checks</th>
                                        <td>
                                            <a class="label label-info" href="${admin_prefix}/certificate-signed/${CertificateSigned.id}/ari-check-history">
                                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                ARI Checks (History)
                                            </a>
                                        </td>
                                    </tr>
                                        <tr>
                                            <th>Manual Check</th>
                                            <td>
                                                % if CertificateSigned.is_ari_check_timely:
                                                    <form
                                                        action="${admin_prefix}/certificate-signed/${CertificateSigned.id}/ari-check" 
                                                        method="POST"
                                                        style="display:inline;"
                                                        id="form-certificate_signed-ari_check"
                                                    >
                                                        <button class="btn btn-xs btn-success" type="submit">
                                                            <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                                                            Check ARI
                                                        </button>
                                                    </form>
                                                % else:
                                                    Too Old for ARI Checks
                                                % endif
                                            </td>
                                        </tr>
                                </table>
                            % else:
                                ARI Does not seem possible for this Certificate
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>CertificateCAChains</th>
                        <td>
                            % if CertificateSigned.certificate_signed_chains:
                                <em>Available Signing Chains:</em>
                                <ul>
                                    % for _chain in CertificateSigned.certificate_signed_chains:
                                        <li>${_chain.certificate_ca_chain.button_view|n}</li>
                                    % endfor
                                </ul>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>CertificateCAs</th>
                        <td>
                            % if CertificateSigned.certificate_cas__upchain:
                                <p>The following CertificateCAs have signed this Certificate in a presented chain</p>
                                <ul class="list list-unstyled">
                                    % for cert_ca in CertificateSigned.certificate_cas__upchain:
                                        <li>
                                            ${cert_ca.button_view|n}
                                        </li>
                                    % endfor
                                </ul>
                                <p>Search for additional compatible CertificateCAs</p>
                                <ul class="list list-unstyled">
                                    % for cert_ca in CertificateSigned.certificate_cas__upchain:
                                        <li>
                                            <span class="label label-default">CertificateCA-${cert_ca.id}</span>
                                            ${cert_ca.button_search_spki|n}
                                        </li>
                                    % endfor
                                </ul>
                            % else:
                                <li><em>No CertificateCAs are currently associated to this Certificate.</em></li>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>PrivateKey</th>
                        <td>
                            % if not CertificateSigned.private_key.is_compromised:
                                <a class="label label-info" href="${admin_prefix}/private-key/${CertificateSigned.private_key_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    PrivateKey-${CertificateSigned.private_key_id}</a>
                            % else:
                                <a class="label label-danger" href="${admin_prefix}/private-key/${CertificateSigned.private_key_id}">
                                    <span class="glyphicon glyphicon-warning-sign" aria-hidden="true"></span>
                                    PrivateKey-${CertificateSigned.private_key_id}</a>
                            % endif
                            <br/>
                            <em>The CertificateSigned is signed by this PrivateKey.</em>
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeAccount</th>
                        <td>
                            % if CertificateSigned.acme_order and CertificateSigned.acme_order.acme_account_id:
                                <a class="label label-info" href="${admin_prefix}/acme-account/${CertificateSigned.acme_order.acme_account_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeAccount-${CertificateSigned.acme_order.acme_account_id}</a>
                                <br/>
                                <em>The CertificateSigned belongs to this AcmeAccount through an AcmeOrder.</em>
                            % else:
                                <em>The CertificateSigned is not associated with an AcmeAccount through an AcmeOrder.</em>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeOrder</th>
                        <td>
                            % if CertificateSigned.acme_order:
                                <a class="label label-info" href="${admin_prefix}/acme-order/${CertificateSigned.acme_order.id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeOrder-${CertificateSigned.acme_order.id}</a>
                                <br/>
                                <em>The CertificateSigned belongs to this AcmeOrder.</em>
                            % else:
                                <em>The CertificateSigned is not associated with an AcmeOrder.</em>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>CertificateRequest</th>
                        <td>
                            % if CertificateSigned.certificate_request_id:
                                <a class="label label-info" href="${admin_prefix}/certificate-request/${CertificateSigned.certificate_request_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    CertificateRequest-${CertificateSigned.certificate_request_id}</a>
                                <br/>
                                <em>The CertificateSigned is the result of this CertificateSigningRequest.</em>
                            % else:
                                <em>The CertificateSigned is not associated with a CertificateSigningRequest.</em>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>UniqueFQDNSet</th>
                        <td>
                            <a  class="label label-info"
                                href="${admin_prefix}/unique-fqdn-set/${CertificateSigned.unique_fqdn_set_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                UniqueFQDNSet-${CertificateSigned.unique_fqdn_set_id}
                            </a>
                            <br/>
                            <em>The CertificateSigned covers the domains in this UniqueFQDNSet.</em>
                            <br/>
                            <%
                                latest_certificate = CertificateSigned.unique_fqdn_set.latest_certificate
                                latest_active_certificate = CertificateSigned.unique_fqdn_set.latest_active_certificate
                                latest_certificate_same = True if latest_certificate and latest_certificate.id == CertificateSigned.id else False
                                latest_active_certificate_same = True if latest_active_certificate and latest_active_certificate.id == CertificateSigned.id else False
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
                                                        href="${admin_prefix}/certificate-signed/${latest_certificate.id}"
                                                        >
                                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                        CertificateSigned-${latest_certificate.id}
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
                                                        href="${admin_prefix}/certificate-signed/${latest_active_certificate.id}"
                                                        >
                                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                        CertificateSigned-${latest_active_certificate.id}
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
                    ${admin_partials.table_tr_OperationsEventCreated(CertificateSigned)}
                    <tr>
                        <th>fingerprint_sha1</th>
                        <td><code>${CertificateSigned.fingerprint_sha1}</code></td>
                    </tr>
                    <tr>
                        <th>cert_pem_md5</th>
                        <td><code>${CertificateSigned.cert_pem_md5}</code></td>
                    </tr>
                    <tr>
                        <th>spki_sha256</th>
                        <td>
                            <code>${CertificateSigned.spki_sha256}</code>
                            <a
                                class="btn btn-xs btn-info"
                                href="${admin_prefix}/search?${CertificateSigned.cert_spki_search}"
                            >
                                <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                            </a>
                        </td>
                    </tr>
                    <tr>
                        <th>cert_pem</th>
                        <td>
                            ## <textarea class="form-control">${CertificateSigned.key_pem}</textarea>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-signed/${CertificateSigned.id}/cert.pem">
                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                cert.pem (PEM)</a>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-signed/${CertificateSigned.id}/cert.pem.txt">
                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                cert.pem.txt (PEM)</a>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-signed/${CertificateSigned.id}/cert.crt">
                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                cert.crt (DER)</a>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-signed/${CertificateSigned.id}/cert.cer">
                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                cert.cer (DER)</a>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-signed/${CertificateSigned.id}/cert.der">
                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                cert.der (DER)</a>
                        </td>
                    </tr>
                    <tr>
                        <th>json payload</th>
                        <td>
                            <em>designed for http server config</em>
                            <hr/>

                            % if CertificateSigned.certificate_ca_chain__preferred:
                                <em>Default Chain</em><br/>
                                The Default Chain is ${CertificateSigned.certificate_ca_chain__preferred.button_view|n}
                                </p>

                                <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-signed/${CertificateSigned.id}/config.json">
                                    <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                    config.json</a><br/>
                                <hr/>
                            % endif

                            <em>all chains</em><br/>
                            <ul class="list list-unstyled">
                                % for _to_certificate_ca_chain in CertificateSigned.certificate_signed_chains:
                                    <li>
                                        <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-signed/${CertificateSigned.id}/via-certificate-ca-chain/${_to_certificate_ca_chain.certificate_ca_chain.id}/config.json">
                                            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                            CertificateCAChain-${_to_certificate_ca_chain.certificate_ca_chain.id}
                                            config.json</a>
                                    </li>
                                % endfor
                            </ul>

                        </td>
                    </tr>
                    <tr>
                        <th>zip payload</th>
                        <td>
                            <em>designed for http server config</em>
                            <hr/>

                            % if CertificateSigned.certificate_ca_chain__preferred:
                                <em>Default Chain</em><br/>
                                The Default Chain is ${CertificateSigned.certificate_ca_chain__preferred.button_view|n}
                                </p>

                                <a
                                    class="btn btn-xs btn-info"
                                    href="${admin_prefix}/certificate-signed/${CertificateSigned.id}/config.zip"
                                    data-certificate_ca_chain-id="${CertificateSigned.certificate_ca_chain__preferred.id}"
                                    data-certificate_ca_chain-certificate_ca_0-id="${CertificateSigned.certificate_ca_chain__preferred.certificate_ca_0.id}"
                                    data-certificate_ca_chain-certificate_ca_0-fingerprint_sha1="${CertificateSigned.certificate_ca_chain__preferred.certificate_ca_0.fingerprint_sha1}"
                                    data-certificate_ca_chain-certificate_ca_n-id="${CertificateSigned.certificate_ca_chain__preferred.certificate_ca_n.id}"
                                    data-certificate_ca_chain-certificate_ca_n-fingerprint_sha1="${CertificateSigned.certificate_ca_chain__preferred.certificate_ca_n.fingerprint_sha1}"
                                >
                                    <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                    config.zip</a><br/>
                            % endif
                            <hr/>

                            <em>all chains</em><br/>
                            <ul class="list list-unstyled">
                                % for _to_certificate_ca_chain in CertificateSigned.certificate_signed_chains:
                                    <li>
                                        <a
                                            class="btn btn-xs btn-info"
                                            href="${admin_prefix}/certificate-signed/${CertificateSigned.id}/via-certificate-ca-chain/${_to_certificate_ca_chain.certificate_ca_chain.id}/config.zip"
                                            data-certificate_ca_chain-id="${_to_certificate_ca_chain.certificate_ca_chain.id}"
                                            data-certificate_ca_chain-certificate_ca_0-id="${_to_certificate_ca_chain.certificate_ca_chain.certificate_ca_0.id}"
                                            data-certificate_ca_chain-certificate_ca_0-fingerprint_sha1="${_to_certificate_ca_chain.certificate_ca_chain.certificate_ca_0.fingerprint_sha1}"
                                            data-certificate_ca_chain-certificate_ca_n-id="${_to_certificate_ca_chain.certificate_ca_chain.certificate_ca_n.id}"
                                            data-certificate_ca_chain-certificate_ca_n-fingerprint_sha1="${_to_certificate_ca_chain.certificate_ca_chain.certificate_ca_n.fingerprint_sha1}"
                                        >
                                            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                            CertificateCAChain-${_to_certificate_ca_chain.certificate_ca_chain.id}
                                            config.zip</a>
                                    </li>
                                % endfor
                            </ul>

                        </td>
                    </tr>
                    % if request.registry.settings["app_settings"]['enable_nginx']:
                        <tr>
                            <th>Nginx cache</th>
                            <td>
                                <span class="btn-group">
                                    <form
                                        action="${admin_prefix}/certificate-signed/${CertificateSigned.id}/nginx-cache-expire"
                                        method="POST"
                                        id="form-certificate_signed-nginx_cache_expire"
                                    >
                                        <button class="btn btn-xs btn-primary" type="submit"  name="submit" value="submit">
                                            <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                            nginx-cache-expire
                                        </button>
                                    </form>
                                    <a  class="btn btn-xs btn-primary"
                                        href="${admin_prefix}/certificate-signed/${CertificateSigned.id}/nginx-cache-expire.json"
                                        target="_blank"
                                    >
                                        <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                        .json</a>
                                </span>
                            </td>
                        </tr>
                    % endif
                    <tr>
                        <th>related payloads</th>
                        <td>
                            <table class="table table-condensed table-striped">
                                <thead>
                                    <tr>
                                        <th>related</th>
                                        <th>payloads</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <th>privatekey</th>
                                        <td>
                                            <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-signed/${CertificateSigned.id}/privkey.pem.txt">
                                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                privkey.pem.txt</a>
                                            <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-signed/${CertificateSigned.id}/privkey.pem">
                                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                privkey.pem</a>
                                            <a class="btn btn-xs btn-info" href="${admin_prefix}/certificate-signed/${CertificateSigned.id}/privkey.key">
                                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                privkey.key (der)</a>
                                        </td>
                                    </tr>
                                    % if CertificateSigned.certificate_signed_chains:
                                        <tr>
                                            <th colspan="2">Certificate Chains</th>
                                        </tr>
                                        % for _to_certificate_ca_chain in CertificateSigned.certificate_signed_chains:
                                            <tr>
                                                <th>chain (upstream)
                                                    <span class="label label-default">CertificateCAChain-${_to_certificate_ca_chain.certificate_ca_chain_id}</span>
                                                </th>
                                                <td>
                                                    <a
                                                        class="btn btn-xs btn-info"
                                                        href="${admin_prefix}/certificate-signed/${CertificateSigned.id}/via-certificate-ca-chain/${_to_certificate_ca_chain.certificate_ca_chain_id}/chain.pem.txt"
                                                        data-certificate_ca_chain-id="${_to_certificate_ca_chain.certificate_ca_chain_id}"
                                                        data-certificate_ca_chain-certificate_ca_0-id="${_to_certificate_ca_chain.certificate_ca_chain.certificate_ca_0.id}"
                                                        data-certificate_ca_chain-certificate_ca_0-fingerprint_sha1="${_to_certificate_ca_chain.certificate_ca_chain.certificate_ca_0.fingerprint_sha1}"
                                                        data-certificate_ca_chain-certificate_ca_n-id="${_to_certificate_ca_chain.certificate_ca_chain.certificate_ca_n.id}"
                                                        data-certificate_ca_chain-certificate_ca_n-fingerprint_sha1="${_to_certificate_ca_chain.certificate_ca_chain.certificate_ca_n.fingerprint_sha1}"
                                                    >
                                                        <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                        chain.pem.txt</a>
                                                    <a
                                                        class="btn btn-xs btn-info"
                                                        href="${admin_prefix}/certificate-signed/${CertificateSigned.id}/via-certificate-ca-chain/${_to_certificate_ca_chain.certificate_ca_chain_id}/chain.pem"
                                                        data-certificate_ca_chain-id="${_to_certificate_ca_chain.certificate_ca_chain_id}"
                                                        data-certificate_ca_chain-certificate_ca_0-id="${_to_certificate_ca_chain.certificate_ca_chain.certificate_ca_0.id}"
                                                        data-certificate_ca_chain-certificate_ca_0-fingerprint_sha1="${_to_certificate_ca_chain.certificate_ca_chain.certificate_ca_0.fingerprint_sha1}"
                                                        data-certificate_ca_chain-certificate_ca_n-id="${_to_certificate_ca_chain.certificate_ca_chain.certificate_ca_n.id}"
                                                        data-certificate_ca_chain-certificate_ca_n-fingerprint_sha1="${_to_certificate_ca_chain.certificate_ca_chain.certificate_ca_n.fingerprint_sha1}"
                                                    >
                                                        <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                        chain.pem</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <th>fullchain (cert+upstream chain)
                                                    <span class="label label-default">CertificateCA-${_to_certificate_ca_chain.certificate_ca_chain_id}</span>
                                                </th>
                                                <td>
                                                    <a
                                                        class="btn btn-xs btn-info"
                                                        href="${admin_prefix}/certificate-signed/${CertificateSigned.id}/via-certificate-ca-chain/${_to_certificate_ca_chain.certificate_ca_chain_id}/fullchain.pem.txt"
                                                        data-certificate_ca_chain-id="${_to_certificate_ca_chain.certificate_ca_chain_id}"
                                                        data-certificate_ca_chain-certificate_ca_0-id="${_to_certificate_ca_chain.certificate_ca_chain.certificate_ca_0.id}"
                                                        data-certificate_ca_chain-certificate_ca_0-fingerprint_sha1="${_to_certificate_ca_chain.certificate_ca_chain.certificate_ca_0.fingerprint_sha1}"
                                                        data-certificate_ca_chain-certificate_ca_n-id="${_to_certificate_ca_chain.certificate_ca_chain.certificate_ca_n.id}"
                                                        data-certificate_ca_chain-certificate_ca_n-fingerprint_sha1="${_to_certificate_ca_chain.certificate_ca_chain.certificate_ca_n.fingerprint_sha1}"
                                                    >
                                                        <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                        fullchain.pem.txt</a>
                                                    <a
                                                        class="btn btn-xs btn-info"
                                                        href="${admin_prefix}/certificate-signed/${CertificateSigned.id}/via-certificate-ca-chain/${_to_certificate_ca_chain.certificate_ca_chain_id}/fullchain.pem"
                                                        data-certificate_ca_chain-id="${_to_certificate_ca_chain.certificate_ca_chain_id}"
                                                        data-certificate_ca_chain-certificate_ca_0-id="${_to_certificate_ca_chain.certificate_ca_chain.certificate_ca_0.id}"
                                                        data-certificate_ca_chain-certificate_ca_0-fingerprint_sha1="${_to_certificate_ca_chain.certificate_ca_chain.certificate_ca_0.fingerprint_sha1}"
                                                        data-certificate_ca_chain-certificate_ca_n-id="${_to_certificate_ca_chain.certificate_ca_chain.certificate_ca_n.id}"
                                                        data-certificate_ca_chain-certificate_ca_n-fingerprint_sha1="${_to_certificate_ca_chain.certificate_ca_chain.certificate_ca_n.fingerprint_sha1}"
                                                    >
                                                        <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                        fullchain.pem</a>
                                                </td>
                                            </tr>
                                        % endfor
                                    % endif
                                </tbody>
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <th>cert_subject</th>
                        <td>
                            <a
                                class="btn btn-xs btn-info"
                                href="${admin_prefix}/search?${CertificateSigned.cert_subject_search}"
                            >
                                <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                            </a>
                            <br/>
                            <samp>${CertificateSigned.cert_subject}</samp>
                        </td>
                    </tr>
                    <tr>
                        <th>cert_issuer</th>
                        <td>
                            <a
                                class="btn btn-xs btn-info"
                                href="${admin_prefix}/search?${CertificateSigned.cert_issuer_search}"
                            >
                                <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                            </a>
                            <br/>

                            <samp>${CertificateSigned.cert_issuer}</samp>
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
                                    % for to_d in CertificateSigned.unique_fqdn_set.to_domains:
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
                                                % if CertificateSigned.id in (to_d.domain.certificate_signed_id__latest_single, to_d.domain.certificate_signed_id__latest_multi):
                                                    <span class="label label-default">
                                                        % if CertificateSigned.id == to_d.domain.certificate_signed_id__latest_single:
                                                            single
                                                        % endif
                                                        % if CertificateSigned.id == to_d.domain.certificate_signed_id__latest_multi:
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
                        <th></th>
                        <td>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</%block>
