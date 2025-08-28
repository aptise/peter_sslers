<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%! enable_search = False %>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/x509-certificates">X509Certificates</a></li>
        <li class="active">Focus [${X509Certificate.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>X509Certificate - Focus</h2>
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
        <a href="${admin_prefix}/x509-certificate/${X509Certificate.id}.json" class="btn btn-xs btn-info">
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
                        <th colspan="2">Core Details</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <th>id</th>
                        <td>
                            <span class="label label-default">
                                ${X509Certificate.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>is_active</th>
                        <td>
                            <span class="label label-${'success' if X509Certificate.is_active else 'warning'}">
                                ${'Active' if X509Certificate.is_active else 'inactive'}
                            </span>
                            &nbsp;
                            % if X509Certificate.is_active:
                                <form 
                                    action="${admin_prefix}/x509-certificate/${X509Certificate.id}/mark" 
                                    method="POST" 
                                    style="display:inline;" 
                                    id="form-x509_certificate-mark-inactive"
                                >
                                    <input type="hidden" name="action" value="inactive"/>
                                    <button class="btn btn-xs btn-warning" type="submit">
                                        <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                        deactivate
                                    </button>
                                </form>
                            % else:
                                ## show a reason
                                % if X509Certificate.is_revoked:
                                    Reason: <code>revoked</code>
                                % elif X509Certificate.is_deactivated:
                                    Reason: <code>deactivated</code>
                                % endif
                                % if not X509Certificate.is_deactivated:
                                    &nbsp;
                                    Actions:
                                    ## % if X509Certificate.is_revoked:
                                    ##     <form action="${admin_prefix}/x509-certificate/${X509Certificate.id}/mark" method="POST" style="display:inline;">
                                    ##         <input type="hidden" name="action" value="unrevoke"/>
                                    ##         <button class="btn btn-xs btn-warning" type="submit">
                                    ##             <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                    ##             unrevoke
                                    ##         </button>
                                    ##     </form>
                                    ## % endif
                                    % if not X509Certificate.is_revoked:
                                        <form
                                            action="${admin_prefix}/x509-certificate/${X509Certificate.id}/mark"
                                            method="POST"
                                            style="display:inline;"
                                            id="form-x509_certificate-mark-active"
                                        >
                                            <input type="hidden" name="action" value="active"/>
                                            <button class="btn btn-xs btn-success" type="submit">
                                                <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                                activate
                                            </button>
                                        </form>
                                        <form
                                            action="${admin_prefix}/x509-certificate/${X509Certificate.id}/mark"
                                            method="POST"
                                            style="display:inline;"
                                            id="form-x509_certificate-mark-revoked"
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
                            % if X509Certificate.acme_order:
                                <a class="label label-info" href="${admin_prefix}/renewal-configuration/${X509Certificate.acme_order.renewal_configuration_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    RenewalConfiguration-${X509Certificate.acme_order.renewal_configuration_id}</a>
                                % if X509Certificate.acme_order:
                                    % if X509Certificate.acme_order.renewal_configuration.is_active:
                                        <span class="label label-success">auto-renew active</span>
                                    % else:
                                        <span class="label label-danger">auto-renew disabled</span>
                                    % endif
                                % endif
                                
                                <a href="${admin_prefix}/renewal-configuration/${X509Certificate.acme_order.renewal_configuration_id}/lineages"
                                    title="Lineages"
                                    class="btn btn-xs btn-primary"
                                >
                                    <span class="glyphicon glyphicon-wrench" aria-hidden="true"></span>
                                    Calculate Lineages
                                </a>                            
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
                            % if X509Certificate.acme_order:
                                <%
                                    _replaces = ""
                                    if not X509Certificate.ari_identifier__replaced_by:
                                        _replaces = "?replaces.id=%s" % X509Certificate.id
                                %>
                                <a  class="btn btn-xs btn-primary"
                                    href="${admin_prefix}/renewal-configuration/${X509Certificate.acme_order.renewal_configuration.id}/new-order${_replaces}"
                                    title="Renew Quick"
                                >
                                    <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                    Renew Quick
                                </a>
                                <a  class="btn btn-xs btn-primary"
                                    href="${admin_prefix}/renewal-configuration/${X509Certificate.acme_order.renewal_configuration.id}/new-configuration"
                                    title="Renew Custom"
                                >
                                    <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                    Renew Custom
                                </a>
                            % else:
                                <a  class="btn btn-xs btn-primary"
                                    href="${admin_prefix}/renewal-configuration/new?domain_names_http01=${X509Certificate.domains_as_string}"
                                    title="Renew Custom"
                                >
                                    <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                    New RenewalConfiguration
                                </a>
                            % endif
                        </td>
                    </tr>
                    % if request.api_context.application_settings['enable_nginx']:
                        <tr>
                            <th>Nginx cache</th>
                            <td>
                                    <form
                                        action="${admin_prefix}/x509-certificate/${X509Certificate.id}/nginx-cache-expire"
                                        method="POST"
                                        id="form-x509_certificate-nginx_cache_expire"
                                    >
                                        <button class="btn btn-xs btn-primary" type="submit"  name="submit" value="submit">
                                            <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                            nginx-cache-expire
                                        </button>
                                    </form>
                                    &nbsp;
                                    <form
                                        action="${admin_prefix}/x509-certificate/${X509Certificate.id}/nginx-cache-expire.json"
                                        method="POST"
                                        id="form-x509_certificate-nginx_cache_expire-json"
                                        target="_blank"
                                    >
                                        <button type="submit" class="btn btn-xs btn-primary" type="submit" name="submit" value="submit">
                                            <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                            nginx-cache-expire.json
                                        </button>
                                    </form>
                            </td>
                        </tr>
                    % endif
                    <tr>
                        <th>Certificate Types</th>
                        <td>
                            ## <code>${X509Certificate.certificate_type}</code>
                            % if X509Certificate.certificate_type_id == model_websafe.CertificateType.MANAGED_PRIMARY:
                                <span class="label label-success">${X509Certificate.certificate_type}</span>
                            % elif X509Certificate.certificate_type_id == model_websafe.CertificateType.MANAGED_BACKUP:
                                <span class="label label-warning">${X509Certificate.certificate_type}</span>
                            % elif X509Certificate.certificate_type_id == model_websafe.CertificateType.RAW_IMPORTED:
                                <span class="label label-default">${X509Certificate.certificate_type}</span>
                            % endif
                            % if X509Certificate.is_single_domain_cert is True:
                                <span class="label label-default">
                                    single domain certificate
                                </span>
                            % elif X509Certificate.is_single_domain_cert is False:
                                <span class="label label-default">
                                    multiple domain certificate
                                </span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>domains</th>
                        <td><code>${X509Certificate.domains_as_string}</code></td>
                    </tr>
                    <tr>
                        <th>cert_serial</th>
                        <td><code>${X509Certificate.cert_serial}</code></td>
                    </tr>
                    <tr>
                        <th>fingerprint_sha1</th>
                        <td><code>${X509Certificate.fingerprint_sha1}</code></td>
                    </tr>
                    <tr>
                        <th>cert_pem_md5</th>
                        <td><code>${X509Certificate.cert_pem_md5}</code></td>
                    </tr>
                    <tr>
                        <th>spki_sha256</th>
                        <td>
                            <code>${X509Certificate.spki_sha256}</code>
                            <a
                                class="btn btn-xs btn-primary"
                                href="${admin_prefix}/search?${X509Certificate.cert_spki_search}"
                            >
                                <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                            </a>
                        </td>
                    </tr>
                    <tr>
                        <th>cert_subject</th>
                        <td>
                            <a
                                class="btn btn-xs btn-primary"
                                href="${admin_prefix}/search?${X509Certificate.cert_subject_search}"
                            >
                                <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                            </a>
                            <br/>
                            <samp>${X509Certificate.cert_subject}</samp>
                        </td>
                    </tr>
                    <tr>
                        <th>cert_issuer</th>
                        <td>
                            <a
                                class="btn btn-xs btn-primary"
                                href="${admin_prefix}/search?${X509Certificate.cert_issuer_search}"
                            >
                                <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                            </a>
                            <br/>

                            <samp>${X509Certificate.cert_issuer}</samp>
                        </td>
                    </tr>                    
                    
                    
                    
                    
                    <tr>
                        <th>timestamp_not_before</th>
                        <td><timestamp>${X509Certificate.timestamp_not_before}</timestamp></td>
                    </tr>
                    <tr>
                        <th>timestamp_not_after</th>
                        <td><timestamp>${X509Certificate.timestamp_not_after}</timestamp></td>
                    </tr>
                    <tr>
                        <th>duration_hours</th>
                        <td><timestamp>${X509Certificate.duration_hours}</timestamp></td>
                    </tr>
                    <tr>
                        <th>remaining_hours</th>
                        <td><timestamp>${X509Certificate.remaining_hours(request.api_context)} (${X509Certificate.remaining_percent(request.api_context)}%)</timestamp></td>
                    </tr>
                    <tr>
                        <th>expires in days</th>
                        <td>
                            <span class="label label-${X509Certificate.days_to_expiry__label}">
                                ${X509Certificate.days_to_expiry} days
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>ARI and Lineage</th>
                        <td>
                            <table class="table table-striped table-condensed">
                                <tr>
                                    <th>ari_identifier__replaced_by</th>
                                    <td>
                                        % if X509Certificate.ari_identifier__replaced_by:
                                            <code>${X509Certificate.ari_identifier__replaced_by}</code>
                                        % endif
                                    </td>
                                </tr>
                                <tr>
                                    <th>Certificate replaced_by</th>
                                    <td>
                                        % if X509Certificate.x509_certificate_id__replaced_by:
                                            <a class="label label-info" href="${admin_prefix}/x509-certificate/${X509Certificate.x509_certificate_id__replaced_by}">
                                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                X509Certificate-${X509Certificate.x509_certificate_id__replaced_by}
                                            </a>
                                        % endif
                                    </td>
                                </tr>
                                <tr>
                                    <th colspan="2"><hr/></th>
                                </tr>
                                <tr>
                                    <th>ari_identifier</th>
                                    <td><code>${X509Certificate.ari_identifier}</code></td>
                                </tr>
                                <tr>
                                    <th colspan="2"><hr/></th>
                                </tr>
                                <tr>
                                    <th>Certificate replaces</th>
                                    <td>
                                        % if X509Certificate.x509_certificate_id__replaces:
                                            <a class="label label-info" href="${admin_prefix}/x509-certificate/${X509Certificate.x509_certificate_id__replaces}">
                                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                X509Certificate-${X509Certificate.x509_certificate_id__replaces}
                                            </a>
                                        % endif
                                    </td>
                                </tr>
                                <tr>
                                    <th>ari_identifier__replaces</th>
                                    <td>
                                        % if X509Certificate.ari_identifier__replaces:
                                            <code>${X509Certificate.ari_identifier__replaces}</code>
                                        % endif
                                    </td>
                                </tr>
                                <tr>
                                    <th colspan="2"><hr/></th>
                                </tr>
                                % if X509Certificate.is_ari_supported:
                                    <tr>
                                        <th>Latest ARI Check</th>
                                        <td>
                                            % if X509Certificate.ari_check__latest:
                                                <a class="label label-info" href="${admin_prefix}/ari-check/${X509Certificate.ari_check__latest.id}">
                                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                    ${X509Certificate.ari_check__latest.id}
                                                    ARI Check Latest
                                                </a>
                                                % if X509Certificate.ari_check__latest.ari_check_status:
                                                    <table>
                                                        <tr>
                                                            <th>Timestamp</th>
                                                            <td><timestamp>${X509Certificate.ari_check__latest.timestamp_created}</timestamp></td>
                                                        </tr>
                                                        <tr>
                                                            <th>Suggested Window Start</th>
                                                            <td><timestamp>${X509Certificate.ari_check__latest.suggested_window_start}</timestamp></td>
                                                        </tr>
                                                        <tr>
                                                            <th>Suggested Window End</th>
                                                            <td><timestamp>${X509Certificate.ari_check__latest.suggested_window_end}</timestamp></td>
                                                        </tr>
                                                        <tr>
                                                            <th>Retry After</th>
                                                            <td><timestamp>${X509Certificate.ari_check__latest.timestamp_retry_after}</timestamp></td>
                                                        </tr>
                                                    </table>
                                                % else:
                                                    <p>ERROR on Last ARI Check</p>
                                                    <table>
                                                        <tr>
                                                            <th>Timestamp</th>
                                                            <td><timestamp>${X509Certificate.ari_check__latest.timestamp_created}</timestamp></td>
                                                        </tr>
                                                        <tr>
                                                            <th>Response</th>
                                                            <td><code>${X509Certificate.ari_check__latest.raw_response}</code></td>
                                                        </tr>
                                                    </table>
                                                % endif
                                            % endif
                                        </td>
                                    </tr>
                                    <tr>
                                        <th>Historical Checks</th>
                                        <td>
                                            <a class="label label-info" href="${admin_prefix}/x509-certificate/${X509Certificate.id}/ari-check-history">
                                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                ARI Checks (History)
                                            </a>
                                        </td>
                                    </tr>
                                    <tr>
                                        <th>Manual Check</th>
                                        <td>
                                            % if X509Certificate.is_ari_checking_timely(request.api_context, context="dashboard"):
                                                <form
                                                    action="${admin_prefix}/x509-certificate/${X509Certificate.id}/ari-check" 
                                                    method="POST"
                                                    style="display:inline;"
                                                    id="form-x509_certificate-ari_check"
                                                >
                                                    <button class="btn btn-xs btn-primary" type="submit">
                                                        <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                                                        Check ARI
                                                    </button>
                                                </form>
                                            % else:
                                                Certificate Too Old for ARI Checking
                                            % endif
                                        </td>
                                    </tr>
                                % else:
                                    <tr>
                                        <th>ARI Checks</th>
                                        <td>ARI Does not seem possible for this Certificate</td>
                                    </tr>
                                % endif
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <th>X509CertificateTrustChains</th>
                        <td>
                            % if X509Certificate.x509_certificate_chains:
                                <em>Available Signing Chains:</em>
                                <ul>
                                    % for _chain in X509Certificate.x509_certificate_chains:
                                        <li>${_chain.x509_certificate_trust_chain.button_view|n}</li>
                                    % endfor
                                </ul>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>CertificateCAs</th>
                        <td>
                            % if X509Certificate.certificate_cas__upchain:
                                <p>The following CertificateCAs have signed this Certificate in a presented chain</p>
                                <ul class="list list-unstyled">
                                    % for cert_ca in X509Certificate.certificate_cas__upchain:
                                        <li>
                                            ${cert_ca.button_view|n}
                                        </li>
                                    % endfor
                                </ul>
                                <p>Search for additional compatible CertificateCAs</p>
                                <ul class="list list-unstyled">
                                    % for cert_ca in X509Certificate.certificate_cas__upchain:
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
                            % if not X509Certificate.private_key.is_compromised:
                                <a class="label label-info" href="${admin_prefix}/private-key/${X509Certificate.private_key_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    PrivateKey-${X509Certificate.private_key_id}</a>
                            % else:
                                <a class="label label-danger" href="${admin_prefix}/private-key/${X509Certificate.private_key_id}">
                                    <span class="glyphicon glyphicon-warning-sign" aria-hidden="true"></span>
                                    PrivateKey-${X509Certificate.private_key_id}</a>
                            % endif
                            <br/>
                            <em>The X509Certificate is signed by this PrivateKey.</em>
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeAccount</th>
                        <td>
                            % if X509Certificate.acme_order and X509Certificate.acme_order.acme_account_id:
                                <a class="label label-info" href="${admin_prefix}/acme-account/${X509Certificate.acme_order.acme_account_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeAccount-${X509Certificate.acme_order.acme_account_id}
                                    </a>
                                @
                                <a class="label label-info" href="${admin_prefix}/acme-server/${X509Certificate.acme_order.acme_account.acme_server_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeServer-${X509Certificate.acme_order.acme_account.acme_server_id}
                                    </a>
                                    <span class="label label-default">${X509Certificate.acme_order.acme_account.acme_server.name}</span>
                                <br/>
                                <em>The X509Certificate belongs to this AcmeAccount through an AcmeOrder.</em>
                            % else:
                                <em>The X509Certificate is not associated with an AcmeAccount through an AcmeOrder.</em>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeOrder</th>
                        <td>
                            % if X509Certificate.acme_order:
                                <a class="label label-info" href="${admin_prefix}/acme-order/${X509Certificate.acme_order.id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeOrder-${X509Certificate.acme_order.id}</a>
                                <br/>
                                <em>The X509Certificate belongs to this AcmeOrder.</em>
                            % else:
                                <em>The X509Certificate is not associated with an AcmeOrder.</em>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>X509CertificateRequest</th>
                        <td>
                            % if X509Certificate.x509_certificate_request_id:
                                <a class="label label-info" href="${admin_prefix}/x509-certificate-request/${X509Certificate.x509_certificate_request_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    X509CertificateRequest-${X509Certificate.x509_certificate_request_id}</a>
                                <br/>
                                <em>The X509Certificate is the result of this CertificateSigningRequest.</em>
                            % else:
                                <em>The X509Certificate is not associated with a CertificateSigningRequest.</em>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>UniqueFQDNSet</th>
                        <td>
                            <a  class="label label-info"
                                href="${admin_prefix}/unique-fqdn-set/${X509Certificate.unique_fqdn_set_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                UniqueFQDNSet-${X509Certificate.unique_fqdn_set_id}
                            </a>
                            <br/>
                            <em>The X509Certificate covers the domains in this UniqueFQDNSet.</em>
                            <br/>
                            <%
                                latest_certificate = X509Certificate.unique_fqdn_set.latest_certificate
                                latest_active_certificate = X509Certificate.unique_fqdn_set.latest_active_certificate
                                latest_certificate_same = True if latest_certificate and latest_certificate.id == X509Certificate.id else False
                                latest_active_certificate_same = True if latest_active_certificate and latest_active_certificate.id == X509Certificate.id else False
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
                                                        href="${admin_prefix}/x509-certificate/${latest_certificate.id}"
                                                        >
                                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                        X509Certificate-${latest_certificate.id}
                                                    </a>
                                                % endif
                                            </td>
                                            <td>
                                                <span class="label label-${'success' if latest_certificate.is_active else 'warning'}">
                                                    ${'Active' if latest_certificate.is_active else 'inactive'}
                                                </span>
                                            </td>
                                            <td>
                                                <span class="label label-${latest_certificate.days_to_expiry__label}">
                                                    ${latest_certificate.days_to_expiry} days
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
                                                        href="${admin_prefix}/x509-certificate/${latest_active_certificate.id}"
                                                        >
                                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                        X509Certificate-${latest_active_certificate.id}
                                                    </a>
                                                % endif
                                            </td>
                                            <td>
                                                <span class="label label-${'success' if latest_active_certificate.is_active else 'warning'}">
                                                    ${'Active' if latest_active_certificate.is_active else 'inactive'}
                                                </span>
                                            </td>
                                            <td>
                                                <span class="label label-${latest_active_certificate.days_to_expiry__label}">
                                                    ${latest_active_certificate.days_to_expiry} days
                                                </span>
                                            </td>
                                        % endif
                                    </tr>
                                </tbody>
                            </table>
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
                                    % for to_d in X509Certificate.unique_fqdn_set.to_domains:
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
                                                % if X509Certificate.id in (to_d.domain.x509_certificate_id__latest_single, to_d.domain.x509_certificate_id__latest_multi):
                                                    <span class="label label-default">
                                                        % if X509Certificate.id == to_d.domain.x509_certificate_id__latest_single:
                                                            single
                                                        % endif
                                                        % if X509Certificate.id == to_d.domain.x509_certificate_id__latest_multi:
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
                    <tr>
                        <th colspan="2">Configuration Files</th>
                    </tr>
                    <tr>
                        <th>cert_pem</th>
                        <td>
                            ## <textarea class="form-control">${X509Certificate.key_pem}</textarea>
                            <a class="label label-info" href="${admin_prefix}/x509-certificate/${X509Certificate.id}/cert.pem">
                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                cert.pem (PEM)</a>
                            <a class="label label-info" href="${admin_prefix}/x509-certificate/${X509Certificate.id}/cert.pem.txt">
                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                cert.pem.txt (PEM)</a>
                            <a class="label label-info" href="${admin_prefix}/x509-certificate/${X509Certificate.id}/cert.crt">
                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                cert.crt (DER)</a>
                            <a class="label label-info" href="${admin_prefix}/x509-certificate/${X509Certificate.id}/cert.cer">
                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                cert.cer (DER)</a>
                            <a class="label label-info" href="${admin_prefix}/x509-certificate/${X509Certificate.id}/cert.der">
                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                cert.der (DER)</a>
                        </td>
                    </tr>
                    <tr>
                        <th>json payload</th>
                        <td>
                            <em>designed for http server config</em>
                            <hr/>

                            % if X509Certificate.x509_certificate_trust_chain__preferred:
                                <em>Default Chain</em><br/>
                                The Default Chain is ${X509Certificate.x509_certificate_trust_chain__preferred.button_view|n}
                                </p>

                                <a class="label label-info" href="${admin_prefix}/x509-certificate/${X509Certificate.id}/config.json">
                                    <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                    config.json</a><br/>
                                <hr/>
                            % endif

                            <em>all chains</em><br/>
                            <ul class="list list-unstyled">
                                % for _to_x509_certificate_trust_chain in X509Certificate.x509_certificate_chains:
                                    <li>
                                        <a class="label label-info" href="${admin_prefix}/x509-certificate/${X509Certificate.id}/via-certificate-ca-chain/${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.id}/config.json">
                                            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                            X509CertificateTrustChain-${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.id}
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

                            % if X509Certificate.x509_certificate_trust_chain__preferred:
                                <em>Default Chain</em><br/>
                                The Default Chain is ${X509Certificate.x509_certificate_trust_chain__preferred.button_view|n}
                                </p>

                                <a
                                    class="label label-info"
                                    href="${admin_prefix}/x509-certificate/${X509Certificate.id}/config.zip"
                                    data-x509_certificate_trust_chain-id="${X509Certificate.x509_certificate_trust_chain__preferred.id}"
                                    data-x509_certificate_trust_chain-certificate_ca_0-id="${X509Certificate.x509_certificate_trust_chain__preferred.certificate_ca_0.id}"
                                    data-x509_certificate_trust_chain-certificate_ca_0-fingerprint_sha1="${X509Certificate.x509_certificate_trust_chain__preferred.certificate_ca_0.fingerprint_sha1}"
                                    data-x509_certificate_trust_chain-certificate_ca_n-id="${X509Certificate.x509_certificate_trust_chain__preferred.certificate_ca_n.id}"
                                    data-x509_certificate_trust_chain-certificate_ca_n-fingerprint_sha1="${X509Certificate.x509_certificate_trust_chain__preferred.certificate_ca_n.fingerprint_sha1}"
                                >
                                    <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                    config.zip</a><br/>
                            % endif
                            <hr/>

                            <em>all chains</em><br/>
                            <ul class="list list-unstyled">
                                % for _to_x509_certificate_trust_chain in X509Certificate.x509_certificate_chains:
                                    <li>
                                        <a
                                            class="label label-info"
                                            href="${admin_prefix}/x509-certificate/${X509Certificate.id}/via-certificate-ca-chain/${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.id}/config.zip"
                                            data-x509_certificate_trust_chain-id="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.id}"
                                            data-x509_certificate_trust_chain-certificate_ca_0-id="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.certificate_ca_0.id}"
                                            data-x509_certificate_trust_chain-certificate_ca_0-fingerprint_sha1="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.certificate_ca_0.fingerprint_sha1}"
                                            data-x509_certificate_trust_chain-certificate_ca_n-id="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.certificate_ca_n.id}"
                                            data-x509_certificate_trust_chain-certificate_ca_n-fingerprint_sha1="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.certificate_ca_n.fingerprint_sha1}"
                                        >
                                            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                            X509CertificateTrustChain-${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.id}
                                            config.zip</a>
                                    </li>
                                % endfor
                            </ul>

                        </td>
                    </tr>
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
                                            <a class="label label-info" href="${admin_prefix}/x509-certificate/${X509Certificate.id}/privkey.pem.txt">
                                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                privkey.pem.txt</a>
                                            <a class="label label-info" href="${admin_prefix}/x509-certificate/${X509Certificate.id}/privkey.pem">
                                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                privkey.pem</a>
                                            <a class="label label-info" href="${admin_prefix}/x509-certificate/${X509Certificate.id}/privkey.key">
                                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                privkey.key (der)</a>
                                        </td>
                                    </tr>
                                    % if X509Certificate.x509_certificate_chains:
                                        <tr>
                                            <th colspan="2">Certificate Chains</th>
                                        </tr>
                                        % for _to_x509_certificate_trust_chain in X509Certificate.x509_certificate_chains:
                                            <tr>
                                                <th>chain (upstream)
                                                    <span class="label label-default">X509CertificateTrustChain-${_to_x509_certificate_trust_chain.x509_certificate_trust_chain_id}</span>
                                                </th>
                                                <td>
                                                    <a
                                                        class="label label-info"
                                                        href="${admin_prefix}/x509-certificate/${X509Certificate.id}/via-certificate-ca-chain/${_to_x509_certificate_trust_chain.x509_certificate_trust_chain_id}/chain.pem.txt"
                                                        data-x509_certificate_trust_chain-id="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain_id}"
                                                        data-x509_certificate_trust_chain-certificate_ca_0-id="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.certificate_ca_0.id}"
                                                        data-x509_certificate_trust_chain-certificate_ca_0-fingerprint_sha1="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.certificate_ca_0.fingerprint_sha1}"
                                                        data-x509_certificate_trust_chain-certificate_ca_n-id="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.certificate_ca_n.id}"
                                                        data-x509_certificate_trust_chain-certificate_ca_n-fingerprint_sha1="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.certificate_ca_n.fingerprint_sha1}"
                                                    >
                                                        <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                        chain.pem.txt</a>
                                                    <a
                                                        class="label label-info"
                                                        href="${admin_prefix}/x509-certificate/${X509Certificate.id}/via-certificate-ca-chain/${_to_x509_certificate_trust_chain.x509_certificate_trust_chain_id}/chain.pem"
                                                        data-x509_certificate_trust_chain-id="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain_id}"
                                                        data-x509_certificate_trust_chain-certificate_ca_0-id="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.certificate_ca_0.id}"
                                                        data-x509_certificate_trust_chain-certificate_ca_0-fingerprint_sha1="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.certificate_ca_0.fingerprint_sha1}"
                                                        data-x509_certificate_trust_chain-certificate_ca_n-id="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.certificate_ca_n.id}"
                                                        data-x509_certificate_trust_chain-certificate_ca_n-fingerprint_sha1="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.certificate_ca_n.fingerprint_sha1}"
                                                    >
                                                        <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                        chain.pem</a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <th>fullchain (cert+upstream chain)
                                                    <span class="label label-default">CertificateCA-${_to_x509_certificate_trust_chain.x509_certificate_trust_chain_id}</span>
                                                </th>
                                                <td>
                                                    <a
                                                        class="label label-info"
                                                        href="${admin_prefix}/x509-certificate/${X509Certificate.id}/via-certificate-ca-chain/${_to_x509_certificate_trust_chain.x509_certificate_trust_chain_id}/fullchain.pem.txt"
                                                        data-x509_certificate_trust_chain-id="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain_id}"
                                                        data-x509_certificate_trust_chain-certificate_ca_0-id="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.certificate_ca_0.id}"
                                                        data-x509_certificate_trust_chain-certificate_ca_0-fingerprint_sha1="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.certificate_ca_0.fingerprint_sha1}"
                                                        data-x509_certificate_trust_chain-certificate_ca_n-id="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.certificate_ca_n.id}"
                                                        data-x509_certificate_trust_chain-certificate_ca_n-fingerprint_sha1="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.certificate_ca_n.fingerprint_sha1}"
                                                    >
                                                        <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                                        fullchain.pem.txt</a>
                                                    <a
                                                        class="label label-info"
                                                        href="${admin_prefix}/x509-certificate/${X509Certificate.id}/via-certificate-ca-chain/${_to_x509_certificate_trust_chain.x509_certificate_trust_chain_id}/fullchain.pem"
                                                        data-x509_certificate_trust_chain-id="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain_id}"
                                                        data-x509_certificate_trust_chain-certificate_ca_0-id="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.certificate_ca_0.id}"
                                                        data-x509_certificate_trust_chain-certificate_ca_0-fingerprint_sha1="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.certificate_ca_0.fingerprint_sha1}"
                                                        data-x509_certificate_trust_chain-certificate_ca_n-id="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.certificate_ca_n.id}"
                                                        data-x509_certificate_trust_chain-certificate_ca_n-fingerprint_sha1="${_to_x509_certificate_trust_chain.x509_certificate_trust_chain.certificate_ca_n.fingerprint_sha1}"
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
                        <th colspan="2">
                            Events and Revocations
                        </th>
                    </tr>
                     ${admin_partials.table_tr_OperationsEventCreated(X509Certificate)}
                    <tr>
                        <th>
                            Revocation
                        </th>
                        <td>
                            % if X509Certificate.is_active:
                                <form
                                    action="${admin_prefix}/x509-certificate/${X509Certificate.id}/mark" 
                                    method="POST" 
                                    style="display:inline;" 
                                    id="form-x509_certificate-mark-revoked"
                                >
                                    <input type="hidden" name="action" value="revoked"/>
                                    <button class="btn btn-xs btn-danger" type="submit">
                                        <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                        mark revoked
                                    </button>
                                </form>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>is_compromised_private_key</th>
                        <td>
                            % if X509Certificate.is_compromised_private_key is not None:
                                <span class="label label-danger">
                                    COMPROMISED PRIVATE KEY
                                </span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>is_revoked_upstream</th>
                        <td>
                            % if X509Certificate.timestamp_revoked_upstream is not None:
                                <span class="label label-danger">
                                    revoked upstream @ ${X509Certificate.timestamp_revoked_upstream_isoformat}
                                </span>
                            % endif
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</%block>
