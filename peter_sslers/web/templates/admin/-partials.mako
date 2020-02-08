<%def name="table_tr_event_created(dbObject)">
    % if dbObject.operations_event_id__created:
        <tr>
            <th>Event Created At</th>
            <td>
                <a  href="${admin_prefix}/operations/log/item/${dbObject.operations_event_id__created}"
                    class="label label-info"
                >
                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                    ${dbObject.operations_event_id__created}
                </a>
                <span class="label label-default">${dbObject.operations_event__created.event_type_text}</span>
                <timestamp>${dbObject.operations_event__created.timestamp_event or ''}</timestamp>
            </td>
        </tr>
    % endif
</%def>

<%def name="table_to_certificates(to_certificates, show_domains=False, show_domains_title='domains', show_expiring_days=False)">
    <table class="table table-striped">
        <thead>
            <tr>
                <th>id</th>
                <th>active?</th>
                <th>timestamp_signed</th>
                <th>timestamp_expires</th>
                % if show_expiring_days:
                    <th>expiring days</th>
                % endif
                % if show_domains:
                    <th>${show_domains_title}</th>
                % endif
            </tr>
        </thead>
        <tbody>
        % for to_cert in to_certificates:
            <tr>
                <td><a class="label label-info" href="${admin_prefix}/certificate/${to_cert.certificate.id}">
                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                    cert-${to_cert.certificate.id}</a>
                </td>
                <td>
                    <span class="label label-${'success' if to_cert.certificate.is_active else 'warning'}">
                        ${'Active' if to_cert.certificate.is_active else 'inactive'}
                    </span>
                </td>
                <td><timestamp>${to_cert.certificate.timestamp_signed}</timestamp></td>
                <td><timestamp>${to_cert.certificate.timestamp_expires or ''}</timestamp></td>
                % if show_expiring_days:
                    <td>
                        <span class="label label-${to_cert.certificate.expiring_days_label}">
                            ${to_cert.certificate.expiring_days} days
                        </span>
                    </td>
                % endif
                % if show_domains:
                     <td><code>${to_cert.certificate.domains_as_string}</code></td>
                % endif
            </tr>
        % endfor
        </tbody>
    </table>
</%def>


<%def name="table_to_certificate_requests(to_certificate_requests, show_domains=False)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>active?</th>
                <th>type?</th>
                <th>timestamp_verified</th>
                <th>challenge_key</th>
                <th>challenge_text</th>
            </tr>
        </thead>
        <tbody>
        % for to_cr in to_certificate_requests:
            <tr>
                <td>
                    <a  class="label label-info"
                        href="${admin_prefix}/certificate-request/${to_cr.certificate_request.id}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        csr-${to_cr.certificate_request.id}</a>
                </td>
                <td>
                    <span class="label label-${'success' if to_cr.certificate_request.is_active else 'warning'}">
                        ${'Active' if to_cr.certificate_request.is_active else 'inactive'}
                    </span>
                </td>
                <td>
                    <span class="label label-defaul">${to_cr.certificate_request.certificate_request_source}</span>
                </td>
                <td><timestamp>${to_cr.timestamp_verified or ''}</timestamp></td>
                <td><code>${to_cr.challenge_key or ''}</code></td>
                <td><code>${to_cr.challenge_text or ''}</code></td>
            </tr>
        % endfor
        </tbody>
    </table>
</%def>


<%def name="table_certificates__list(certificates, show_domains=False, show_expiring_days=False)">
    <table class="table table-striped">
        <thead>
            <tr>
                <th>id</th>
                <th>active?</th>
                <th>auto-renew?</th>
                <th>is renewed?</th>
                <th>timestamp_signed</th>
                <th>timestamp_expires</th>
                % if show_expiring_days:
                    <th>expiring days</th>
                % endif
                % if show_domains:
                    <th>domains</th>
                % endif
            </tr>
        </thead>
        <tbody>
        % for cert in certificates:
            <tr>
                <td><a class="label label-info" href="${admin_prefix}/certificate/${cert.id}">
                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                    cert-${cert.id}</a>
                </td>
                <td>
                    % if cert.is_revoked:
                        <span class="label label-danger">
                            revoked
                        </span>
                    % else:
                        <span class="label label-${'success' if cert.is_active else 'warning'}">
                            ${'Active' if cert.is_active else 'inactive'}
                        </span>
                    % endif
                </td>
                <td>
                    <span class="label label-${'success' if cert.is_auto_renew else 'warning'}">
                        ${'AutoRenew' if cert.is_auto_renew else 'manual'}
                    </span>
                </td>
                <td>
                    <span class="label label-${'success' if cert.is_renewed else 'default'}">
                        ${'Renewed' if cert.is_renewed else 'not-renewed-yet'}
                    </span>
                </td>
                <td><timestamp>${cert.timestamp_signed}</timestamp></td>
                <td><timestamp>${cert.timestamp_expires or ''}</timestamp></td>
                % if show_expiring_days:
                    <td>
                        <span class="label label-${cert.expiring_days_label}">
                            ${cert.expiring_days} days
                        </span>
                    </td>
                % endif
                % if show_domains:
                    <td><code>${cert.domains_as_string}</code></td>
                % endif
            </tr>
        % endfor
        </tbody>
    </table>
</%def>


<%def name="table_certificate_requests__list(certificate_requests, show_domains=False, show_certificate=False)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>type</th>
                <th>active?</th>
                ## <th>error?</th>
                % if show_certificate:
                    <th>cert issued?</th>
                % endif
                <th>timestamp_created</th>
                ## <th>timestamp_finished</th>
                % if show_domains:
                    <th>domains</th>
                % endif
            </tr>
        </thead>
        <tbody>
        % for certificate_request in certificate_requests:
            <tr>
                <td>
                    <a  class="label label-info"
                        href="${admin_prefix}/certificate-request/${certificate_request.id}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        csr-${certificate_request.id}</a>
                </td>
                <td>
                    <span class="label label-default">${certificate_request.certificate_request_source}</span>
                </td>
                <td>
                    <span class="label label-${'success' if certificate_request.is_active else 'warning'}">
                        ${'Active' if certificate_request.is_active else 'inactive'}
                    </span>
                </td>
                ## <td>
                ##    <span class="label label-${'danger' if certificate_request.is_error else 'default'}">
                ##        ${'Error' if certificate_request.is_error else 'ok'}
                ##    </span>
                ## </td>
                % if show_certificate:
                    <td>
                        % if certificate_request.server_certificate:
                            <a  class="label label-info"
                                href="${admin_prefix}/certificate/${certificate_request.server_certificate.id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                cert-${certificate_request.server_certificate.id}</a>
                        % else:
                            &nbsp;
                        % endif
                    </td>
                % endif
                <td><timestamp>${certificate_request.timestamp_created}</timestamp></td>
                ## <td><timestamp>${certificate_request.timestamp_finished or ''}</timestamp></td>
                % if show_domains:
                     <td><code>${certificate_request.domains_as_string}</code></td>
                % endif
            </tr>
        % endfor
        </tbody>
    </table>
</%def>


<%def name="table_queue_renewal__list(renewal_items, show_certificate=False)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>active?</th>
                % if show_certificate:
                    <th>certificate</th>
                % endif
                <th>timestamp_entered</th>
                <th>operations_event_id__created</th>
                <th>timestamp_processed</th>
                <th>timestamp_process_attempt</th>
                <th>result</th>
            </tr>
        </thead>
        <tbody>
        % for queue_renewal in renewal_items:
            <tr>
                <td><a href="${admin_prefix}/queue-renewal/${queue_renewal.id}" class="label label-info">
                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                    qrenew-${queue_renewal.id}</a>
                </td>
                <td>
                    <span class="label label-${'success' if queue_renewal.is_active else 'warning'}">
                        ${'active' if queue_renewal.is_active else 'no'}
                    </span>
                </td>
                % if show_certificate:
                    <td>
                        % if queue_renewal.server_certificate_id:
                            <a href="${admin_prefix}/certificate/${queue_renewal.server_certificate_id}" class="label label-info">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                cert-${queue_renewal.server_certificate_id}</a>
                        % endif
                    </td>
                % endif
                <td><timestamp>${queue_renewal.timestamp_entered or ''}</timestamp></td>
                <td><span class="label label-info">${queue_renewal.operations_event_id__created}</span></td>
                <td><timestamp>${queue_renewal.timestamp_processed or ''}</timestamp></td>
                <td><timestamp>${queue_renewal.timestamp_process_attempt or ''}</timestamp></td>
                <td>
                    % if queue_renewal.process_result is None:
                        &nbsp;
                    % elif queue_renewal.process_result is False:
                        <span class="label label-danger"><span class="glyphicon glyphicon-remove" aria-hidden="true"></span></span>
                    % elif queue_renewal.process_result is True:
                        <span class="label label-success"><span class="glyphicon glyphicon-ok" aria-hidden="true"></span></span>
                    % endif
                </td>
            </tr>
        % endfor
        </tbody>
    </table>
</%def>



<%def name="table_AcmeOrders(acme_orders, perspective=None)">
    % if perspective == 'CertificateRequest':
        <table class="table table-striped table-condensed">
            <thead>
                <tr>
                    <th>id</th>
                    <th>timestamp_created</th>
                    <th>timestamp_finalized</th>
                    <th>acme_account_key_id</th>
                    <th>server_certificate_id</th>
                </tr>
            </thead>
            <tbody>
                % for acme_order in acme_orders:
                    <tr>
                        <td>
                            <a href="${admin_prefix}/acme-order/${acme_order.id}" class="label label-info">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                acme-order-${acme_order.id}
                            </a>
                        </td>
                        <td><timestamp>${acme_order.timestamp_created or ''}</timestamp></td>
                        <td><timestamp>${acme_order.timestamp_finalized or ''}</timestamp></td>
                        <td>
                            <a href="${admin_prefix}/acme-account-key/${acme_order.acme_account_key_id}" class="label label-info">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                acme-account-key-${acme_order.acme_account_key_id}
                            </a>
                        </td>
                        <td>
                            <a href="${admin_prefix}/server-certificate/${acme_order.server_certificate_id}" class="label label-info">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                server-certificate-${acme_order.server_certificate_id}
                            </a>
                        </td>
                    </tr>
                % endfor
            </tbody>
        </table>
    % else:
        <!-- table_AcmeOrders missing perspective -->
    % endif
</%def>
    

<%def name="table_UniqueFqdnSet_Domains(unique_fqdn_set, perspective=None)">
    % if perspective == 'CertificateRequest':
        <table class="table table-striped table-condensed">
            <thead>
                <tr>
                    <th>domain</th>
                </tr>
            </thead>
            <tbody>
                % for to_d in unique_fqdn_set.to_domains:
                    <tr>
                        <td>
                            <a href="${admin_prefix}/domain/${to_d.domain.id}" class="label label-info">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                domain-${to_d.domain.id}
                            </a>
                            <code>${to_d.domain.domain_name}</code>
                        </td>
                    </tr>
                % endfor
            </tbody>
        </table>
    % else:
        <!-- table_UniqueFqdnSet_Domains missing perspective -->
    % endif
</%def>
        


<%def name="table_CertificateRequest2Domain(lcr2mds, request_inactive=None, current_domain_id=None, perspective=None)">
    % if perspective == 'CertificateRequest':
        <% raise ValueError("deprecated") %>
    % elif perspective == 'certificate_request_sidebar':
        <table class="table table-striped table-condensed">
            <thead>
                <tr>
                    <th>current?</th>
                    <th>domain</th>
                    <th>configured?</th>
                    <th>verified?</th>
                    <th>test</th>
                </tr>
            </thead>
            <tbody>
            % for to_d in CertificateRequest.unique_fqdn_set.to_domains:
                <tr>
                    <td>
                        % if current_domain_id == to_d.domain_id:
                            <span class="label label-success">current</span>
                        % endif
                    </td>
                    <td>
                        <span class="label label-default"
                        >
                            ${to_d.domain.domain_name}
                        </span>
                    </td>
                    <td>
                        % if current_domain_id == to_d.domain_id:
                            % if to_d.is_configured:
                                <span
                                    class="label label-success">configured</span>
                            % else:
                                <span
                                    class="label label-warning">not configured</span>
                            % endif
                        % else:
                            % if to_d.is_configured:
                                <a
                                    href="${admin_prefix}/certificate-request/${CertificateRequest.id}/acme-flow/manage/domain/${to_d.domain_id}"
                                    class="label label-success">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    configured</a>
                            % else:
                                <a href="${admin_prefix}/certificate-request/${CertificateRequest.id}/acme-flow/manage/domain/${to_d.domain_id}"
                                    class="label label-warning">
                                    % if request_inactive:
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                         not configured
                                    % else:
                                        <span class="glyphicon glyphicon-wrench" aria-hidden="true"></span>
                                        configure
                                    % endif
                                    </a>
                            % endif
                        % endif
                    </td>
                    <td>
                        % if to_d.timestamp_verified:
                            <span class="label label-success">verified</span>
                        % else:
                            &nbsp;
                        % endif
                    </td>
                    <td>
                        % if to_d.is_configured:
                            <a  class="label label-info"
                                target="_blank"
                                href="http://${to_d.domain.domain_name}/.well-known/acme-challenge/${to_d.challenge_key}?test=1"
                            >
                                <span class="glyphicon glyphicon-link" aria-hidden="true"></span>
                                test
                            </a>
                        % endif
                    </td>
                </tr>
            % endfor
            </tbody>
        </table>

    % else:
        <!-- table_CertificateRequest2Domain missing perspective -->
    % endif
</%def>


<%def name="table_UniqueFQDNSets(UniqueFQDNSets)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>timestamp first seen</th>
                <th>domain ids string</th>
            </tr>
        </thead>
        <tbody>
        % for i in UniqueFQDNSets:
            <tr>
                <td>
                    <a  class="label label-info"
                        href="${admin_prefix}/unique-fqdn-set/${i.id}"
                    >
                     <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                     fqdnset-${i.id}
                    </a>
                </td>
                <td>
                    <timestamp>${i.timestamp_first_seen}</timestamp>
                </td>
                <td>
                    <code>${i.domain_ids_string}</code>
                </td>
            </tr>
        % endfor
        </tbody>
    </table>
</%def>


<%def name="table_OperationsEvents(OperationsEvents, show_event=None, event_type_listable=None)">
    <%
        event_id = None
        if show_event is not None:
            event_id = request.params.get('event.id')
    %>
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>child of</th>
                <th>event_type</th>
                <th>event timestamp</th>
            </tr>
        </thead>
        <tbody>
            % for event in OperationsEvents:
                <tr class="${'success' if event_id == str(event.id) else ''}">
                    <td>
                        <a  href="${admin_prefix}/operations/log/item/${event.id}"
                            class="label label-info"
                        >
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            ${event.id}
                        </a>
                    </td>
                    <td>
                        % if event.operations_event_id__child_of:
                            <span class="label label-default">${event.operations_event_id__child_of}</span>
                        % endif
                    </td>
                    <td>
                        % if event_type_listable:
                            <a  href="${admin_prefix}/operations/log?event_type=${event.event_type_text}"
                                class="label label-default"
                            >
                                ${event.event_type_text}
                            </a>
                        % else:
                            <span class="label label-default">${event.event_type_text}</span>
                        % endif
                    </td>
                    <td><timestamp>${event.timestamp_event}</timestamp></td>
                </tr>
            % endfor
        </tbody>
    </table>
</%def>


<%def name="table_OperationsObjectEvents(OperationsObjectEvents, table_context=None)">
    <%
        show_event = True
        if table_context == "log_list":
            pass
    %>
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                % if show_event:
                    <th>event: id</th>
                    <th>event: type</th>
                    <th>event: timestamp</th>
                % endif
                <th>id</th>
                <th>event status</th>
                <th>object</th>
            </tr>
        </thead>
        <tbody>
            % for object_event in OperationsObjectEvents:
                <tr>
                    % if show_event:
                        <td>
                            <a class="label label-info" href="${admin_prefix}/operations/log/item/${object_event.operations_event_id}">
                                ${object_event.operations_event_id}
                            </a>
                        </td>
                        <td>
                            <code>
                                ${object_event.operations_event.event_type_text}
                            </code>
                        </td>
                        <td>
                            <timestamp>
                                ${object_event.operations_event.timestamp_event}
                            </timestamp>
                        </td>
                    % endif
                    <td>
                        <a class="label label-info" href="${admin_prefix}/operations/object-log/item/${object_event.id}">
                            ${object_event.id}
                        </a>
                    </td>
                    <td>
                        <code>
                            ${object_event.event_status_text}
                        </code>
                    </td>
                    <td>
                        ${object_event__object(object_event)}
                    </td>
                </tr>
            % endfor
        </tbody>
    </table>
</%def>


<%def name="object_event__object(object_event)">
                        % if object_event.ca_certificate_id:
                            <a class="label label-info" href="${admin_prefix}/ca-certificate/${object_event.ca_certificate_id}">
                                CaCert
                                ${object_event.ca_certificate_id}
                            </a>
                        % elif object_event.certificate_request_id:
                            <a class="label label-info" href="${admin_prefix}/certificate-request/${object_event.certificate_request_id}">
                                CSR
                                ${object_event.certificate_request_id}
                            </a>
                        % elif object_event.domain_id:
                            <a class="label label-info" href="${admin_prefix}/domain/${object_event.domain_id}">
                                Domain
                                ${object_event.domain_id}
                            </a>
                            <code>${object_event.domain.domain_name}</code>
                        % elif object_event.acme_account_key_id:
                            <a class="label label-info" href="${admin_prefix}/acme-account-key/${object_event.acme_account_key_id}">
                                AccountKey
                                ${object_event.acme_account_key_id}
                            </a>
                        % elif object_event.private_key_id:
                            <a class="label label-info" href="${admin_prefix}/private-key/${object_event.private_key_id}">
                                Private Key
                                ${object_event.private_key_id}
                            </a>
                        % elif object_event.queue_domain_id:
                            <a class="label label-info" href="${admin_prefix}/queue-domain/${object_event.queue_domain_id}">
                                q-Domain
                                ${object_event.queue_domain_id}
                            </a>
                            <code>${object_event.queue_domain.domain_name}</code>
                        % elif object_event.queue_renewal_id:
                            <a class="label label-info" href="${admin_prefix}/queue-renewal/${object_event.queue_renewal_id}">
                                q-Renewal
                                ${object_event.queue_renewal_id}
                            </a>
                        % elif object_event.server_certificate_id:
                            <a class="label label-info" href="${admin_prefix}/certificate/${object_event.server_certificate_id}">
                                Cert
                                ${object_event.server_certificate_id}
                            </a>
                        % elif object_event.unique_fqdn_set_id:
                            <a class="label label-info" href="${admin_prefix}/unique-fqdn-set/${object_event.unique_fqdn_set_id}">
                                uFQDN
                                ${object_event.unique_fqdn_set_id}
                            </a>
                        % endif
</%def>


<%def name="info_AcmeAccountKey()">
    <h3>Need an Acme Account Key?</h3>
        <p>Use an Existing LetsEncrypt key from their client.
           This is the easiest way to register with LetsEncrypt and opt into their TOS.
        </p>
</%def>


<%def name="info_PrivateKey()">
    <h3>Need a Private Key?</h3>
        <p>NOTE: you can not use your account private key as your private key for signing domains!</p>
        <p>
            <code>openssl genrsa 4096 > domain.key</code>
        </p>
</%def>


<%def name="info_CACertificate()">
    <h3>What are CA Certificates?</h3>
    <p>
        These are the trusted(?) certs that CertificateAuthorities use to sign your certs.  They are used for building fullchains.
        Often these are called 'chain.pem'.
    </p>
</%def>


<%def name="formgroup__account_key_selector_advanced(dbAcmeAccountKeyReuse=None)">
    % if dbAcmeAccountKeyReuse:
        <div class="radio">
            <label>
                <input type="radio" name="account_key_option" id="account_key_option-account_key_reuse" value="account_key_reuse" checked="checked"/>
                <input type="hidden" name="account_key_reuse" value="${dbAcmeAccountKeyReuse.key_pem_md5}"/>
                Select to renew with same Acme Account Key<br/>
                <b>pem md5:</b> <code>${dbAcmeAccountKeyReuse.key_pem_md5}</code><br/>
                <b>pem line 1:</b> <code>${dbAcmeAccountKeyReuse.key_pem_sample}</code>
            </label>
            <a  class="label label-info"
                href="${admin_prefix}/acme-account-key/${dbAcmeAccountKeyReuse.id}"
            >
                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                account-${dbAcmeAccountKeyReuse.id}
            </a>
        </div>
    % endif
    % if dbAcmeAccountKeyDefault:
        <div class="radio">
            <label>
                <input type="radio" name="account_key_option" id="account_key_option-account_key_default" value="account_key_default"/>
                <input type="hidden" name="account_key_default" value="${dbAcmeAccountKeyDefault.key_pem_md5}"/>
                Select to use the default Acme Account Key<br/>
                <b>pem md5:</b> <code>${dbAcmeAccountKeyDefault.key_pem_md5}</code><br/>
                <b>pem line 1:</b> <code>${dbAcmeAccountKeyDefault.key_pem_sample}</code>
            </label>
        </div>
    % endif
    <div class="radio">
        <label>
            <input type="radio" name="account_key_option" id="account_key_option-account_key_existing" value="account_key_existing"/>
            Select to provide a different existing key (as pem_md5).
        </label>
        <label>
            <input class="form-control" name="account_key_existing" id="account_key_existing-pem_md5" type="text"/>
        </label>
    </div>
    <div class="radio">
        <label>
            <input type="radio" name="account_key_option" id="account_key_option-account_key_file" value="account_key_file">
            Select to upload a new Acme Account Key<br/>
        </label>
        <label>
            ${formgroup__account_key_file()}
        </label>
    </div>
</%def>


<%def name="formgroup__private_key_selector(show_text=None)">
    <h4>Private Key</h4>
        % if dbPrivateKeyDefault:
            <div class="checkbox">
                <label>
                    <input type="checkbox" name="private_key_default" id="f1-private_key_default" value="${dbPrivateKeyDefault.key_pem_md5}"/>
                    Check this box to use the default.<br/>
                    <b>pem md5:</b> <code>${dbPrivateKeyDefault.key_pem_md5}</code><br/>
                    <b>pem line 1:</b> <code>${dbPrivateKeyDefault.key_pem_sample}</code>
                </label>
            </div>
        % else:
            <p>No default.</p>
        % endif
    <h5>Use Default</h5>
    <h5>or Use Existing</h5>
        <div class="form-group">
            <label for="f1-private_key_existing">Other existing key (pem md5)</label>
            <input class="form-control" name="private_key_existing" id="f1-private_key_existing" type="text"/>
        </div>
    <h5>or Upload File</h5>
        ${formgroup__private_key_file(show_text=show_text, header=None)}
</%def>


<%def name="formgroup__private_key_selector_advanced(show_text=None, dbPrivateKeyReuse=None)">
    % if dbPrivateKeyReuse:
        <div class="radio">
            <label>
                <input type="radio" name="private_key_option" id="private_key_option-private_key_reuse" value="private_key_reuse" checked="checked"/>
                <input type="hidden" name="private_key_reuse" value="${dbPrivateKeyReuse.key_pem_md5}"/>
                Select to renew with same RSA Private Key<br/>
                <b>pem md5:</b> <code>${dbPrivateKeyReuse.key_pem_md5}</code><br/>
                <b>pem line 1:</b> <code>${dbPrivateKeyReuse.key_pem_sample}</code>
            </label>
            <a  class="label label-info"
                href="${admin_prefix}/private-key/${dbPrivateKeyReuse.id}"
            >
                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                private-${dbPrivateKeyReuse.id}
            </a>
        </div>
    % endif
    <div class="radio">
        <label>
            <input type="radio" name="private_key_option" id="private_key_option-private_key_existing" value="private_key_existing"/>
            Select to provide a different existing RSA Private key (as pem_md5).
        </label>
        <label>
            <input class="form-control" name="private_key_existing" id="private_key_existing-pem_md5" type="text"/>
        </label>
    </div>
    <div class="radio">
        <label>
            <input type="radio" name="private_key_option" id="private_key_option-private_key_file" value="private_key_file">
            Select to upload a new RSA Private Key<br/>
        </label>
        <label>
            ${formgroup__private_key_file(show_text=False)}
        </label>
    </div>
</%def>


<%def name="formgroup__account_key_file(show_header=True)">
    <div class="form-group">
        <label for="f1-account_key_file_pem">Acme Account Key: PEM</label>
        <p class="help-block">
            Enter your LetsEncrypt registered AccountKey in PEM format. This is used when requesting the ACME server sign your certificates.
        </p>
        <input class="form-control" type="file" id="f1-account_key_file_pem" name="account_key_file_pem" />
        <div class="form-group">
            <label for="f1-account_key_file_le_meta">Acme Account Key: LetsEncrypt meta.json</label>
            <select class="form-control" id="f1-acme_account_provider_id" name="acme_account_provider_id" />
                % for option in AcmeAccountProviderOptions:
                    <option value="${option['id']}" ${'selected' if option['is_default'] else ''}>${option['name']}</option>
                % endfor
            </select>
        </div>
        <hr/>
        or
        <hr/>
        <p class="help-block">
            Enter your LetsEncrypt registered AccountKey in PEM format. This is used when requesting the ACME server sign your certificates.
            The provider will be auto-detected.
        </p>
        <label for="f1-account_key_file_le_meta">Acme Account Key: LetsEncrypt meta.json</label>
        <input class="form-control" type="file" id="f1-account_key_file_le_meta" name="account_key_file_le_meta" />
        <label for="f1-account_key_file_le_pkey">Acme Account Key: LetsEncrypt private_key.json</label>
        <input class="form-control" type="file" id="f1-account_key_file_le_pkey" name="account_key_file_le_pkey" />
        <label for="f1-account_key_file_le_reg">Acme Account Key: LetsEncrypt regr.json</label>
        <input class="form-control" type="file" id="f1-account_key_file_le_reg" name="account_key_file_le_reg" />
    </div>
</%def>


<%def name="formgroup__private_key_file(show_text=False, header=True)">
    <div class="form-group clearfix">
        % if header:
            <label for="f1-private_key_file">Private Key</label>
        % endif
        <input class="form-control" type="file" id="f1-private_key_file" name="private_key_file" />
        <p class="help-block">
            Enter your PRIVATE key used to sign CSRs above in PEM format; this will be used to create a CSR used for configuring servers/chains and matched against existing issued certs.
            This WILL be saved.
        </p>
        % if show_text:
            <label for="f1-private_key">Private Key [text]</label>
            <textarea class="form-control" rows="4" name="private_key" id="f1-private_key"></textarea>
            <p class="help-block">
                Alternately, provide text inline.
            </p>
        % endif
    </div>
</%def>


<%def name="formgroup__certificate_file(show_text=False)">
    <div class="form-group clearfix">
        <label for="f1-certificate_file">Signed Certificate</label>
        <input class="form-control" type="file" id="f1-certificate_file" name="certificate_file" />
        <p class="help-block">
            Enter a Signed Certificate above in PEM format.
            This is something that has been signed by a CA.
        </p>
        % if show_text:
            <label for="f1-certificate">Signed Certificate [text]</label>
            <textarea class="form-control" rows="4" name="certificate" id="f1-certificate"></textarea>
            <p class="help-block">
                Alternately, provide text inline.
            </p>
        % endif
    </div>
</%def>


<%def name="formgroup__chain_file(show_text=False)">
    <div class="form-group clearfix">
        <label for="f1-chain_file">Chain File</label>
        <input class="form-control" type="file" id="f1-chain_file" name="chain_file" />
        <p class="help-block">
            This should be the public cert of the upstream signer.
        </p>
        % if show_text:
            <label for="f1-chain">Chain File [text]</label>
            <textarea class="form-control" rows="4" name="chain" id="f1-chain"></textarea>
            <p class="help-block">
                Alternately, provide text inline.
            </p>
        % endif
    </div>
</%def>



<%def name="formgroup__chain_bundle_file(CA_CROSS_SIGNED_X=None, CA_AUTH_X=None)">
    <div class="form-group clearfix">
        <label for="f1-isrgrootx1_file">ISRG Root X1</label>
        <input class="form-control" type="file" id="f1-isrgrootx1_file" name="isrgrootx1_file" />
        <p class="help-block">
            As linked to from https://letsencrypt.org/certificates/
        </p>
    </div>
    <hr/>

    % for xi in CA_AUTH_X:
        <div class="form-group clearfix">
            <label for="f1-le_${xi}_auth_file">Let’s Encrypt Authority ${xi}</label>
            <input class="form-control" type="file" id="f1-le_${xi}_auth_file" name="le_${xi}_auth_file" />
            <p class="help-block">
                As linked to from https://letsencrypt.org/certificates/
            </p>
        </div>
        <hr/>
    % endfor

    % for xi in CA_CROSS_SIGNED_X:
        <div class="form-group clearfix">
            <label for="f1-le_${xi}_cross_signed_file">Let’s Encrypt Authority ${xi} (IdenTrust cross-signed)</label>
            <input class="form-control" type="file" id="f1-le_${xi}_cross_signed_file" name="le_${xi}_cross_signed_file" />
            <p class="help-block">
                As linked to from https://letsencrypt.org/certificates/
            </p>
        </div>
        <hr/>
    % endfor

</%def>


<%def name="formgroup__domain_names()">
    <div class="form-group clearfix">
        <label for="f1-domain_names">Domain Names</label>
        <textarea class="form-control" rows="4" name="domain_names" id="f1-domain_names"></textarea>
        <p class="help-block">
            A comma(,) separated list of domain names.
        </p>
    </div>
</%def>


<%def name="nav_pagination(pager)">
    <% if not pager: return '' %>
    <center>
        <nav>
            <ul class="pagination">
                % if pager.start > 1:
                    <li>
                        <a href="${pager.template.format(max(pager.current-pager.range_num, 1))}" aria-label="Previous">
                            <span aria-hidden="true">&laquo;</span>
                        </a>
                    </li>
                % endif
                % for p in pager.pages:
                    <li ${'class="active"' if pager.current == p else ''|n}><a href="${pager.template.format(p)}">${p}</a></li>
                % endfor
                % if pager.end < pager.page_num:
                    <li>
                        <a href="${pager.template.format(min(pager.start+pager.range_num, pager.page_num-pager.range_num))}" aria-label="Next">
                            <span aria-hidden="true">&raquo;</span>
                        </a>
                    </li>
                % endif
            </ul>
        </nav>
    </center>
</%def>


<%def name="nav_pager(see_all_url, see_all_text='See All')">
    <nav>
      <ul class="pager">
        <li>
            <a
                href="${see_all_url}"
            >${see_all_text}</a>
        </li>
      </ul>
    </nav>
</%def>


<%def name="operations_options(enable_redis=False, enable_nginx=False, as_list=None, active=None)">
    <h4>Log</h4>
    <ul class="nav nav-pills nav-stacked">
        <li class="${'active' if active =='/operations/log' else ''}">
            <a  href="${admin_prefix}/operations/log"
            >
            <span class="glyphicon glyphicon-folder-open" aria-hidden="true"></span>
            Full Operations Log</a></li>
        % if enable_redis:
            <li class="${'active' if active =='/operations/redis' else ''}">
                <a  href="${admin_prefix}/operations/redis"
                >
                <span class="glyphicon glyphicon-folder-open" aria-hidden="true"></span>
                Operations Log: Redis</a></li>
        % endif
        % if enable_nginx:
            <li class="${'active' if active =='/operations/nginx' else ''}">
                <a  href="${admin_prefix}/operations/nginx"
                >
                <span class="glyphicon glyphicon-folder-open" aria-hidden="true"></span>
                Operations Log: Nginx</a></li>
        % endif
        <li class="${'active' if active =='/operations/ca-certificate-probes' else ''}">
            <a  href="${admin_prefix}/operations/ca-certificate-probes"
            >
            <span class="glyphicon glyphicon-folder-open" aria-hidden="true"></span>
            Operations Log: CA Certificate Probes</a></li>
        <li class="${'active' if active =='/operations/object-log' else ''}">
            <a  href="${admin_prefix}/operations/object-log"
            >
            <span class="glyphicon glyphicon-folder-open" aria-hidden="true"></span>
            Object Log</a></li>
    </ul>

    <h4>Actions</h4>
    <ul class="nav nav-pills nav-stacked">
        <li class="${'active' if active =='/api/deactivate-expired' else ''}">
            <a  href="${admin_prefix}/api/deactivate-expired"
            >
             <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
             Deactivate Expired Certificates</a></li>
        <li class="${'active' if active =='/api/update-recents' else ''}">
            <a  href="${admin_prefix}/api/update-recents"
            >
             <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
             Update Recents</a></li>
        % if enable_redis:
            <li>
                <a  href="${admin_prefix}/api/redis/prime"
                >
                    <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                    Prime Redis Cache
                </a>
            </li>
            <li>
                <a  href="${admin_prefix}/api/redis/prime.json"
                >
                    <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                    Prime Redis Cache - JSON
                </a>
            </li>
        % endif
        % if enable_nginx:
            <li>
                <a  href="${admin_prefix}/api/nginx/cache-flush"
                >
                    <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                    Flush Nginx Cache
                </a>
            </li>
            <li>
                <a  href="${admin_prefix}/api/nginx/cache-flush.json"
                >
                    <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                    Flush Nginx Cache - JSON
                </a>
            </li>
        % endif
    </ul>
</%def>


<%def name="standard_error_display(has_message=None)">
    <%
        error = request.params.get('error', None)
        message = request.params.get('message', None)
    %>
    % if error:
        <div class="alert alert-danger">
            ## operation=mark&action=deactivate&result=error&error=Can%20not%20deactivate%20the%20default
            <b>Error</b>
            <p>
                % if has_message:
                    ${message}
                % else:
                    ${error}
                % endif
            </p>
        </div>
    % endif
</%def>


<%def name="domains_section_nav()">
    <ul class="nav nav-pills nav-stacked">
      <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="${admin_prefix}/domains">All Domains</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'expiring' else ''}"><a href="${admin_prefix}/domains/expiring">Expiring Domains</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'search' else ''}"><a href="${admin_prefix}/domains/search">Search Domains</a></li>
    </ul>
    <p class="pull-right">
        % if sidenav_option == 'expiring' :
            <a href="${admin_prefix}/domains/expiring.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        % elif sidenav_option == 'all' :
            <a href="${admin_prefix}/domains.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        % elif sidenav_option == 'search' :
            <a href="${admin_prefix}/domains/search.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        % endif
    </p>
</%def>


<%def name="handle_querystring_result()">
    <% result =  request.params.get('result', '') %>
    % if result == 'success':
        <div class="alert alert-success">
            The operation `${request.params.get('operation')}` was successful.
        </div>
    % elif result == 'error':
        <div class="alert alert-danger">
            The operation `${request.params.get('operation')}` was not successful.
        </div>
    % endif
</%def>
