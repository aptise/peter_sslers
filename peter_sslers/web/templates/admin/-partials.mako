<%def name="table_tr_OperationsEventCreated(dbObject)">
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



<%def name="table_AcmeAuthorizations(data, perspective=None)">
    <%
        cols = ("id", 
                "domain_id",
                "status",
                "timestamp_created",
                "timestamp_expires",
                "timestamp_updated",
                "acme_order_id__created",
                "wildcard",
               )
        if perspective == 'AcmeAccountKey':
            cols = [c for c in cols]
        elif perspective == 'AcmeOrder.to_acme_authorizations':
            cols = [c for c in cols if c != 'acme_order_id__created']
            data = [d.acme_authorization for d in data.to_acme_authorizations]
        elif perspective == 'AcmeAuthorizations':
            cols = [c for c in cols]
        elif perspective == 'Domain':
            cols = [c for c in cols if c != 'domain_id']
        else:
            raise ValueError("invalid `perspective`")
    %>
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                % for c in cols:
                    <th>${c}</th>
                % endfor
            </tr>
        </thead>
        <tbody>
            % for acme_authorization in data:
                <tr>
                    % for c in cols:
                        <td>
                            % if c == 'id':
                                <a href="${admin_prefix}/acme-authorization/${acme_authorization.id}" class="label label-info">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeAuthorization-${acme_authorization.id}
                                </a>
                            % elif c == 'status':
                                <code>${acme_authorization.acme_status_authorization or ''}</code>
                            % elif c == 'domain_id':
                                % if acme_authorization.domain_id:
                                    <a class="label label-info" href="${admin_prefix}/domain/${acme_authorization.domain_id}">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        Domain-${acme_authorization.domain_id}
                                    </a>
                                % endif
                            % elif c == 'timestamp_created':
                                <timestamp>${acme_authorization.timestamp_created or ''}</timestamp>
                            % elif c == 'timestamp_expires':
                                <timestamp>${acme_authorization.timestamp_expires or ''}</timestamp>
                            % elif c == 'timestamp_expires':
                                <timestamp>${acme_authorization.timestamp_updated or ''}</timestamp>
                            % elif c == 'wildcard':
                                <code>${acme_authorization.wildcard or ''}</code>
                            % elif c == 'acme_order_id__created':
                                % if acme_authorization.acme_order_id__created:
                                    <a class="label label-info" href="${admin_prefix}/acme-order/${acme_authorization.acme_order_id__created}">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        Order-${acme_authorization.acme_order_id__created}
                                    </a>
                                % endif
                            % endif
                        </td>
                    % endfor
                </tr>
            % endfor
        </tbody>
    </table>
</%def>
    


<%def name="table_AcmeChallenges(acme_challenges, perspective=None)">
    <table class="table table-striped">
        <thead>
            <tr>
                <th>id</th>
                <th>timestamp_created</th>
                <th>acme_challenge_type</th>
                <th>status</th>
                <th>token</th>
                <th>timestamp_updated</th>
            </tr>
        </thead>
        <tbody>
        % for item in acme_challenges:
            <tr>
                <td><a class="label label-info" href="${admin_prefix}/acme-challenge/${item.id}">
                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                    ${item.id}</a></td>
                <td><timestamp>${item.timestamp_created}</timestamp></td>
                <td><span class="label label-default">${item.acme_challenge_type}</span></td>
                <td><code>${item.acme_status_challenge}</code></td>
                <td><code>${item.token}</code></td>
                <td><timestamp>${item.timestamp_updated}</timestamp></td>
            </tr>
        % endfor
        </tbody>
    </table>
</%def>


<%def name="table_AcmeOrderlesss(acme_orderlesss, perspective=None)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>is active</th>
                <th>timestamp_created</th>
                <th>timestamp_finalized</th>
            </tr>
        </thead>
        <tbody>
            % for order_ in acme_orderlesss:
                <tr>
                    <td>
                        <a href="${admin_prefix}/acme-orderless/${order_.id}" class="label label-info">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            AcmeOrderless-${order_.id}
                        </a>
                    </td>
                    <td>
                        % if order_.is_active:
                            <div class="label label-success">
                                <span class="glyphicon glyphicon-ok" aria-hidden="true"></span>
                            </div>
                        % else:
                            <div class="label label-danger">
                                <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                            </div>
                        % endif
                    </td>
                    <td><timestamp>${order_.timestamp_created or ''}</timestamp></td>
                    <td><timestamp>${order_.timestamp_finalized or ''}</timestamp></td>
                </tr>
            % endfor
        </tbody>
    </table>
</%def>


<%def name="table_AcmeOrders(acme_orders, perspective=None)">
    <%
        cols = ("id", 
                "is_active",
                "status",
                "timestamp_created",
                "timestamp_finalized",
                "acme_account_key_id",
                "certificate_request_id",
                "server_certificate_id",
                "unique_fqdn_set_id",
               )
        if perspective == 'AcmeOrders':
            cols = [c for c in cols if c != 'certificate_request_id']
        elif perspective == 'CertificateRequest':
            cols = [c for c in cols if c != 'certificate_request_id']
        elif perspective == 'Domain':
            cols = [c for c in cols]
        elif perspective == 'AcmeAuthorization':
            cols = [c for c in cols]
        elif perspective == 'AcmeAccountKey':
            cols = [c for c in cols if c != "acme_account_key_id"]
        elif perspective == 'UniqueFQDNSet':
            cols = [c for c in cols if c != "unique_fqdn_set_id"]
        else:
            raise ValueError("invalid `perspective`")
    %>
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                % for c in cols:
                    <th>${c}</th>
                % endfor
            </tr>
        </thead>
        <tbody>
            % for acme_order in acme_orders:
                <tr>
                    % for c in cols:
                        <td>
                            % if c == 'id':
                                <a href="${admin_prefix}/acme-order/${acme_order.id}" class="label label-info">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeOrder-${acme_order.id}
                                </a>
                            % elif c == 'is_active':
                                % if acme_order.is_active:
                                    <div class="label label-success">
                                        <span class="glyphicon glyphicon-ok" aria-hidden="true"></span>
                                    </div>
                                % else:
                                    <div class="label label-danger">
                                        <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                    </div>
                                % endif
                            % elif c == 'status':
                                <code>${acme_order.acme_status_order or ''}</code>
                            % elif c == 'timestamp_created':
                                <timestamp>${acme_order.timestamp_created or ''}</timestamp>
                            % elif c == 'timestamp_finalized':
                                <timestamp>${acme_order.timestamp_finalized or ''}</timestamp>
                            % elif c == 'acme_account_key_id':
                                % if acme_order.acme_account_key_id:
                                    <a href="${admin_prefix}/acme-account-key/${acme_order.acme_account_key_id}" class="label label-info">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        AcmeAccountKey-${acme_order.acme_account_key_id}
                                    </a>
                                % endif
                            % elif c == 'certificate_request_id':
                                % if acme_order.certificate_request_id:
                                    <a href="${admin_prefix}/certificate-request/${acme_order.certificate_request_id}" class="label label-info">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        CertificateRequest-${acme_order.certificate_request_id}
                                    </a>
                                % endif
                            % elif c == 'server_certificate_id':
                                % if acme_order.server_certificate_id:
                                    <a href="${admin_prefix}/server-certificate/${acme_order.server_certificate_id}" class="label label-info">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        Certificate-${acme_order.server_certificate_id}
                                    </a>
                                % endif
                            % elif c == 'unique_fqdn_set_id':
                                % if acme_order.unique_fqdn_set_id:
                                    <a href="${admin_prefix}/unique-fqdn-set/${acme_order.unique_fqdn_set_id}" class="label label-info">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        UniqueFQDNSet-${acme_order.unique_fqdn_set_id}
                                    </a>
                                % endif
                            % endif
                        </td>
                    % endfor
                </tr>
            % endfor
        </tbody>
    </table>
</%def>
    

<%def name="table_CertificateRequests(certificate_requests, perspective=None)">
    <%
        show_domains = True if perspective in ("PrivateKey", 'CertificateRequest', ) else False
        show_certificate = True if perspective in ("ServerCertificate", 'CertificateRequest', ) else False
    %>
    <%
        cols = ("id", 
                "type"
                "timestamp_created",
                "certificate_request_source_id",
                "unique_fqdn_set_id",
               )
        if perspective == 'AcmeAccountKey':
            cols = [c for c in cols]
        elif perspective == 'CertificateRequest':
            cols = [c for c in cols]
        elif perspective == 'Domain':
            cols = [c for c in cols]
        elif perspective == 'PrivateKey':
            cols = [c for c in cols if c != 'private_key_id']
        elif perspective == 'ServerCertificate':
            cols = [c for c in cols]
        elif perspective == 'UniqueFQDNSet':
            cols = [c for c in cols if c != 'unique_fqdn_set_id']
        else:
            raise ValueError("invalid `perspective`")
    %>
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                % for c in cols:
                    <th>${c}</th>
                % endfor
                % if show_domains:
                     <th>domains</th>
                % endif
            </tr>
        </thead>
        <tbody>
            % for certificate_request in certificate_requests:
                <tr>
                    % for c in cols:
                        <td>
                            % if c == 'id':
                                <a  class="label label-info"
                                    href="${admin_prefix}/certificate-request/${certificate_request.id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    CertificateRequest-${certificate_request.id}</a>
                            % elif c == 'type':
                                <span class="label label-default">${certificate_request.certificate_request_source}</span>
                            % elif c == 'timestamp_created':
                                <timestamp>${certificate_request.timestamp_created}</timestamp>
                            % elif c == 'certificate_request_source_id':
                                % if certificate_request.certificate_request_source_id:
                                    ## <code>${certificate_request.certificate_request_source_id}</code>
                                    <span class="label label-default">${model_websafe.CertificateRequestSource.as_string(certificate_request.certificate_request_source_id)}</span>
                                % endif
                            % elif c == 'unique_fqdn_set_id':
                                <a  class="label label-info"
                                    href="${admin_prefix}/unique-fqdn-set/${certificate_request.unique_fqdn_set_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    UniqueFQDNSet-${certificate_request.unique_fqdn_set_id}</a>
                            % endif
                        </td>
                        % if show_domains:
                             <td><code>${certificate_request.domains_as_string}</code></td>
                        % endif
                    % endfor
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
                            <code>${object_event.operations_event.event_type_text}</code>
                        </td>
                        <td>
                            <timestamp>${object_event.operations_event.timestamp_event}</timestamp>
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


<%def name="table_QueueRenewal(renewal_items, perspective=None)">
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
                                Certificate-${queue_renewal.server_certificate_id}</a>
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



<%def name="table_ServerCertificates(certificates, perspective=None, show_domains=False, show_expiring_days=False)">
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
                    Certificate-${cert.id}</a>
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



<%def name="table_UniqueFQDNSets(unique_fqdn_sets, perspective=None)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>timestamp first seen</th>
                <th>domain ids string</th>
            </tr>
        </thead>
        <tbody>
        % for i in unique_fqdn_sets:
            <tr>
                <td>
                    <a  class="label label-info"
                        href="${admin_prefix}/unique-fqdn-set/${i.id}"
                    >
                     <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                     UniqueFQDNSet-${i.id}
                    </a>
                </td>
                <td>
                    <timestamp>${i.timestamp_created}</timestamp>
                </td>
                <td>
                    <code>${i.domain_ids_string}</code>
                </td>
            </tr>
        % endfor
        </tbody>
    </table>
</%def>


<%def name="table_UniqueFQDNSet_Domains(unique_fqdn_set, perspective=None)">
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
                                Domain-${to_d.domain.id}
                            </a>
                            <code>${to_d.domain.domain_name}</code>
                        </td>
                    </tr>
                % endfor
            </tbody>
        </table>
    % else:
        <!-- table_UniqueFQDNSet_Domains missing perspective -->
    % endif
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
    <h3>Need an AcmeAccountKey?</h3>
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


<%def name="formgroup__AcmeAccountKey_selector__advanced(dbAcmeAccountKeyReuse=None)">
    <p>Select an AcmeAccountKey with one of the following options</p>
    <div class="form-horizontal">
        % if dbAcmeAccountKeyReuse:
            <div class="radio">
                <label>
                    <input type="radio" name="account_key_option" id="account_key_option-account_key_reuse" value="account_key_reuse" checked="checked"/>
                    <input type="hidden" name="account_key_reuse" value="${dbAcmeAccountKeyReuse.key_pem_md5}"/>
                    Select to renew with the same AcmeAccountKey
                </label>
                <p class="form-control-static">
                    <b>pem md5:</b> <code>${dbAcmeAccountKeyReuse.key_pem_md5}</code><br/>
                    <b>pem line 1:</b> <code>${dbAcmeAccountKeyReuse.key_pem_sample}</code><br/>
                    <a  class="label label-info"
                        href="${admin_prefix}/acme-account-key/${dbAcmeAccountKeyReuse.id}"
                    >
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        AcmeAccountKey-${dbAcmeAccountKeyReuse.id}
                    </a>
                </p>
            </div>
        % endif
        % if AcmeAccountKey_Default:
            <div class="radio">
                <label>
                    <input type="radio" name="account_key_option" id="account_key_option-account_key_default" value="account_key_default"/>
                    The default AcmeAccountKey.
                </label>
                <p class="form-control-static">
                    <b>pem md5:</b> <code>${AcmeAccountKey_Default.key_pem_md5}</code><br/>
                    <b>pem line 1:</b> <code>${AcmeAccountKey_Default.key_pem_sample}</code>
                    <input type="hidden" name="account_key_default" value="${AcmeAccountKey_Default.key_pem_md5}"/>
                </p>
            </div>
        % else:
            <div class="alert alert-warning">
                <span class="glyphicon glyphicon-exclamation-sign" aria-hidden="true"></span>
                There is no Default AcmeAccountKey configured. Any key can be configured as the System Default.
                Browse keys at 
                <a  class="label label-info"
                    href="${admin_prefix}/acme-account-keys"
                >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    AcmeAccountKeys
                </a>
            </div>
        % endif
        <div class="radio">
            <label for="account_key_option-account_key_existing">
                <input type="radio" name="account_key_option" id="account_key_option-account_key_existing" value="account_key_existing"/>
                The PEM MD5 of an AcmeAccountKey already enrolled in the system.
            </label>
            <div class="form-control-static">
               <input class="form-control" name="account_key_existing" id="account_key_existing-pem_md5" type="text"/>
            </div>
        </div>
        <div class="radio">
            <label>
                <input type="radio" name="account_key_option" id="account_key_option-account_key_file" value="account_key_file">
                Upload a new AcmeAccountKey
                ${formgroup__AcmeAccountKey_file()}
            </label>
        </div>
    </div>
</%def>


<%def name="formgroup__AcmeAccountKey_file(show_header=True)">
    <table class="table table-condensed">
        <thead>
            <tr><th>AcmeAccountKey: PEM</th></tr>
        </thead>
        <tbody>
            <tr><td>
                <p class="help-block">
                    Select your provider, and upload your LetsEncrypt registered AccountKey in PEM format.
                    This is used when requesting the ACME server sign your certificates.
                </p>
                <table class="table table-condensed table-striped">
                    <tr>
                        <th>
                            <label for="f1-acme_account_provider_id">
                                ACME Server
                            </label>
                        </th>
                        <td>
                            <select class="form-control" id="f1-acme_account_provider_id" name="acme_account_provider_id" />
                                % for option in AcmeAccountProviderOptions:
                                    <option value="${option['id']}" ${'selected' if option['is_default'] else ''}>${option['name']}</option>
                                % endfor
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th>
                            <label for="f1-account_key_file_pem">
                                PEM File
                            </label>
                        </th>
                        <td>
                            <input class="form-control" type="file" id="f1-account_key_file_pem" name="account_key_file_pem" />
                        </td>
                    </tr>
                </table>
            </td></tr>
        </tbody>
        <thead>
            <tr><th>AcmeAccountKey: Certbot Encoding</th></tr>
        </thead>
        <tbody>
            <tr><td>
                <p class="help-block">
                    The provider will be auto-detected.
                </p>
                <table class="table table-condensed table-striped">
                    <tr>
                        <th>
                            <label for="f1-account_key_file_le_meta">LetsEncrypt meta.json</label>
                        </th>
                        <td>
                            <input class="form-control" type="file" id="f1-account_key_file_le_meta" name="account_key_file_le_meta" />
                        </td>
                    </tr>
                    <tr>
                        <th>
                            <label for="f1-account_key_file_le_pkey">LetsEncrypt private_key.json</label>
                        </th>
                        <td>
                            <input class="form-control" type="file" id="f1-account_key_file_le_pkey" name="account_key_file_le_pkey" />
                        </td>
                    </tr>
                    <tr>
                        <th>
                            <label for="f1-account_key_file_le_reg">LetsEncrypt regr.json</label>
                        </th>
                        <td>
                            <input class="form-control" type="file" id="f1-account_key_file_le_reg" name="account_key_file_le_reg" />
                        </td>
                    </tr>
                </table>
            </td></tr>
        </tbody>
    </table>
</%def>



<%def name="formgroup__CACertificateChain_file(show_text=False)">
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



<%def name="formgroup__CACertificateChain_bundle_file(CA_CROSS_SIGNED_X=None, CA_AUTH_X=None)">
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


<%def name="formgroup__Certificate_file(show_text=False)">
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


<%def name="formgroup__domain_names()">
    <div class="form-group clearfix">
        <label for="f1-domain_names">Domain Names</label>
        <textarea class="form-control" rows="4" name="domain_names" id="f1-domain_names"></textarea>
        <p class="help-block">
            A comma(,) separated list of domain names.
        </p>
    </div>
</%def>


<%def name="formgroup__PrivateKey_selector__advanced(show_text=None, dbPrivateKeyReuse=None)">
    <p>Select a PrivateKey with one of the following options</p>
    <div class="form-horizontal">
        % if dbPrivateKeyReuse:
            <div class="radio">
                <label>
                    <input type="radio" name="private_key_option" id="private_key_option-private_key_reuse" value="private_key_reuse" checked="checked"/>
                    <input type="hidden" name="private_key_reuse" value="${dbPrivateKeyReuse.key_pem_md5}"/>
                    Select to renew with the same PrivateKey
                </label>
                <p class="form-control-static">
                    <b>pem md5:</b> <code>${dbPrivateKeyReuse.key_pem_md5}</code><br/>
                    <b>pem line 1:</b> <code>${dbPrivateKeyReuse.key_pem_sample}</code><br/>
                    <a  class="label label-info"
                        href="${admin_prefix}/private-key/${dbPrivateKeyReuse.id}"
                    >
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        PrivateKey-${dbPrivateKeyReuse.id}
                    </a>
                </label>
            </div>
        % endif
        % if PrivateKey_Default:
            <div class="radio">
                <label>
                    <input type="radio" name="private_key_option" id="private_key_option-private_key_default" value="private_key_default"/>
                    The default PrivateKey.
                </label>
                <p class="form-control-static">
                    <b>pem md5:</b> <code>${PrivateKey_Default.key_pem_md5}</code><br/>
                    <b>pem line 1:</b> <code>${PrivateKey_Default.key_pem_sample}</code>
                    <input type="hidden" name="private_key_default" value="${PrivateKey_Default.key_pem_md5}"/>
                </p>
            </div>
        % else:
            <div class="alert alert-warning">
                <span class="glyphicon glyphicon-exclamation-sign" aria-hidden="true"></span>
                There is no Default PrivateKey configured. Any key can be configured as the System Default.
                Browse keys at 
                <a  class="label label-info"
                    href="${admin_prefix}/private-keys"
                >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    PrivateKeys
                </a>
            </div>
        % endif
        <div class="radio">
            <label for="private_key_option-account_key_existing">
                <input type="radio" name="private_key_option" id="private_key_option-private_key_existing" value="private_key_existing"/>
                The PEM MD5 of a PrivateKey already enrolled in the system.
            </label>
            <div class="form-control-static">
               <input class="form-control" name="private_key_existing" id="private_key_existing-pem_md5" type="text"/>
            </div>
        </div>
        <div class="radio">
            <label>
                <input type="radio" name="private_key_option" id="private_key_option-private_key_file_pem" value="private_key_file_pem">
                Upload a new PrivateKey
                    ${formgroup__PrivateKey_file()}
            </label>
        </div>
    </div>
</%def>

<%def name="formgroup__PrivateKey_file()">
    <table class="table table-condensed">
        <thead>
            <tr><th>PrivateKey: PEM</th></tr>
        </thead>
        <tbody>
            <tr><td>
                <p class="help-block">
                    Upload a RSA PrivateKey in PEM format.
                    This will be used to sign CertificateRequests and is required for ServerCertificate deployment. 
                    The key will be saved into the system.
                </p>
                <table class="table table-condensed table-striped">
                    <tr>
                        <th>
                            <label for="f1-private_key_file_pem">
                                PEM File
                            </label>
                        </th>
                        <td>
                            <input class="form-control" type="file" id="f1-private_key_file_pem" name="private_key_file_pem" />
                        </td>
                    </tr>
                </table>
            </td></tr>
        </tbody>
    </table>
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


<%def name="standard_error_display(expect_message=None)">
    <%
        error = request.params.get('error', None)
        message = request.params.get('message', None)
    %>
    % if error:
        <div class="alert alert-danger">
            ## operation=mark&action=deactivate&result=error&error=Can%20not%20deactivate%20the%20default
            <b>Error</b>
            <p>
                % if message:
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
