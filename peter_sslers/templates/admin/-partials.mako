<%def name="table_tr_event_created(dbObject)">
    % if dbObject.ssl_operations_event_id__created:
        <tr>
            <th>Event Created At</th>
            <td>
                <a  href="${admin_prefix}/operations/log/item/${dbObject.ssl_operations_event_id__created}"
                    class="label label-info"
                >
                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                    ${dbObject.ssl_operations_event_id__created}
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
                    ${to_cert.certificate.id}</a>
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
                        ${to_cr.certificate_request.id}</a>
                </td>
                <td>
                    <span class="label label-${'success' if to_cr.certificate_request.is_active else 'warning'}">
                        ${'Active' if to_cr.certificate_request.is_active else 'inactive'}
                    </span>
                </td>
                <td>
                    <span class="label label-defaul">${to_cr.certificate_request.certificate_request_type}</span>
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
                    ${cert.id}</a>
                </td>
                <td>
                    <span class="label label-${'success' if cert.is_active else 'warning'}">
                        ${'Active' if cert.is_active else 'inactive'}
                    </span>
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
                <th>error?</th>
                % if show_certificate:
                    <th>cert issued?</th>
                % endif
                <th>timestamp_started</th>
                <th>timestamp_finished</th>
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
                        ${certificate_request.id}</a>
                </td>
                <td>
                    <span class="label label-default">${certificate_request.certificate_request_type}</span>
                </td>
                <td>
                    <span class="label label-${'success' if certificate_request.is_active else 'warning'}">
                        ${'Active' if certificate_request.is_active else 'inactive'}
                    </span>
                </td>
                <td>
                    <span class="label label-${'danger' if certificate_request.is_error else 'default'}">
                        ${'Error' if certificate_request.is_error else 'ok'}
                    </span>
                </td>
                % if show_certificate:
                    <td>
                        % if certificate_request.server_certificate:
                            <a  class="label label-info"
                                href="${admin_prefix}/certificate/${certificate_request.server_certificate.id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ${certificate_request.server_certificate.id}</a>
                        % else:
                            &nbsp;
                        % endif
                    </td>
                % endif
                <td><timestamp>${certificate_request.timestamp_started}</timestamp></td>
                <td><timestamp>${certificate_request.timestamp_finished or ''}</timestamp></td>
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
                % if show_certificate:
                    <th>certificate</th>
                % endif
                <th>timestamp_entered</th>
                <th>ssl_operations_event_id__created</th>
                <th>timestamp_processed</th>
            </tr>
        </thead>
        <tbody>
        % for queue_renewal in renewal_items:
            <tr>
                <td><a href="${admin_prefix}/queue-renewal/${queue_renewal.id}" class="label label-info">
                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                    ${queue_renewal.id}</a>
                </td>
                % if show_certificate:
                    <td><a href="${admin_prefix}/certificate/${queue_renewal.ssl_server_certificate_id}" class="label label-info">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        ${queue_renewal.ssl_server_certificate_id}</a>
                    </td>
                % endif
                <td><timestamp>${queue_renewal.timestamp_entered or ''}</timestamp></td>
                <td><span class="label label-info">${queue_renewal.ssl_operations_event_id__created}</span></td>
                <td><timestamp>${queue_renewal.timestamp_processed or ''}</timestamp></td>
            </tr>
        % endfor
        </tbody>
    </table>
</%def>


<%def name="table_SslCertificateRequest2SslDomain(lcr2mds, request_inactive=None, current_domain_id=None, perspective=None)">
    % if perspective == 'certificate_request':
        <table class="table table-striped table-condensed">
            <thead>
                <tr>
                    <th>domain</th>
                    <th>timestamp_verified</th>
                    <th>challenge_key</th>
                    <th>challenge_text</th>
                    <th>configured?</th>
                </tr>
            </thead>
            <tbody>
                % for to_d in lcr2mds:
                    <tr>
                        <td><a href="${admin_prefix}/domain/${to_d.domain.id}" class="label label-info">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            ${to_d.domain.id}</a> ${to_d.domain.domain_name}</td>
                        <td><timestamp>${to_d.timestamp_verified or ''}</timestamp></td>
                        <td><code>${to_d.challenge_key or ''}</code></td>
                        <td><code>${to_d.challenge_text or ''}</code></td>
                        <td>
                            % if to_d.is_configured:
                                % if request_inactive:
                                    <span class="label label-success">configured</span>
                                % else:
                                    <a  class="label label-success"
                                        href="${admin_prefix}/certificate-request/${SslCertificateRequest.id}/acme-flow/manage/domain/${to_d.domain.id}"
                                        >
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        configured</a>
                                % endif
                            % else:
                                % if request_inactive:
                                    <span class="label label-warning">not configured</span>
                                % else:
                                    <a  class="label label-warning"
                                        href="${admin_prefix}/certificate-request/${SslCertificateRequest.id}/acme-flow/manage/domain/${to_d.domain.id}"
                                        >
                                        <span class="glyphicon glyphicon-wrench" aria-hidden="true"></span>
                                        configure!</a>
                                % endif
                            % endif
                        </td>
                    </tr>
                % endfor
            </tbody>
        </table>
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
            % for to_d in SslCertificateRequest.to_domains:
                <tr>
                    <td>
                        % if current_domain_id == to_d.ssl_domain_id:
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
                        % if current_domain_id == to_d.ssl_domain_id:
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
                                    href="${admin_prefix}/certificate-request/${SslCertificateRequest.id}/acme-flow/manage/domain/${to_d.ssl_domain_id}"
                                    class="label label-success">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    configured</a>
                            % else:
                                <a href="${admin_prefix}/certificate-request/${SslCertificateRequest.id}/acme-flow/manage/domain/${to_d.ssl_domain_id}"
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
        <!-- table_SslCertificateRequest2SslDomain missing perspective -->
    % endif
</%def>


<%def name="table_SslUniqueFQDNSets(SslUniqueFQDNSets)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>timestamp first seen</th>
                <th>domain ids string</th>
            </tr>
        </thead>
        <tbody>
        % for i in SslUniqueFQDNSets:
            <tr>
                <td>
                    <a  class="btn btn-xs btn-info"
                        href="${admin_prefix}/unique-fqdn-set/${i.id}"
                    >
                     <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                     ${i.id}
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


<%def name="table_SslOperationsEvents(SslOperationsEvents, show_event=None, event_type_listable=None)">
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
            % for event in SslOperationsEvents:
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
                        % if event.ssl_operations_event_id__child_of:
                            <span class="label label-default">${event.ssl_operations_event_id__child_of}</span>
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


<%def name="table_SslOperationsObjectEvents(SslOperationsObjectEvents, table_context=None)">
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
            % for object_event in SslOperationsObjectEvents:
                <tr>
                    % if show_event:
                        <td>
                            <a class="label label-info" href="${admin_prefix}/operations/log/item/${object_event.ssl_operations_event_id}">
                                ${object_event.ssl_operations_event_id}
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
                        % if object_event.ssl_ca_certificate_id:
                            <a class="label label-info" href="${admin_prefix}/ca-certificate/${object_event.ssl_ca_certificate_id}">
                                CaCert
                                ${object_event.ssl_ca_certificate_id}
                            </a>
                        % elif object_event.ssl_certificate_request_id:
                            <a class="label label-info" href="${admin_prefix}/certificate-request/${object_event.ssl_certificate_request_id}">
                                CSR
                                ${object_event.ssl_certificate_request_id}
                            </a>
                        % elif object_event.ssl_domain_id:
                            <a class="label label-info" href="${admin_prefix}/domain/${object_event.ssl_domain_id}">
                                ${object_event.ssl_domain_id}
                            </a>
                            <code>${object_event.domain.domain_name}</code>
                        % elif object_event.ssl_letsencrypt_account_key_id:
                            <a class="label label-info" href="${admin_prefix}/account-key/${object_event.ssl_letsencrypt_account_key_id}">
                                AccountKey
                                ${object_event.ssl_letsencrypt_account_key_id}
                            </a>
                        % elif object_event.ssl_private_key_id:
                            <a class="label label-info" href="${admin_prefix}/private-key/${object_event.ssl_private_key_id}">
                                PrivateKey
                                ${object_event.ssl_private_key_id}
                            </a>
                        % elif object_event.ssl_queue_domain_id:
                            <a class="label label-info" href="${admin_prefix}/queue-domain/${object_event.ssl_queue_domain_id}">
                                qDomain
                                ${object_event.ssl_queue_domain_id}
                            </a>
                            <code>${object_event.queue_domain.domain_name}</code>
                        % elif object_event.ssl_queue_renewal_id:
                            <a class="label label-info" href="${admin_prefix}/queue-renewal/${object_event.ssl_queue_renewal_id}">
                                qRenewal
                                ${object_event.ssl_queue_renewal_id}
                            </a>
                        % elif object_event.ssl_server_certificate_id:
                            <a class="label label-info" href="${admin_prefix}/certificate/${object_event.ssl_server_certificate_id}">
                                Cert
                                ${object_event.ssl_server_certificate_id}
                            </a>
                        % elif object_event.ssl_unique_fqdn_set_id:
                            <a class="label label-info" href="${admin_prefix}/unique-fqdn-set/${object_event.ssl_unique_fqdn_set_id}">
                                uFQDN
                                ${object_event.ssl_unique_fqdn_set_id}
                            </a>
                        % endif
</%def>


<%def name="info_AccountKey()">
    <h3>Need an Account Key?</h3>
        <p>Use an Existing LetsEncrypt key from their client.
           This is the easiest way to register with LetsEncrypt and opt into their TOS.
        </p>
        <p>
            You have to convert the key from <code>jwk</code> to <code>pem</code> format.
            The easiest way is outlined on this github page: <a href="https://github.com/diafygi/acme-tiny">https://github.com/diafygi/acme-tiny</a>
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


<%def name="formgroup__account_key_file(show_text=False)">
    <div class="form-group clearfix">
        <label for="f1-account_key_file">Account Private Key</label>
        <input class="form-control" type="file" id="f1-account_key_file" name="account_key_file" />
        <p class="help-block">
            Enter your LetsEncrypted registered PRIVATE AccountKey above in PEM format; this will be used to sign your request.
            This is saved ot the DB and is used to track requests and handle reiussues.
        </p>
        % if show_text:
            <label for="f1-account_key">Account Private Key [text]</label>
            <textarea class="form-control" rows="4" name="account_key" id="f1-account_key"></textarea>
            <p class="help-block">
                Alternately, provide text inline.
            </p>
        % endif
    </div>
</%def>


<%def name="formgroup__private_key_file(show_text=False)">
    <div class="form-group clearfix">
        <label for="f1-private_key_file">Private Key</label>
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
            Full Operations Log</a>
        </li>
        % if enable_redis:
            <li class="${'active' if active =='/operations/redis' else ''}">
                <a  href="${admin_prefix}/operations/redis"
                >
                <span class="glyphicon glyphicon-folder-open" aria-hidden="true"></span>
                Operations Log: Redis</a>
            </li>
        % endif
        % if enable_nginx:
            <li class="${'active' if active =='/operations/nginx' else ''}">
                <a  href="${admin_prefix}/operations/nginx"
                >
                <span class="glyphicon glyphicon-folder-open" aria-hidden="true"></span>
                Operations Log: nginx</a>
            </li>
        % endif
        <li class="${'active' if active =='/operations/ca-certificate-probes' else ''}">
            <a  href="${admin_prefix}/operations/ca-certificate-probes"
            >
            <span class="glyphicon glyphicon-folder-open" aria-hidden="true"></span>
            Operations Log: CA Certificate Probes</a>
        </li>
        <li class="${'active' if active =='/operations/object-log' else ''}">
            <a  href="${admin_prefix}/operations/object-log"
            >
            <span class="glyphicon glyphicon-folder-open" aria-hidden="true"></span>
            Object Log</a>
        </li>
    </ul>

    <h4>Actions</h4>
    <ul class="nav nav-pills nav-stacked">
        <li class="${'active' if active =='/api/deactivate-expired' else ''}">
            <a  href="${admin_prefix}/api/deactivate-expired"
            >
             <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
             Deactivate Expired Certificates</a>
        </li>
        <li class="${'active' if active =='/api/update-recents' else ''}">
            <a  href="${admin_prefix}/api/update-recents"
            >
             <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
             Update Recents</a>
        </li>
    </ul
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
