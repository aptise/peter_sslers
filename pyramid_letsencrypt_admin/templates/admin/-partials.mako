
<%def name="table_to_certificates(to_certificates, show_domains=False, show_domains_title='domains')">
    <table class="table table-striped">
        <thead>
            <tr>
                <th>id</th>
                <th>active?</th>
                <th>timestamp_signed</th>
                <th>timestamp_expires</th>
                % if show_domains:
                    <th>${show_domains_title}</th>
                % endif
            </tr>
        </thead>
        <tbody>
        % for to_cert in to_certificates:
            <tr>
                <td><a class="label label-default" href="/.well-known/admin/certificate/${to_cert.certificate.id}">&gt; ${to_cert.certificate.id}</a></td>
                <td>
                    <span class="label label-${'success' if to_cert.certificate.is_active else 'warning'}">
                        ${'Active' if to_cert.certificate.is_active else 'inactive'}
                    </span>
                </td>
                <td>${to_cert.certificate.timestamp_signed}</td>
                <td>${to_cert.certificate.timestamp_expires or ''}</td>
                % if show_domains:
                     <td>${', '.join([to_d.domain.domain_name for to_d in to_cert.certificate.certificate_to_domains])}</td>
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
                    <a  class="label label-default"
                        href="/.well-known/admin/certificate_request/${to_cr.certificate_request.id}">&gt; ${to_cr.certificate_request.id}</a>
                </td>
                <td>
                    <span class="label label-${'success' if to_cr.certificate_request.is_active else 'warning'}">
                        ${'Active' if to_cr.certificate_request.is_active else 'inactive'}
                    </span>
                </td>
                <td>
                    <span class="label label-info">${to_cr.certificate_request.certificate_request_type}</span>
                </td>                
                <td>${to_cr.timestamp_verified or ''}</td>
                <td><code>${to_cr.challenge_key or ''}</code></td>
                <td><code>${to_cr.challenge_text or ''}</code></td>
            </tr>
        % endfor
        </tbody>
    </table>
</%def>


<%def name="table_certificates__list(certificates, show_domains=False)">
    <table class="table table-striped">
        <thead>
            <tr>
                <th>id</th>
                <th>active?</th>
                <th>timestamp_signed</th>
                <th>timestamp_expires</th>
                % if show_domains:
                    <th>domains</th>
                % endif
            </tr>
        </thead>
        <tbody>
        % for cert in certificates:
            <tr>
                <td><a class="label label-default" href="/.well-known/admin/certificate/${cert.id}">&gt; ${cert.id}</a></td>
                <td>
                    <span class="label label-${'success' if cert.is_active else 'warning'}">
                        ${'Active' if cert.is_active else 'inactive'}
                    </span>
                </td>
                <td>${cert.timestamp_signed}</td>
                <td>${cert.timestamp_expires or ''}</td>
                % if show_domains:
                    <td>${', '.join([to_d.domain.domain_name for to_d in cert.certificate_to_domains])}</td>
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
                    <a  class="label label-default"
                        href="/.well-known/admin/certificate_request/${certificate_request.id}">&gt; ${certificate_request.id}</a>
                </td>
                <td>
                    <span class="label label-info">${certificate_request.certificate_request_type}</span>
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
                        % if certificate_request.signed_certificate:
                            <a  class="label label-default"
                                href="/.well-known/admin/certificate/${certificate_request.signed_certificate.id}">&gt; ${certificate_request.signed_certificate.id}</a>
                        % else:
                            &nbsp;
                        % endif
                    </td>                
                % endif
                <td>${certificate_request.timestamp_started}</td>
                <td>${certificate_request.timestamp_finished or ''}</td>
                % if show_domains:
                    <td>${', '.join([to_d.domain.domain_name for to_d in certificate_request.certificate_request_to_domains])}</td>
                % endif
            </tr>
        % endfor
        </tbody>
    </table>
</%def>


<%def name="table_LetsencryptCertificateRequest_2_ManagedDomain(lcr2mds, request_inactive=None, active_domain_id=None, perspective=None)">
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
                        <td><a href="/.well-known/admin/domain/${to_d.domain.id}" class="label label-default">&gt; ${to_d.domain.id}</a> ${to_d.domain.domain_name}</td>
                        <td>${to_d.timestamp_verified or ''}</td>
                        <td><code>${to_d.challenge_key or ''}</code></td>
                        <td><code>${to_d.challenge_text or ''}</code></td>
                        <td>
                            % if to_d.is_configured:
                                % if request_inactive:
                                    <span class="label label-success">configured</span>
                                % else:
                                    <a  class="label label-success"
                                        href="/.well-known/admin/certificate_request/${LetsencryptCertificateRequest.id}/process/domain/${to_d.domain.id}"
                                        >&gt; configured</a>
                                % endif
                            % else:
                                % if request_inactive:
                                    <span class="label label-warning">not configured</span>
                                % else:
                                    <a  class="label label-warning"
                                        href="/.well-known/admin/certificate_request/${LetsencryptCertificateRequest.id}/process/domain/${to_d.domain.id}"
                                        >&gt; configure!</a>
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
                    <th>active?</th>
                    <th>domain</th>
                    <th>configured?</th>
                    <th>verified?</th>
                    <th>test</th>
                </tr>
            </thead>
            <tbody>
            % for to_d in LetsencryptCertificateRequest.certificate_request_to_domains:
                <tr>
                    <td>
                        % if active_domain_id == to_d.letsencrypt_managed_domain_id:
                            <span class="label label-info">active</span>
                        % endif
                    </td>
                    <td>
                        <span class="label label-default"
                        >
                            ${to_d.domain.domain_name}
                        </span>
                    </td>
                    <td>
                        % if active_domain_id == to_d.letsencrypt_managed_domain_id:
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
                                    href="/.well-known/admin/certificate_request/${LetsencryptCertificateRequest.id}/process/domain/${to_d.letsencrypt_managed_domain_id}"
                                    class="label label-success">&gt; configured</a>
                            % else:
                                <a href="/.well-known/admin/certificate_request/${LetsencryptCertificateRequest.id}/process/domain/${to_d.letsencrypt_managed_domain_id}"
                                    class="label label-warning">
                                    % if request_inactive:
                                        &gt; not configured
                                    % else:
                                        &gt; configure
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
                            <a  class="label label-default"
                                target="_blank"
                                href="http://${to_d.domain.domain_name}/.well-known/acme-challenge/${to_d.challenge_key}?test=1"
                            >
                                &gt; test
                            </a>
                        % endif
                    </td>
                </tr>
            % endfor
            </tbody>
        </table>

    % else:
        <!-- table_LetsencryptCertificateRequest_2_ManagedDomain missing perspective -->
    % endif
</%def>


<%def name="info_AccountKey()">
    <h3>Need a Private Key?</h3>
        <p>Use an Existing LetsEncrypt key from their client.  This is the easiest way to register with LetsEncrypt.</p>
        <p>
            You have to convert the key from <code>jwk</code> to <code>pem</code> format.  
            The easiest way is outlined on this github page: <a href="https://github.com/diafygi/acme-tiny">https://github.com/diafygi/acme-tiny</a>
        </p>
</%def>

<%def name="info_DomainKey()">
    <h3>Need a Domain Private Key?</h3>
        <p>NOTE: you can not use your account private key as your domain private key!</p>
        <p>
            <code>openssl genrsa 4096 > domain.key</code>
        </p>
</%def>


<%def name="formgroup__account_key_file(show_text=False)">
    <div class="form-group clearfix">
        <label for="f1-account_key_file">Account Private Key</label>
        <input class="form-control" type="file" id="f1-account_key_file" name="account_key_file" />
        <p class="help-block">
            Enter your LetsEncrypted registered PRIVATE AccountKey above in PEM format; this will be used to sign your request.
            This is save dot the DB and used to track requests and handle reiussues.
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


<%def name="formgroup__domain_key_file(show_text=False)">
    <div class="form-group clearfix">
        <label for="f1-domain_key_file">Domain Private Key</label>
        <input class="form-control" type="file" id="f1-domain_key_file" name="domain_key_file" />
        <p class="help-block">
            Enter your PRIVATE DomainKey above in PEM format; this will be used to create a CSR used for configuring servers/chains.
            This WILL be saved.
        </p>
        % if show_text:
            <label for="f1-domain_key">Domain Private Key [text]</label>
            <textarea class="form-control" rows="4" name="domain_key" id="f1-domain_key"></textarea>
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



<%def name="formgroup__domain_names()">
    <div class="form-group clearfix">
        <label for="f1-domain_names">Domain Names</label>
        <textarea class="form-control" rows="4" name="domain_names" id="f1-domain_names"></textarea>
        <p class="help-block">
            A comma(,) separated list of domain names.
        </p>
    </div>
</%def>
