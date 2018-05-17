<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Search</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Search</h2>
</%block>


<%block name="content_main">
    % if not ResultsPage:
        <div class="row">
            <div class="col-sm-12">
                Search only displays results off other pages.
            </div>
        </div>
    % else:
        <div class="row">
            <div class="col-sm-9">

                % if show_only['SslLetsEncryptAccountKey']:
                    <h4>Account Keys</h4>
                    % if results['SslLetsEncryptAccountKey']['count']:
                        <table class="table table-condensed">
                            <thead>
                                <tr>
                                    <th>id</th>
                                    <th>key_pem_modulus_md5</th>
                                    <th>timestamp last CSR</th>
                                    <th>timestamp last issue</th>
                                </tr>
                            </thead>
                            <body>
                            % for key in results['SslLetsEncryptAccountKey']['items']:
                                <tr>
                                    <td>
                                        <a  class="btn btn-xs btn-info"
                                            href="${admin_prefix}/account-key/${key.id}"
                                        >
                                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                            account-${key.id}</a>
                                    </td>
                                    <td><code>${key.key_pem_modulus_md5}</code></td>
                                    <td><timestamp>${key.timestamp_last_certificate_request}</timestamp></td>
                                    <td><timestamp>${key.timestamp_last_certificate_issue}</timestamp></td>
                                </tr>
                            % endfor
                            </body>
                        </table>
                        % if results['SslLetsEncryptAccountKey']['next']:
                            <a href="${results['SslLetsEncryptAccountKey']['next']}">More</a>
                        % endif
                    % else:
                        <em>None</em>
                    % endif
                    <hr/>
                % endif

                % if show_only['SslPrivateKey']:
                    <h4>Private Keys</h4>
                    % if results['SslPrivateKey']['count']:
                        <table class="table table-condensed">
                            <thead>
                                <tr>
                                    <th>id</th>
                                    <th>key_pem_modulus_md5</th>
                                    <th>timestamp last CSR</th>
                                    <th>timestamp last issue</th>
                                </tr>
                            </thead>
                            <body>
                            % for key in results['SslPrivateKey']['items']:
                                <tr>
                                    <td>
                                        <a  class="btn btn-xs btn-info"
                                            href="${admin_prefix}/private-key/${key.id}"
                                        >
                                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                            pkey-${key.id}</a>
                                    </td>
                                    <td><code>${key.key_pem_modulus_md5}</code></td>
                                    <td><timestamp>${key.timestamp_last_certificate_request}</timestamp></td>
                                    <td><timestamp>${key.timestamp_last_certificate_issue}</timestamp></td>
                                </tr>
                            % endfor
                            </body>
                        </table>
                        % if results['SslPrivateKey']['next']:
                            <a href="${results['SslPrivateKey']['next']}">More</a>
                        % endif
                    % else:
                        <em>None</em>
                    % endif
                    <hr/>
                % endif

                % if show_only['SslServerCertificate']:
                    <h4>Certificates</h4>
                    % if results['SslServerCertificate']['count']:
                        <table class="table table-condensed">
                            <thead>
                                <tr>
                                    <th>id</th>
                                    <th>cert_pem_modulus_md5</th>
                                    <th>active?</th>
                                    <th>timestamp signed</th>
                                    <th>timestamp expires</th>
                                    <th>subject hash</th>
                                    <th>issuer hash</th>
                                </tr>
                            </thead>
                            <body>
                            % for cert in results['SslServerCertificate']['items']:
                                <tr>
                                    <td>
                                        <a  class="btn btn-xs btn-info"
                                            href="${admin_prefix}/certificate/${cert.id}"
                                        >
                                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                            cert-${cert.id}</a>
                                    </td>
                                    <td><code>${cert.cert_pem_modulus_md5}</code></td>
                                    <td><span class="label label-${'success' if cert.is_active else 'danger'}">${'Y' if cert.is_active else ''}</label></td>
                                    <td><timestamp>${cert.timestamp_signed}</timestamp></td>
                                    <td><timestamp>${cert.timestamp_expires}</timestamp></td>
                                    <td><code>${cert.cert_subject_hash}</code></td>
                                    <td><code>${cert.cert_issuer_hash}</code></td>
                                </tr>
                            % endfor
                            </body>
                        </table>
                        % if results['SslServerCertificate']['next']:
                            <a href="${results['SslServerCertificate']['next']}">More</a>
                        % endif
                    % else:
                        <em>None</em>
                    % endif
                    <hr/>
                % endif

                % if show_only['SslCaCertificate']:
                    <h4>CA Certificates</h4>
                    % if results['SslCaCertificate']['count']:
                        <table class="table table-condensed">
                            <thead>
                                <tr>
                                    <th>id</th>
                                    <th>cert_pem_modulus_md5</th>
                                    <th>timestamp signed</th>
                                    <th>timestamp expires</th>
                                    <th>subject hash</th>
                                    <th>issuer hash</th>
                                </tr>
                            </thead>
                            <body>
                            % for cert in results['SslCaCertificate']['items']:
                                <tr>
                                    <td>
                                        <a  class="btn btn-xs btn-info"
                                            href="${admin_prefix}/ca-certificate/${cert.id}"
                                        >
                                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                            cacert-${cert.id}</a>
                                    </td>
                                    <td><code>${cert.cert_pem_modulus_md5}</code></td>
                                    <td><timestamp>${cert.timestamp_signed}</timestamp></td>
                                    <td><timestamp>${cert.timestamp_expires}</timestamp></td>
                                    <td><code>${cert.cert_subject_hash}</code></td>
                                    <td><code>${cert.cert_issuer_hash}</code></td>
                                </tr>
                            % endfor
                            </body>
                        </table>
                        % if results['SslCaCertificate']['next']:
                            <a href="${results['SslCaCertificate']['next']}">More</a>
                        % endif
                    % else:
                        <em>None</em>
                    % endif
                    <hr/>
                % endif

                % if show_only['SslCertificateRequest']:
                    <h4>Certificate Requests</h4>
                    % if results['SslCertificateRequest']['count']:
                        <table class="table table-condensed">
                            % for csr in results['SslCertificateRequest']['items']:
                                <tr>
                                    <td>
                                        <a  class="btn btn-xs btn-info"
                                            href="${admin_prefix}/certificate-request/${csr.id}"
                                        >
                                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                            csr-${csr.id}</a>
                                    </td>
                                </tr>
                            % endfor
                        </table>
                        % if results['SslCertificateRequest']['next']:
                            <a href="${results['SslCertificateRequest']['next']}">More</a>
                        % endif
                    % else:
                        <em>None</em>
                    % endif
                    <hr/>
                % endif

            </div>
            <div class="col-sm-3">
                <h4>Search Results</h4>
                <table class="table table-striped table-condensed">
                    <tr>
                        <th>Search Type</th>
                        <td>${search_type}</td>
                    </tr>
                    <tr>
                        <th>
                            ${search_type}
                        </th>
                        <td>
                            ${request.params.get(search_type, '')}
                        </td>
                    </tr>
                </table>
            </div>
        </div>
    % endif
</%block>
