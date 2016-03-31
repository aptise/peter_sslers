<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li class="active">Search</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Search</h2>
</%block>


<%block name="content_main">
    % if not ResultsPage:
        Search only displays results off other pages.
    % else:
        <div class="row">
            <div class="col-sm-9">

            % if show_only['LetsencryptAccountKey']:
                <h4>Account Keys</h4>
                % if results['LetsencryptAccountKey']['count']:
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
                        % for key in results['LetsencryptAccountKey']['items']:
                            <tr>
                                <td>
                                    <a  class="btn btn-xs btn-info"
                                        href="/.well-known/admin/account_key/${key.id}"
                                    >&gt; ${key.id}</a>
                                </td>
                                <td><code>${key.key_pem_modulus_md5}</code></td>
                                <td><timestamp>${key.timestamp_last_certificate_request}</timestamp></td>
                                <td><timestamp>${key.timestamp_last_certificate_issue}</timestamp></td>
                            </tr>
                        % endfor
                        </body>
                    </table>
                    % if results['LetsencryptAccountKey']['next']:
                        <a href="${results['LetsencryptAccountKey']['next']}">More</a>
                    % endif
                % else:
                    <em>None</em>
                % endif
                <hr/>
            % endif


            % if show_only['LetsencryptPrivateKey']:
                <h4>Private Keys</h4>
                % if results['LetsencryptPrivateKey']['count']:
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
                        % for key in results['LetsencryptPrivateKey']['items']:
                            <tr>
                                <td>
                                    <a  class="btn btn-xs btn-info"
                                        href="/.well-known/admin/private_key/${key.id}"
                                    >&gt; ${key.id}</a>
                                </td>
                                <td><code>${key.key_pem_modulus_md5}</code></td>
                                <td><timestamp>${key.timestamp_last_certificate_request}</timestamp></td>
                                <td><timestamp>${key.timestamp_last_certificate_issue}</timestamp></td>
                            </tr>
                        % endfor
                        </body>
                    </table>
                    % if results['LetsencryptPrivateKey']['next']:
                        <a href="${results['LetsencryptPrivateKey']['next']}">More</a>
                    % endif
                % else:
                    <em>None</em>
                % endif
                <hr/>
            % endif


            % if show_only['LetsencryptServerCertificate']:
                <h4>Certificates</h4>
                % if results['LetsencryptServerCertificate']['count']:
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
                        % for cert in results['LetsencryptServerCertificate']['items']:
                            <tr>
                                <td>
                                    <a  class="btn btn-xs btn-info"
                                        href="/.well-known/admin/certificate/${cert.id}"
                                    >&gt; ${cert.id}</a>
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
                    % if results['LetsencryptServerCertificate']['next']:
                        <a href="${results['LetsencryptServerCertificate']['next']}">More</a>
                    % endif
                % else:
                    <em>None</em>
                % endif
                <hr/>
            % endif


            % if show_only['LetsencryptCACertificate']:
                <h4>CA Certificates</h4>
                % if results['LetsencryptCACertificate']['count']:
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
                        % for cert in results['LetsencryptCACertificate']['items']:
                            <tr>
                                <td>
                                    <a  class="btn btn-xs btn-info"
                                        href="/.well-known/admin/ca_certificate/${cert.id}"
                                    >&gt; ${cert.id}</a>
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
                    % if results['LetsencryptCACertificate']['next']:
                        <a href="${results['LetsencryptCACertificate']['next']}">More</a>
                    % endif
                % else:
                    <em>None</em>
                % endif
                <hr/>
            % endif


            % if show_only['LetsencryptCertificateRequest']:
                <h4>Certificate Requests</h4>
                % if results['LetsencryptCertificateRequest']['count']:
                    <table class="table table-condensed">
                        % for csr in results['LetsencryptCertificateRequest']['items']:
                            <tr>
                                <td>
                                    <a  class="btn btn-xs btn-info"
                                        href="/.well-known/admin/certificate_request/${csr.id}"
                                    >&gt; ${csr.id}</a>
                                </td>
                            </tr>
                        % endfor
                    </table>
                    % if results['LetsencryptCertificateRequest']['next']:
                        <a href="${results['LetsencryptCertificateRequest']['next']}">More</a>
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
