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

                % if show_only['AcmeAccount']:
                    <h4>AcmeAccounts</h4>
                    % if results['AcmeAccount']['count']:
                        <table class="table table-condensed">
                            <thead>
                                <tr>
                                    <th>id</th>
                                    <th>spki_sha256</th>
                                    <th>timestamp last CSR</th>
                                    <th>timestamp last issue</th>
                                </tr>
                            </thead>
                            <body>
                            % for acme_account in results['AcmeAccount']['items']:
                                <tr>
                                    <td>
                                        <a  class="label label-info"
                                            href="${admin_prefix}/acme-account/${acme_account.id}"
                                        >
                                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                            AcmeAccount-${acme_account.id}</a>
                                    </td>
                                    <td><code>${acme_account.acme_account_key.spki_sha256}</code></td>
                                    <td><timestamp>${acme_account.timestamp_last_x509_certificate_request}</timestamp></td>
                                    <td><timestamp>${acme_account.timestamp_last_certificate_issue}</timestamp></td>
                                </tr>
                            % endfor
                            </body>
                        </table>
                        % if results['AcmeAccount']['next']:
                            <a href="${results['AcmeAccount']['next']}">More</a>
                        % endif
                    % else:
                        <em>None</em>
                    % endif
                    <hr/>
                % endif

                % if show_only['PrivateKey']:
                    <h4>Private Keys</h4>
                    % if results['PrivateKey']['count']:
                        <table class="table table-condensed">
                            <thead>
                                <tr>
                                    <th>id</th>
                                    <th>spki_sha256</th>
                                    <th>timestamp last CSR</th>
                                    <th>timestamp last issue</th>
                                </tr>
                            </thead>
                            <body>
                            % for key in results['PrivateKey']['items']:
                                <tr>
                                    <td>
                                        <a  class="label label-info"
                                            href="${admin_prefix}/private-key/${key.id}"
                                        >
                                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                            PrivateKey-${key.id}</a>
                                    </td>
                                    <td><code>${key.spki_sha256}</code></td>
                                    <td><timestamp>${key.timestamp_last_x509_certificate_request}</timestamp></td>
                                    <td><timestamp>${key.timestamp_last_certificate_issue}</timestamp></td>
                                </tr>
                            % endfor
                            </body>
                        </table>
                        % if results['PrivateKey']['next']:
                            <a href="${results['PrivateKey']['next']}">More</a>
                        % endif
                    % else:
                        <em>None</em>
                    % endif
                    <hr/>
                % endif

                % if show_only['X509Certificate']:
                    <h4>X509Certificates</h4>
                    % if results['X509Certificate']['count']:
                        <table class="table table-condensed">
                            <thead>
                                <tr>
                                    <th>id</th>
                                    <th>spki_sha256</th>
                                    <th>active?</th>
                                    <th>timestamp signed</th>
                                    <th>timestamp expires</th>
                                </tr>
                            </thead>
                            <body>
                            % for cert in results['X509Certificate']['items']:
                                <tr>
                                    <td>
                                        <a  class="label label-info"
                                            href="${admin_prefix}/x509-certificate/${cert.id}"
                                        >
                                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                            X509Certificate-${cert.id}</a>
                                    </td>
                                    <td><code>${cert.spki_sha256}</code></td>
                                    <td><span class="label label-${'success' if cert.is_active else 'danger'}">${'Y' if cert.is_active else ''}</label></td>
                                    <td><timestamp>${cert.timestamp_not_before}</timestamp></td>
                                    <td><timestamp>${cert.timestamp_not_after}</timestamp></td>
                                </tr>
                            % endfor
                            </body>
                        </table>
                        % if results['X509Certificate']['next']:
                            <a href="${results['X509Certificate']['next']}">More</a>
                        % endif
                    % else:
                        <em>None</em>
                    % endif
                    <hr/>
                % endif

                % if show_only['CertificateCA']:
                    <h4>CertificateCAs</h4>
                    % if results['CertificateCA']['count']:
                        <table class="table table-condensed">
                            <thead>
                                <tr>
                                    <th>id</th>
                                    <th>display_name</th>
                                    <th>spki_sha256</th>
                                    <th>timestamp signed</th>
                                    <th>timestamp expires</th>
                                </tr>
                            </thead>
                            <body>
                            % for cert in results['CertificateCA']['items']:
                                <tr>
                                    <td>
                                        <a  class="label label-info"
                                            href="${admin_prefix}/certificate-ca/${cert.id}"
                                        >
                                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                            CertificateCA-${cert.id}</a>
                                    </td>
                                    <td>${cert.display_name}</td>
                                    <td><code>${cert.spki_sha256}</code></td>
                                    <td><timestamp>${cert.timestamp_not_before}</timestamp></td>
                                    <td><timestamp>${cert.timestamp_not_after}</timestamp></td>
                                </tr>
                            % endfor
                            </body>
                        </table>
                        % if results['CertificateCA']['next']:
                            <a href="${results['CertificateCA']['next']}">More</a>
                        % endif
                    % else:
                        <em>None</em>
                    % endif
                    <hr/>
                % endif

                % if show_only['X509CertificateRequest']:
                    <h4>X509 Certificate Requests</h4>
                    % if results['X509CertificateRequest']['count']:
                        <table class="table table-condensed">
                            % for csr in results['X509CertificateRequest']['items']:
                                <tr>
                                    <td>
                                        <a  class="label label-info"
                                            href="${admin_prefix}/x509-certificate-request/${csr.id}"
                                        >
                                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                            X509CertificateRequest-${csr.id}</a>
                                    </td>
                                </tr>
                            % endfor
                        </table>
                        % if results['X509CertificateRequest']['next']:
                            <a href="${results['X509CertificateRequest']['next']}">More</a>
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
