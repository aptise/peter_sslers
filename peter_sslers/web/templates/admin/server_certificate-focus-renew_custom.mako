<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%! enable_search = False %>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/server-certificates">ServerCertificates</a></li>
        <li><a href="${admin_prefix}/server-certificate/${ServerCertificate.id}">Focus [${ServerCertificate.id}]</a></li>
        <li class="active">Renew</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>ServerCertificate - Focus - RENEW</h2>
</%block>


<%block name="content_main">

    <div class="row">
        <div class="col-sm-12">

            <form method="POST"
                  action="${admin_prefix}/server-certificate/${ServerCertificate.id}/renew/custom"
                  enctype="multipart/form-data"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}

                <h3>Custom Renewal</h3>

                <p>We will generate a New AcmeOrder and CertificateSigningRequest through LetsEncrypt</p>

                <table class="table table-striped table-condensed">
                    <tr>
                        <th>Renewal of</th>
                        <td>
                            <table class="table table-striped table-condensed">
                                <tr>
                                    <th>Server Certificate</th>
                                    <td>
                                        <a  class="label label-info"
                                            href="${admin_prefix}/server-certificate/${ServerCertificate.id}"
                                        >
                                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                            ServerCertificate-${ServerCertificate.id}
                                        </a>
                                    </td>
                                </tr>
                                <tr>
                                    <th>Issued:</th>
                                    <td>
                                        <timestamp>${ServerCertificate.timestamp_signed}</timestamp>
                                    </td>
                                </tr>
                                <tr>
                                    <th>Expires</th>
                                    <td>
                                        <timestamp>${ServerCertificate.timestamp_expires}</timestamp>
                                    </td>
                                </tr>
                                <tr>
                                    <th>Domains</th>
                                    <td>
                                        <a  class="label label-info"
                                            href="${admin_prefix}/unique-fqdn-set/${ServerCertificate.unique_fqdn_set_id}"
                                        >
                                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                            UniqueFQDNSet-${ServerCertificate.unique_fqdn_set_id}
                                        </a>
                                        <br/>
                                        <code>${ServerCertificate.domains_as_string}</code>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeAccount</th>
                        <td>
                            ${admin_partials.formgroup__AcmeAccountKey_selector__advanced(
                                dbAcmeAccountKeyReuse=ServerCertificate.acme_account_key,
                            )}
                        </td>
                    </tr>
                    <tr>
                        <th>Private Key</th>
                        <td>
                            ${admin_partials.formgroup__PrivateKey_selector__advanced(
                                show_text=False,
                                dbPrivateKeyReuse=ServerCertificate.private_key,
                                option_generate_new=True,
                            )}
                        </td>
                    </tr>
                </table>

                <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>

            </form>
        </div>
    </div>

    <div class="row">
        <div class="col-sm-6">
        </div>
    </div>

</%block>
