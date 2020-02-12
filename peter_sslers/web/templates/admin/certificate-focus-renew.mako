<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%! enable_search = False %>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificates">Certificates</a></li>
        <li><a href="${admin_prefix}/certificate/${ServerCertificate.id}">Focus [${ServerCertificate.id}]</a></li>
        <li class="active">Renew</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Certificate - Focus - RENEW</h2>
</%block>


<%block name="content_main">

    <div class="row">
        <div class="col-sm-12">

            <form method="POST"
                  action="${admin_prefix}/certificate/${ServerCertificate.id}/renew/custom"
                  enctype="multipart/form-data"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}

                <h3>Custom Renewal</h3>

                <p>We will generate a new CSR through letsencypt</p>

                <table class="table table-striped table-condensed">
                    <tr>
                        <th>renewal of: id</th>
                        <td>
                            <a  class="btn btn-xs btn-info"
                                href="${admin_prefix}/certificate/${ServerCertificate.id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                cert-${ServerCertificate.id}
                            </a>
                        </td>
                    </tr>
                    <tr>
                        <th>renewal of: issued</th>
                        <td>
                            <timestamp>${ServerCertificate.timestamp_signed}</timestamp>
                        </td>
                    </tr>
                    <tr>
                        <th>renewal of: expires</th>
                        <td>
                            <timestamp>${ServerCertificate.timestamp_expires}</timestamp>
                        </td>
                    </tr>
                    <tr>
                        <th>renewal of: expires</th>
                        <td>
                            <timestamp>${ServerCertificate.timestamp_expires}</timestamp>
                        </td>
                    </tr>
                    <tr>
                        <th>domains</th>
                        <td><code>${ServerCertificate.domains_as_string}</code></td>
                    </tr>
                    <tr>
                        <th>Lets Encrypt Account</th>
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
                            )}
                        </td>
                    </tr>
                </table>

                <input type="submit" value="submit" />

            </form>
        </div>
    </div>

    <div class="row">
        <div class="col-sm-6">
        </div>
    </div>

</%block>
