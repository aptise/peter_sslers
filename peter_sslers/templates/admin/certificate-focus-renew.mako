<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%! enable_search = False %>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificates">Certificates</a></li>
        <li><a href="${admin_prefix}/certificates/${SslServerCertificate.id}">Focus [${SslServerCertificate.id}]</a></li>
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
                  action="${admin_prefix}/certificate/${SslServerCertificate.id}/renew/custom"
                  enctype="multipart/form-data"
            >
                <% form = request.formhandling.get_form(request) %>
                ${form.html_error_main_fillable()|n}

                <h3>Custom Renewal</h3>

                <p>We will generate a new CSR through letsencypt</p>

                <table class="table table-striped table-condensed">
                    <tr>
                        <th>renewal of: id</th>
                        <td>
                            <a  class="btn btn-xs btn-info"
                                href="${admin_prefix}/certificate/${SslServerCertificate.id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                cert-${SslServerCertificate.id}
                            </a>
                        </td>
                    </tr>
                    <tr>
                        <th>renewal of: issued</th>
                        <td>
                            <timestamp>${SslServerCertificate.timestamp_signed}</timestamp>
                        </td>
                    </tr>
                    <tr>
                        <th>renewal of: expires</th>
                        <td>
                            <timestamp>${SslServerCertificate.timestamp_expires}</timestamp>
                        </td>
                    </tr>
                    <tr>
                        <th>renewal of: expires</th>
                        <td>
                            <timestamp>${SslServerCertificate.timestamp_expires}</timestamp>
                        </td>
                    </tr>
                    <tr>
                        <th>domains</th>
                        <td><code>${SslServerCertificate.domains_as_string}</code></td>
                    </tr>
                    <tr>
                        <th>Lets Encrypt Account</th>
                        <td>
                            ${admin_partials.formgroup__account_key_selector_advanced(
                                show_text=False,
                                dbAccountKeyReuse=SslServerCertificate.letsencrypt_account_key,
                            )}
                        </td>
                    </tr>
                    <tr>
                        <th>Private Key</th>
                        <td>
                            ${admin_partials.formgroup__private_key_selector_advanced(
                                show_text=False,
                                dbPrivateKeyReuse=SslServerCertificate.private_key,
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
