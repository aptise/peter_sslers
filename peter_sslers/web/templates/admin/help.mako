<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Help</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Admin Help</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-6">

            <h3>What must be installed on my webserver?</h3>
            <p>
                Your webserver must have the following 3 items installed:
                <ul>
                    <li>PrivateKey</li>
                    <li>CertificateSigned</li>
                    <li>CertificateCA</li>
                </ul>
                Some webservers require the CertificateSigned and CertificateCA be joined in PEM format as a "fullchain" certificate.
            </p>

             <p>Most pages have documentation on them</p>

            <h4>Core Objects</h4>
            <table class="table table-striped table-condensed">
                <tr>
                    <th>AcmeOrder</th>
                    <td>An <em>AcmeOrder</em>  is used to request a new signed certificate for your server.
                    </td>
                </tr>
                <tr>
                    <th>UniqueFQDNSet</th>
                    <td>An <em>UniqueFQDNSet</em>  is a unique grouping of <en>Domains</em>.
                    </td>
                </tr>
                <tr>
                    <th>AcmeAccount</th>
                    <td>An Account and Secret Key that is registered with the LetsEncrypt service.
                        The <em>AcmeAccount</em> has an <em>AcmeAccountKey</em> that is only used for Authentication against the LetsEncrypt service.
                    </td>
                </tr>
                <tr>
                    <th>PrivateKey</th>
                    <td>An RSA Key that is used to sign <em>CertficateRequest</em>s AND is paired to your <em>CertificateSigned</em>.
                        The <em>PrivateKey</em> must be installed on your webserver to serve https content.
                    </td>
                </tr>
                <tr>
                    <th>CertificateRequest</th>
                    <td>In order to get a <em>CertificateSigned</em> you create a <em>CertificateRequest</em> and sign it with your <em>PrivateKey</em>.
                        It is generally not needed after a <em>CertificateSigned</em> is issued.
                        A <em>CertificateRequest</em> will be created when an <em>AcmeOrder</em> is successful.
                    </td>
                </tr>
                <tr>
                    <th>CertificateSigned</th>
                    <td>Your <em>CertificateSigned</em> is an OpenSSL certificate that has been signed by a trusted <em>CertificateCA</em>.
                        The <em>CertificateSigned</em> must be installed on your webserver with the <em>PrivateKey</em> that signed the corresponding <em>CertificateRequest</em> to serve https content.
                    </td>
                </tr>
                <tr>
                    <th>CertificateCA</th>
                    <td>A trusted Certificate Authority Certificate, used to sign your <em>CertificateSigned</em>.
                        It must be installed on your webserver in order to serve https content.
                    </td>
                </tr>

            </table>

        </div>
        <div class="col-sm-6">

            <h4>Status Codes</h4>
            <table class="table table-condensed">
                <tr>
                    <th>Authorization</th>
                    <td>
                        <table class="table table-striped table-condensed">
                            <tr>
                                <th><code>*discovered*</code></th>
                                <td>Not an ACME RFC Status. Internal marker. Equivalent to "pending", but not yet confirmed with the ACME Server.</td>
                            </tr>
                            <tr>
                                <th><code>pending</code></th>
                                <td>see ACME RFC</td>
                            </tr>
                            <tr>
                                <th><code>valid</code></th>
                                <td>see ACME RFC</td>
                            </tr>
                            <tr>
                                <th><code>invalid</code></th>
                                <td>see ACME RFC</td>
                            </tr>
                            <tr>
                                <th><code>deactivated</code></th>
                                <td>see ACME RFC</td>
                            </tr>
                            <tr>
                                <th><code>expired</code></th>
                                <td>see ACME RFC</td>
                            </tr>
                            <tr>
                                <th><code>revoked</code></th>
                                <td>see ACME RFC</td>
                            </tr>
                            <tr>
                                <th><code>*404*</code></th>
                                <td>Not an ACME RFC Status. Internal marker to signify the ACME Server returned a 404 response for the AuthoriationURL.</td>
                            </tr>
                            <tr>
                                <th><code>*406*</code></th>
                                <td>Not an ACME RFC Status. Internal marker to signify the ACME Server returned a status that is untracked/unknown.</td>
                            </tr>
                        </table>
                    </td>
                </tr>

                <tr>
                    <th>Challenge</th>
                    <td>
                        <table class="table table-striped table-condensed">
                            <tr>
                                <th><code>*discovered*</code></th>
                                <td>Not an ACME RFC Status. Internal marker. Equivalent to "pending", but not yet confirmed with the ACME Server.</td>
                            </tr>
                            <tr>
                                <th><code>pending</code></th>
                                <td>see ACME RFC</td>
                            </tr>
                            <tr>
                                <th><code>processing</code></th>
                                <td>see ACME RFC</td>
                            </tr>
                            <tr>
                                <th><code>valid</code></th>
                                <td>see ACME RFC</td>
                            </tr>
                            <tr>
                                <th><code>invalid</code></th>
                                <td>see ACME RFC</td>
                            </tr>
                            <tr>
                                <th><code>*404*</code></th>
                                <td>Not an ACME RFC Status. Internal marker to signify the ACME Server returned a 404 response for the AuthoriationURL.</td>
                            </tr>
                            <tr>
                                <th><code>*406*</code></th>
                                <td>Not an ACME RFC Status. Internal marker to signify the ACME Server returned a status that is untracked/unknown.</td>
                            </tr>
                            <tr>
                                <th><code>*410*</code></th>
                                <td>Not an ACME RFC Status. Internal marker to signify the ACME Server no longer shows this AcmeChallenge as part of the AcmeAuthorization that had created it. The AcmeChallenge may still be synced and show another RFC code, or may <code>*404*</code>.</td>
                            </tr>
                        </table>
                    </td>
                </tr>

                <tr>
                    <th>Order</th>
                    <td>
                        <table class="table table-striped table-condensed">
                            <tr>
                                <th><code>*discovered*</code></th>
                                <td>Not an ACME RFC Status. Internal marker. Equivalent to "pending", but not yet confirmed with the ACME Server.</td>
                            </tr>
                            <tr>
                                <th><code>pending</code></th>
                                <td>see ACME RFC</td>
                            </tr>
                            <tr>
                                <th><code>ready</code></th>
                                <td>see ACME RFC</td>
                            </tr>
                            <tr>
                                <th><code>processing</code></th>
                                <td>see ACME RFC</td>
                            </tr>
                            <tr>
                                <th><code>valid</code></th>
                                <td>see ACME RFC</td>
                            </tr>
                            <tr>
                                <th><code>invalid</code></th>
                                <td>see ACME RFC</td>
                            </tr>
                            <tr>
                                <th><code>*404*</code></th>
                                <td>Not an ACME RFC Status. Internal marker to signify the ACME Server returned a 404 response for the AuthoriationURL.</td>
                            </tr>
                            <tr>
                                <th><code>*406*</code></th>
                                <td>Not an ACME RFC Status. Internal marker to signify the ACME Server returned a status that is untracked/unknown.</td>
                            </tr>
                        </table>
                    </td>
                </tr>
        </div>
    </div>
</%block>
