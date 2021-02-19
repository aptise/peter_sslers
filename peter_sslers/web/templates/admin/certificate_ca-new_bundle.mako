<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificate-cas">CertificateCAs</a></li>
        <li class="active">New Bundle</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>CertificateCAs | New Bundle</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-6">

            <%! show_text = False %>

            <form
                action="${admin_prefix}/certificate-ca/upload-bundle"
                method="POST"
                enctype="multipart/form-data"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}

                ${admin_partials.formgroup__CertificateCAChain_bundle_file(
                    CA_LE_INTERMEDIATES=CA_LE_INTERMEDIATES,
                    CA_LE_INTERMEDIATES_CROSSED=CA_LE_INTERMEDIATES_CROSSED,
                )}
                <hr/>

                <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>

            </form>
        </div>
        <div class="col-sm-6">
            ${admin_partials.info_CertificateCA()}

            <h3>You only need this form if you are uploading OLD certificates</h3>
            <p>This form can import your old bundled certificates.</p>
            <p>New certificates are automatically recorded when discovered.</p>
            <p>You can also "download" the certificate authority to sync discovered certificates with human-readable information.</p>

            <h3>This form is JSON capable</h3>
            <p>
                <code>curl ${request.admin_url}/certificate-ca/upload.json</code>
            </p>

<p>
<code>curl \<br/>
&nbsp;--form 'isrgrootx1_file=@isrgrootx1.pem'\<br/>
% for xi in CA_LE_INTERMEDIATES_CROSSED:
    &nbsp;--form 'le_${xi}_cross_file=@lets-encrypt-${xi}-cross-signed.pem'\<br/>
% endfor
% for xi in CA_LE_INTERMEDIATES:
    &nbsp;--form 'le_int_${xi}_file=@letsencryptauthority${xi}.pem'\<br/>
% endfor
&nbsp;${request.admin_url}/certificate-ca/upload-bundle.json
</code>
</p>

            <h3>What is a "bundle"?</h3>
            <p>
                We define a bundle as one or more of the following certificates:
                <ul>
                    <li>ISRG Root X1</li>
                    <li>ISRG Root X2</li>
                    <li>ISRG Root X2 (ISRG Root X1 cross-signed)</li>
                    <li>Let’s Encrypt Authority E1</li>
                    <li>Let’s Encrypt Authority E2</li>
                    <li>Let’s Encrypt Authority R3</li>
                    <li>Let’s Encrypt Authority R4</li>
                    <li>Let’s Encrypt Authority R3 (IdenTrust cross-signed)</li>
                    <li>Let’s Encrypt Authority R4 (IdenTrust cross-signed)</li>

                    <li>Let’s Encrypt Authority X1</li>
                    <li>Let’s Encrypt Authority X2</li>
                    <li>Let’s Encrypt Authority X3</li>
                    <li>Let’s Encrypt Authority X4</li>
                    <li>Let’s Encrypt Authority X1 (IdenTrust cross-signed)</li>
                    <li>Let’s Encrypt Authority X2 (IdenTrust cross-signed)</li>
                    <li>Let’s Encrypt Authority X3 (IdenTrust cross-signed)</li>
                    <li>Let’s Encrypt Authority X4 (IdenTrust cross-signed)</li>
                </ul>
            </p>

        </div>
    </div>
</%block>
