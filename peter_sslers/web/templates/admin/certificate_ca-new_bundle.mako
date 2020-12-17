<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificate-cas">CA Certificates</a></li>
        <li class="active">New Bundle</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>CA Certificates | New Bundle</h2>
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
                    CA_CROSS_SIGNED_X=CA_CROSS_SIGNED_X,
                    CA_AUTH_X=CA_AUTH_X,
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
% for xi in CA_CROSS_SIGNED_X:
    &nbsp;--form 'le_${xi}_cross_signed_file=@lets-encrypt-${xi}-cross-signed.pem'\<br/>
% endfor
% for xi in CA_AUTH_X:
    &nbsp;--form 'le_${xi}_auth_file=@letsencryptauthority${xi}.pem'\<br/>
% endfor
&nbsp;${request.admin_url}/certificate-ca/upload-bundle.json
</code>
</p>

        </div>
    </div>
</%block>
