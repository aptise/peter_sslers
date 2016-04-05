<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li><a href="/.well-known/admin/ca-certificates">CA Certificates</a></li>
        <li class="active">New Bundle</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>CA Certificates | New Bundle</h2>
    <p><em>${request.text_library.info_CACertificates[1]}</em></p>
</%block>


<%block name="content_main">

    <div class="row">
        <div class="col-sm-6">

            <%! show_text = False %>

            <form
                action="/.well-known/admin/ca-certificate/upload-bundle"
                method="POST"
                enctype="multipart/form-data"
            >
                <% form = request.formhandling.get_form(request) %>
                ${form.html_error_main('Error_Main')|n}

                ${admin_partials.formgroup__chain_bundle_file(
                    CA_CROSS_SIGNED_X=CA_CROSS_SIGNED_X,
                    CA_AUTH_X=CA_AUTH_X,
                )}
                <hr/>

                <button type="submit" class="btn btn-default">Submit</button>

            </form>
        </div>
        <div class="col-sm-6">
            ${admin_partials.info_CACertificate()}

            <h3>You only need this form if you are uploading OLD certificates</h3>
            <p>This form can import your old bundled certificates.</p>
            <p>New certificates are automatically recorded when discovered.</p>
            <p>You can also "probe" the certificate authority to sync discovered certificates with human-readable information.</p>


            <h3>This form accepts JSON</h3>

            <p>
                <code>curl http://127.0.0.1:6543/.well-known/admin/ca-certificate/upload.json</code>
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
&nbsp;http://127.0.0.1:6543/.well-known/admin/ca-certificate/upload-bundle.json
</code>
</p>

        </div>
    </div>
</%block>
