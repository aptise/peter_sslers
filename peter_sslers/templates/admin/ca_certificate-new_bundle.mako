<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li><a href="/.well-known/admin/ca_certificates">CA Certificates</a></li>
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
                action="/.well-known/admin/ca_certificate/upload_bundle"
                method="POST"
                enctype="multipart/form-data"
            >
                <% form = request.formhandling.get_form(request) %>
                ${form.html_error_main('Error_Main')|n}

                ${admin_partials.formgroup__chain_bundle_file()}
                <hr/>

                <button type="submit" class="btn btn-default">Submit</button>
        
            </form>
        </div>
        <div class="col-sm-6">
            ${admin_partials.info_CACertificate()}

            <h3>This form accepts JSON</h3>
            
            <p>
                <code>curl http://127.0.0.1:6543/.well-known/admin/ca_certificate/upload.json</code>
            </p>

<p>
<code>curl \<br/>
&nbsp;--form 'isrgrootx1_file=@isrgrootx1.pem'\<br/>
&nbsp;--form 'le_x1_cross_signed_file=@lets-encrypt-x1-cross-signed.pem'\<br/>
&nbsp;--form 'le_x2_cross_signed_file=@lets-encrypt-x2-cross-signed.pem'\<br/>
&nbsp;--form 'le_x1_auth_file=@letsencryptauthorityx2.pem'\<br/>
&nbsp;--form 'le_x2_auth_file=@letsencryptauthorityx2.pem'\<br/>
&nbsp;http://127.0.0.1:6543/.well-known/admin/ca_certificate/upload_bundle.json
</code>
</p>

        </div>
    </div>
</%block>
