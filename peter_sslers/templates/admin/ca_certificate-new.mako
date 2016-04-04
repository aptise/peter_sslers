<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li><a href="/.well-known/admin/ca-certificates">CA Certificates</a></li>
        <li class="active">New</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>CA Certificates | New</h2>
    <p><em>${request.text_library.info_CACertificates[1]}</em></p>
</%block>

    
<%block name="content_main">

    <div class="row">
        <div class="col-sm-6">
        
            <%! show_text = False %>

            <form
                action="/.well-known/admin/ca-certificate/upload"
                method="POST"
                enctype="multipart/form-data"
            >
                <% form = request.formhandling.get_form(request) %>
                ${form.html_error_main('Error_Main')|n}

                ${admin_partials.formgroup__chain_file(show_text=show_text)}
                <hr/>

                <button type="submit" class="btn btn-default">Submit</button>
        
            </form>
        </div>
        <div class="col-sm-6">
            ${admin_partials.info_CACertificate()}

            <h3>This form accepts JSON</h3>
            
            <p>
                <code>curl http://127.0.0.1:6543/.well-known/admin/ca-certificate/upload.json</code>
            </p>


            <h3>Do you have a "bundle"?</h3>
            <p>
                We define a bundle as one or more of the following certificates:
                <ul>
                    <li>ISRG Root X1</li>
                    <li>Let’s Encrypt Authority X1</li>
                    <li>Let’s Encrypt Authority X2</li>
                    <li>Let’s Encrypt Authority X1 (IdenTrust cross-signed)</li>
                    <li>Let’s Encrypt Authority X2 (IdenTrust cross-signed)</li>
                </ul>
            </p>
            <p>
                You can upload a bundle of certificates on this form: <br/>
                <a  class="btn btn-primary"
                    href="/.well-known/admin/ca-certificate/upload-bundle"
                >Upload CaCert Bundle</a>
                    
            </p>
        </div>
    </div>
</%block>
