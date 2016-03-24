<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li><a href="/.well-known/admin/certificates">Certificates</a></li>
        <li class="active">Upload</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Upload Certificate</h2>
    <p>
        You can upload existing certificates for management and deployment.
    </p>
</%block>
    

<%block name="content_main">

    <div class="row">
        <div class="col-sm-6">
        
            <%! show_text = False %>
            <form
                action="/.well-known/admin/certificate/upload"
                method="POST"
                enctype="multipart/form-data"
            >
                <% form = request.formhandling.get_form(request) %>
                ${form.html_error_main('Error_Main')|n}

                ${admin_partials.formgroup__private_key_file(show_text=show_text)}
                <hr/>

                ${admin_partials.formgroup__certificate_file(show_text=show_text)}
                <hr/>

                ${admin_partials.formgroup__chain_file(show_text=show_text)}
                <hr/>

                <button type="submit" class="btn btn-default">Submit</button>
        
            </form>
        </div>
        <div class="col-sm-6">

            <h2>Why do you need the private key?  That is a security risk!</h2>
                <p>YES! Storing your private key IS a security risk.</p>
                <p>This tool was designed for distributing the ssl certificate chains -- and private keys -- within a secured LAN.</p>
                <p>If you feel uncomfortable with this tool DO NOT USE IT.  This is for advanced deployments.</p>

            <h2>How can I do this from the command line?</h2>
            
            <p>running locally from a directory that includes letencrypt issued files, you could do the following:</p>
            
            <p><code>curl --form "private_key_file=@privkey1.pem" --form "certificate_file=@cert1.pem" --form "chain_file=@chain1.pem" http://127.0.0.1:6543/.well-known/admin/certificate/upload</code></p>


            <h2>What do all these mean?</h2>
            
            <p>
                If you are famiiliar with LetsEncrypt or most other Certificate Authorities
            </p>
            
            <table class="table table-striped table-condensed">
                <tr>
                    <th>Private Key</th>
                    <td>The private key used to sign requests</td>
                    <td><code>privkey.pem</code></td>
                </tr>
                <tr>
                    <th>Signed Certificate</th>
                    <td>The signed certificate file in PEM format</td>
                    <td><code>cert.pem</code></td>
                </tr>
                <tr>
                    <th>Chain File</th>
                    <td>The upstream chain from the CA</td>
                    <td><code>chain.pem</code></td>
                </tr>
            </table>
            
            <p>
                Right now this tool only handles Chain files that include a single cert.
                We do not need <code>fullchain.pem</code>, because that is just <code>cert.pem + fullchain.pem</code>
            </p>

        </div>
    </div>
</%block>
