<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificates">Certificates</a></li>
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
                action="${admin_prefix}/certificate/upload"
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

            <p><code>curl --form "private_key_file=@privkey1.pem" --form "certificate_file=@cert1.pem" --form "chain_file=@chain1.pem" ${request.admin_url}/certificate/upload</code></p>

            <p>But instead of that, post to <code>upload.json</code>, which will give you a json parcel in return</p>

            <p><code>curl --form "private_key_file=@privkey1.pem" --form "certificate_file=@cert1.pem" --form "chain_file=@chain1.pem" ${request.admin_url}/certificate/upload.json</code></p>

            <p>The JSON response will have a <code>result</code> attribute that is "success" or "error"; if there is an error, you will see the info in <code>form_errors</code></p>

            <table class="table table-striped table-condensed">
                <tr>
                    <th>valid form</th>
                    <td><code>{"private_key": {"id": 2, "created": false}, "ca_certificate": {"id": 1, "created": false}, "result": "success", "certificate": {"url": "${admin_prefix}/certificate/2", "id": 2, "created": false}}</code></td>
                </tr>
                <tr>
                    <th>valid form</th>
                    <td><code>{"form_errors": {"Error_Main": "There was an error with your form. ", "chain_file": "Missing value"}, "result": "error"}</code></td>
                </tr>
            </table>

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
