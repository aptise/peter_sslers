<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li>Peter SSLers</li>
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificate-requests">Certificate Requests</a></li>
        <li class="active">New</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Certificate Request - FULL | New</h2>
    <p><em>${request.text_library.info_CertificateRequest_new_AcmeAutomated[1]}</em></p>
    <div class="alert alert-info">
        <em>
            Requests will be performed against the following Certificate Authority:
            <b>${CERTIFICATE_AUTHORITY}</b>
        </em>
    </div>
</%block>


<%block name="content_main">

    <div class="row">
        <div class="col-sm-6">

            <%! show_text = False %>

            <form
                action="${admin_prefix}/certificate-request/new-acme-automated"
                method="POST"
                enctype="multipart/form-data"
            >
                <% form = request.formhandling.get_form(request) %>
                ${form.html_error_main('Error_Main')|n}

                ${admin_partials.formgroup__account_key_file(show_text=show_text)}
                <hr/>
                ${admin_partials.formgroup__private_key_file(show_text=show_text)}
                <hr/>
                ${admin_partials.formgroup__domain_names()}
                <hr/>

                <button type="submit" class="btn btn-default">Submit</button>

            </form>
        </div>
        <div class="col-sm-6">
            ${admin_partials.info_AccountKey()}
            ${admin_partials.info_PrivateKey()}
        </div>
    </div>
</%block>
