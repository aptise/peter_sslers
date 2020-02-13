<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificate-requests">Certificate Requests</a></li>
        <li class="active">New</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Certificate Request - FULL | New</h2>
    <p><em>${request.text_library.info_AcmeOrder_new_Automated[1]}</em></p>
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
                action="${admin_prefix}/acme-order/new/automated"
                method="POST"
                enctype="multipart/form-data"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}

                <h3>AcmeAccountKey</h3>
                ${admin_partials.formgroup__AcmeAccountKey_selector__advanced()}
                <hr/>

                <h3>PrivateKey</h3>
                ${admin_partials.formgroup__PrivateKey_selector__advanced(show_text=show_text)}
                <hr/>

                ${admin_partials.formgroup__domain_names()}
                <hr/>

                <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>

            </form>
        </div>
        <div class="col-sm-6">
            ${admin_partials.info_AcmeAccountKey()}
            ${admin_partials.info_PrivateKey()}
        </div>
    </div>
</%block>