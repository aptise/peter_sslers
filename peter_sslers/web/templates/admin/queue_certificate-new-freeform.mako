<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/queue-certificates">Queue Certificate</a></li>
        <li class="active">New</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Queue Certificate - New</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/queue-certificate/new/freeform.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    ${admin_partials.handle_querystring_result()}
    <div class="row">
        <div class="col-sm-6">

            <h4>Queue a Renewal?</h4>
            
            <p>Upon submission, the following combination will be added to the processing queue for AcmeOrders.</p>
            
            <form
                action="${admin_prefix}/queue-certificate/new/freeform"
                method="POST"
                enctype="multipart/form-data"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}

                <h3>AcmeAccount</h3>
                ${admin_partials.formgroup__AcmeAccount_selector__advanced()}
                <hr/>

                <h3>PrivateKey</h3>
                ${admin_partials.formgroup__PrivateKey_selector__advanced(option_account_key_default=True, option_generate_new=True, default="private_key_for_account_key")}
                <hr/>

                ${admin_partials.formgroup__domain_names()}
                <hr/>

                ${admin_partials.formgroup__private_key_cycle__renewal()}
                <hr/>

                <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>
            </form>
        </div>
        <div class="col-sm-6">
            <p>This route supports JSON and is self-documenting on GET requests.</p>
            ${admin_partials.info_AcmeAccount()}
            ${admin_partials.info_PrivateKey()}
        </div>
    </div>
</%block>
