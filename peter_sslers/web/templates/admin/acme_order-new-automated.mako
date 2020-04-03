<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-orders">AcmeOrder</a></li>
        <li class="active">New</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>AcmeOrder | New</h2>
    <p><em>${request.text_library.info_AcmeOrder_new_Automated[1]}</em></p>
    <div class="alert alert-info">
        <em>
            Requests will be performed against the Certificate Authority associated with the Account Key
        </em>
    </div>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-order/new/automated.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">

    <div class="row">
        <div class="col-sm-6">

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
                ${admin_partials.formgroup__PrivateKey_selector__advanced(option_account_key_default=True, option_generate_new=True, default="private_key_for_account_key")}
                <hr/>

                ${admin_partials.formgroup__domain_names()}
                <hr/>

                <div class="form-group">
                    <label for="private_key_cycle">Private Key Cycle - Renewals</label>
                    <select class="form-control" name="private_key_cycle__renewal">
                        <% _default = model_websafe.PrivateKeyCycle._DEFAULT_AcmeOrder %>
                        % for _option_text in model_websafe.PrivateKeyCycle._options_AcmeOrder_private_key_cycle:
                            <option value="${_option_text}"${" selected" if (_option_text == _default) else ""}>${_option_text}</option>
                        % endfor
                    </select>
                </div>
                <hr/>

                ${admin_partials.formgroup__processing_strategy()}
                <hr/>

                <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>
            </form>
        </div>
        <div class="col-sm-6">
            <p>This route supports JSON and is self-documenting on GET requests.</p>
            ${admin_partials.info_AcmeAccountKey()}
            ${admin_partials.info_PrivateKey()}
        </div>
    </div>
</%block>
