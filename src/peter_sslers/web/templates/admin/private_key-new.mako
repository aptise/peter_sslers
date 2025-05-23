<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/private-keys">Private Keys</a></li>
        <li class="active">New</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Private Key | New</h2>
</%block>


<%block name="content_main">

    <div class="row">
        <div class="col-sm-6">

            <form
                action="${admin_prefix}/private-key/new"
                method="POST"
                enctype="multipart/form-data"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}

                <select class="form-control" id="private_key_generate" name="private_key_generate">
                    <% _default = model_websafe.KeyTechnology._DEFAULT_Generate %>
                    % for _option_text in model_websafe.KeyTechnology._options_Generate:
                        <option value="${_option_text}"${" selected" if (_option_text == _default) else ""}>${_option_text}</option>
                    % endfor
                </select>
                    
                <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>

            </form>
        </div>
        <div class="col-sm-6">
            ${admin_partials.info_PrivateKey()}

            <h3>This form is JSON capable</h3>
            <p>
                <code>curl ${request.api_host}${admin_prefix}/private-key/new.json</code>
            </p>

        </div>
    </div>
</%block>
