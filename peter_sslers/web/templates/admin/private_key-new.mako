<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/private-keys">Private Keys</a></li>
        <li class="active">Upload</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Private Key | New</h2>
    <p><em>${request.text_library.info_PrivateKeys[1]}</em></p>
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

                <div class="radio">
                    <label>
                        <input type="radio" name="bits" id="private_key=bits" value="4096" checked="checked"/>
                        4096 bits
                    </label>
                </div>

                <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>

            </form>
        </div>
        <div class="col-sm-6">
            ${admin_partials.info_PrivateKey()}

            <h3>This form accepts JSON</h3>
            <p>
                <code>curl ${request.api_host}${admin_prefix}/private-key/new.json</code>
            </p>

        </div>
    </div>
</%block>
