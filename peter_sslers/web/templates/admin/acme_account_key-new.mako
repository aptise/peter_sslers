<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-account-keys">AcmeAccountKeys</a></li>
        <li class="active">New</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>AcmeAccountKey | New</h2>
    <p><em>${request.text_library.info_AcmeAccountKeys[1]}</em></p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-6">
            <form
                action="${admin_prefix}/acme-account-key/new"
                method="POST"
                enctype="multipart/form-data"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}

                <div class="form-group">
                    <label for="acme_account_provider_id">
                        ACME Provider
                    </label>
                    <select class="form-control" id="acme_account_provider_id" name="acme_account_provider_id">
                        % for option in AcmeAccountProviders:
                            <option value="${option.id}" ${'selected' if option.is_default else ''}>${option.name} (${option.url})</option>
                        % endfor
                    </select>
                </div>

                <div class="form-group">
                    <label for="token">contact</label>
                    <input class="form-control" type="text" name="contact" value=""/>
                </div>

                <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>
            </form>
        </div>
        <div class="col-sm-6">
            ${admin_partials.info_AcmeAccountKey()}
            <h3>This form accepts JSON</h3>

            <p>
                <code>curl ${request.api_host}${admin_prefix}/acme-account-key/new.json</code>
            </p>
        </div>
    </div>
</%block>
