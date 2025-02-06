<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-accounts">AcmeAccounts</a></li>
        <li class="active">New</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>AcmeAccount | New</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-6">

            ${admin_partials.handle_querystring_result()}

            <form
                action="${admin_prefix}/acme-account/new"
                method="POST"
                enctype="multipart/form-data"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}

                <div class="form-group">
                    <label for="acme_server_id">
                        ACME Server
                    </label>
                    <select class="form-control" id="acme_server_id" name="acme_server_id">
                        <%
                            ## the default will be one of two places...
                            ## first is the param
                            ## second is the `option.is_default` attribute
                            _requested_id = request.params.get("acme-server-id")
                            if _requested_id:
                                try:
                                    _requested_id = int(_requested_id)
                                except:
                                    pass
                            option_status = {}
                            for option in AcmeServers:
                                if option.id == _requested_id:
                                    option_status[option.id] = "selected"
                                else:
                                    if option.is_default and not _requested_id:                         
                                        option_status[option.id] = "selected"
                                    else:
                                        option_status[option.id] = ""
                        %>
                        % for option in AcmeServers:
                            <option value="${option.id}" ${option_status[option.id]}>${option.name} (${option.url})</option>
                        % endfor
                    </select>
                </div>
                
                <h3>Account Data</h3>

                <div class="form-group">
                    <label for="account__contact">contact</label>
                    <input class="form-control" type="text" name="account__contact" value=""/>
                </div>

                <div class="form-group">
                    <label for="account__private_key_technology">PrivateKey Technology</label>
                    <select class="form-control" name="account__private_key_technology">
                        <% _default = model_websafe.KeyTechnology._DEFAULT_AcmeAccount %>
                        % for _option_text in model_websafe.KeyTechnology._options_AcmeAccount_private_key_technology:
                            <option value="${_option_text}"${" selected" if (_option_text == _default) else ""}>${_option_text}</option>
                        % endfor
                    </select>
                </div>

                <hr/>
                <h3>Order/Renewal Defaults</h3>
                ${admin_partials.formgroup__AcmeAccount_order_defaults()}

                <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>
            </form>
        </div>
        <div class="col-sm-6">
            ${admin_partials.info_AcmeAccount()}
            <h3>This form is JSON capable</h3>

            <p>
                <code>curl ${request.api_host}${admin_prefix}/acme-account/new.json</code>
            </p>
        </div>
    </div>
</%block>
