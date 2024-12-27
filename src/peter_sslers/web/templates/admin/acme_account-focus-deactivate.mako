<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-accounts">AcmeAccounts</a></li>
        <li><a href="${admin_prefix}/acme-account/${AcmeAccount.id}">Focus [${AcmeAccount.id}]</a></li>
        <li class="active">Deactivate</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>AcmeAccounts - Focus - Deactivate</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-account/${AcmeAccount.id}/acme-server/deactivate.json" class="btn btn-xs btn-danger">
            <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    ${admin_partials.handle_querystring_result()}

    <div class="row">
        <div class="col-sm-12">

            <form action="${admin_prefix}/acme-account/${AcmeAccount.id}/acme-server/deactivate"
                  method="POST"
                  id="form-acme_account-deactivate"
                  >
            <% form = request.pyramid_formencode_classic.get_form() %>
            ${form.html_error_main_fillable()|n}

            <table class="table">
                <thead>
                    <tr>
                        <th colspan="2">
                            Core Details
                        </th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <th>id</th>
                        <td>
                            <span class="label label-default">
                                ${AcmeAccount.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>source</th>
                        <td>
                            <span class="label label-default">${AcmeAccount.acme_account_key.acme_account_key_source}</span>
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeServer</th>
                        <td>
                            <a
                                class="label label-info"
                                href="${admin_prefix}/acme-servers"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeServer-${AcmeAccount.acme_server_id}
                                [${AcmeAccount.acme_server.name}]
                                (${AcmeAccount.acme_server.url})
                            </a>
                        </td>
                    </tr>
                    <tr>
                        <th>contact</th>
                        <td><code>${AcmeAccount.contact or ''}</code></td>
                    </tr>
                    <tr>
                        <th>key_pem_md5</th>
                        <td><code data-key_id="${AcmeAccount.acme_account_key.id}" data-key_pem_md5="${AcmeAccount.acme_account_key.key_pem_md5}">${AcmeAccount.acme_account_key.key_pem_md5}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>Deactivate?</th>
                        <td>
                            <div class="form-group">
                                <label for="key_pem">key pem</label>
                                <span class="help-inline">Just to be safe, please enter the key_pem_md5 or key_pem.</span>
                                <input type="text" name="key_pem" class="form-control" />
                            </div>
                            <button class="btn btn-danger" type="submit" name="submit" value="submit">
                                <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                Deactivate
                            </button>
                        </td>
                    </tr>
                </tbody>
            </table>
            </form>
        </div>
    </div>
</%block>
