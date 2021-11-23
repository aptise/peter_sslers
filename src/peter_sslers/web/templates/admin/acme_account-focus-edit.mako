<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-accounts">AcmeAccounts</a></li>
        <li><a href="${admin_prefix}/acme-account/${AcmeAccount.id}">Focus [${AcmeAccount.id}]</a></li>
        <li class="active">Edit</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>AcmeAccounts - Focus - Edit</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-account/${AcmeAccount.id}/edit.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-pencil" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    ${admin_partials.handle_querystring_result()}

    <div class="row">
        <div class="col-sm-12">

            <form action="${admin_prefix}/acme-account/${AcmeAccount.id}/edit"
                  method="POST"
                  >
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
                        <th>AcmeAccountProvider</th>
                        <td>
                            <a
                                class="label label-info"
                                href="${admin_prefix}/acme-account-providers"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeAccountProvider-${AcmeAccount.acme_account_provider_id}
                                [${AcmeAccount.acme_account_provider.name}]
                                (${AcmeAccount.acme_account_provider.url})
                            </a>
                        </td>
                    </tr>
                    <tr>
                        <th>contact</th>
                        <td><code>${AcmeAccount.contact or ''}</code></td>
                    </tr>
                    <tr>
                        <th>key_pem_md5</th>
                        <td><code>${AcmeAccount.acme_account_key.key_pem_md5}</code></td>
                    </tr>
                    <tr>
                        <th>PrivateKey cycle</th>
                        <td>
                            <%
                                _selected = AcmeAccount.private_key_cycle
                            %>
                            <select class="form-control" name="account__private_key_cycle">
                                % for _option_text in model_websafe.PrivateKeyCycle._options_AcmeAccount_private_key_cycle:
                                    <%
                                        _selected = ' selected' if _option_text == _selected else ''
                                    %>
                                    <option value="${_option_text}" ${_selected}>${_option_text}</option>
                                % endfor
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th>PrivateKey Technology</th>
                        <td>
                                <%
                                    _selected = AcmeAccount.private_key_technology
                                %>
                                <select class="form-control" name="account__private_key_technology">
                                    % for _option_text in model_websafe.KeyTechnology._options_AcmeAccount_private_key_technology:
                                        <%
                                            _selected = ' selected' if _option_text == _selected else ''
                                        %>
                                        <option value="${_option_text}" ${_selected}>${_option_text}</option>
                                    % endfor
                                </select>
                        </td>
                    </tr>
                    <tr>
                        <th></th>
                        <td>
                            <button class="btn btn-primary" type="submit" name="submit" value="submit">
                                <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
                                Edit
                            </button>
                        </td>
                    </tr>
                </tbody>
            </table>
            </form>
        </div>
    </div>
</%block>
