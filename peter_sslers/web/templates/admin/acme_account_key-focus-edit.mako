<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-account-keys">AcmeAccountKeys</a></li>
        <li><a href="${admin_prefix}/acme-account-key/${AcmeAccountKey.id}">Focus [${AcmeAccountKey.id}]</a></li>
        <li class="active">Edit</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>AcmeAccountKeys - Focus - Edit</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-account-key/${AcmeAccountKey.id}/edit.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-pencil" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    ${admin_partials.standard_error_display()}
    ${admin_partials.handle_querystring_result()}

    <div class="row">
        <div class="col-sm-12">
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
                                ${AcmeAccountKey.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>source</th>
                        <td>
                            <span class="label label-default">${AcmeAccountKey.acme_account_key_source}</span>
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
                                AcmeAccountProvider-${AcmeAccountKey.acme_account_provider_id}
                                [${AcmeAccountKey.acme_account_provider.name}]
                                (${AcmeAccountKey.acme_account_provider.url})
                            </a>
                        </td>
                    </tr>
                    <tr>
                        <th>contact</th>
                        <td><code>${AcmeAccountKey.contact or ''}</code></td>
                    </tr>
                    <tr>
                        <th>key_pem_md5</th>
                        <td><code>${AcmeAccountKey.key_pem_md5}</code></td>
                    </tr>
                    <tr>
                        <th>PrivateKey cycle</th>
                        <td>
                            <form action="${admin_prefix}/acme-account-key/${AcmeAccountKey.id}/edit"
                                  method="POST"
                                  >
                                <%
                                    _selected = AcmeAccountKey.private_key_cycle
                                %>
                                <select class="form-control" name="private_key_cycle">
                                    % for _option_text in model_websafe.PrivateKeyCycle._options_AcmeAccountKey_private_key_cycle:
                                        <%
                                            _selected = ' selected' if _option_text == _selected else ''
                                        %>
                                        <option value="${_option_text}" ${_selected}>${_option_text}</option>
                                    % endfor
                                </select>
                                <button class="btn btn-primary">
                                    <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
                                    Edit
                                </button>
                            </form>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</%block>
