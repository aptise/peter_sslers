<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-account-keys">AcmeAccountKeys</a></li>
        <li class="active">Focus [${AcmeAccountKey.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>AcmeAccountKeys - Focus</h2>
    <p>${request.text_library.info_AcmeAccountKeys[1]}</p>

    ${admin_partials.standard_error_display()}
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-account-key/${AcmeAccountKey.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
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
                        <th>timestamp_last_authenticated</th>
                        <td><timestamp>${AcmeAccountKey.timestamp_last_authenticated or ''}</timestamp>
                            % if AcmeAccountKey.is_can_authenticate:
                                <form action="${admin_prefix}/acme-account-key/${AcmeAccountKey.id}/authenticate" method="POST">
                                    <button class="btn btn-xs btn-primary" type="submit">
                                        <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                        Authenticate Against ACME Server
                                    </button>
                                </form>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>is_active</th>
                        <td>
                            <span class="label label-${'success' if AcmeAccountKey.is_active else 'warning'}">
                                ${'active' if AcmeAccountKey.is_active else 'inactive'}
                            </span>
                            &nbsp;
                            % if not AcmeAccountKey.is_active:
                                <form action="${admin_prefix}/acme-account-key/${AcmeAccountKey.id}/mark" method="POST" style="display:inline;">
                                    <input type="hidden" name="action" value="active"/>
                                    <button class="label label-info" type="submit">
                                        <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                        active
                                    </button>
                                </form>
                            % else:
                                % if not AcmeAccountKey.is_default:
                                    <form action="${admin_prefix}/acme-account-key/${AcmeAccountKey.id}/mark" method="POST" style="display:inline;">
                                        <input type="hidden" name="action" value="inactive"/>
                                        <button class="label label-danger" type="submit">
                                            <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                            inactive
                                        </button>
                                    </form>
                                % else:
                                    <span
                                        class="label label-warning"
                                    >
                                        <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                        select another default key to deactivate this one
                                    </span>
                                % endif
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>is_default</th>
                        <td>
                            % if AcmeAccountKey.is_default:
                                <span class="label label-success">
                                    default
                                </span>
                            % else:
                                <span class="label label-default">
                                    no
                                </span>
                            % endif
                            &nbsp;
                            % if AcmeAccountKey.is_default_candidate:
                                <form action="${admin_prefix}/acme-account-key/${AcmeAccountKey.id}/mark" method="POST" style="display:inline;">
                                    <input type="hidden" name="action" value="default"/>
                                    <button class="label label-primary" type="submit">
                                        <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                        make default
                                    </button>
                                </form>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>acme_account_provider_id</th>
                        <td>
                            <a
                                class="label label-info"
                                href="${admin_prefix}/acme-account-providers"
                            >
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
                        <th>account url</th>
                        <td><code>${AcmeAccountKey.account_url or ''}</code></td>
                    </tr>
                    <tr>
                        <th>terms of service</th>
                        <td><code>${AcmeAccountKey.terms_of_service or ''}</code></td>
                    </tr>
                    <tr>
                        <th>timestamp_created</th>
                        <td><timestamp>${AcmeAccountKey.timestamp_created or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>timestamp_last_certificate_request</th>
                        <td><timestamp>${AcmeAccountKey.timestamp_last_certificate_request or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>timestamp_last_certificate_issue</th>
                        <td><timestamp>${AcmeAccountKey.timestamp_last_certificate_issue or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>count_certificate_requests</th>
                        <td><span class="badge">${AcmeAccountKey.count_certificate_requests or ''}</span></td>
                    </tr>
                    <tr>
                        <th>count_certificates_issued</th>
                        <td><span class="badge">${AcmeAccountKey.count_certificates_issued or ''}</span></td>
                    </tr>
                    <tr>
                        <th>key_pem_md5</th>
                        <td><code>${AcmeAccountKey.key_pem_md5}</code></td>
                    </tr>
                    <tr>
                        <th>key_pem_modulus_md5</th>
                        <td>
                            <code>${AcmeAccountKey.key_pem_modulus_md5}</code>
                            <a
                                class="btn btn-xs btn-info"
                                href="${admin_prefix}/search?${AcmeAccountKey.key_pem_modulus_search}"
                            >
                                <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                            </a>
                        </td>
                    </tr>
                    <tr>
                        <th>key_pem</th>
                        <td>
                            ## ${'tracked' if AcmeAccountKey.key_pem else 'untracked'}
                            ## <textarea class="form-control">${AcmeAccountKey.key_pem}</textarea>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/acme-account-key/${AcmeAccountKey.id}/key.pem">key.pem</a>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/acme-account-key/${AcmeAccountKey.id}/key.pem.txt">key.pem.txt</a>
                            <a class="btn btn-xs btn-info" href="${admin_prefix}/acme-account-key/${AcmeAccountKey.id}/key.key">key.key (der)</a>
                        </td>
                    </tr>
                    ${admin_partials.table_tr_OperationsEventCreated(AcmeAccountKey)}
                </tbody>
                <thead>
                    <tr>
                        <th colspan="2">
                        <hr/>
                        </th>
                    </tr>
                    <tr>
                        <th colspan="2">
                            Relations Library
                        </th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <th>AcmeAuthorizations</th>
                        <td>
                            ${admin_partials.table_AcmeAuthorizations(AcmeAccountKey.acme_authorizations__5, perspective="AcmeAccountKey")}
                            % if AcmeAccountKey.acme_authorizations__5:
                                ${admin_partials.nav_pager("%s/acme-account-key/%s/acme-authorizations" % (admin_prefix, AcmeAccountKey.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeAuthorizations Pending</th>
                        <td>
                            ${admin_partials.table_AcmeAuthorizations(AcmeAccountKey.acme_authorizations_pending__5, perspective="AcmeAccountKey")}
                            % if AcmeAccountKey.acme_authorizations_pending__5:
                                ${admin_partials.nav_pager("%s/acme-account-key/%s/acme-authorizations?authorization-status=pending" % (admin_prefix, AcmeAccountKey.id))}
                            % endif
                        </td>
                    </tr>


                    <tr>
                        <th>AcmeOrder(s)</th>
                        <td>
                            ${admin_partials.table_AcmeOrders(AcmeAccountKey.acme_orders__5, perspective="AcmeAccountKey")}
                            % if AcmeAccountKey.acme_orders__5:
                                ${admin_partials.nav_pager("%s/acme-account-key/%s/acme-orders" % (admin_prefix, AcmeAccountKey.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>Certificate(s)</th>
                        <td>
                            ${admin_partials.table_ServerCertificates(AcmeAccountKey.server_certificates__5, show_domains=True, show_expiring_days=True)}
                            % if AcmeAccountKey.server_certificates__5:
                                ${admin_partials.nav_pager("%s/acme-account-key/%s/server-certificates" % (admin_prefix, AcmeAccountKey.id))}
                            % endif
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</%block>
