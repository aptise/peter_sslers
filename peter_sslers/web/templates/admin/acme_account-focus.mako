<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-accounts">AcmeAccounts</a></li>
        <li class="active">Focus [${AcmeAccount.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>AcmeAccounts - Focus</h2>
    <p>${request.text_library.info_AcmeAccounts[1]}</p>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-account/${AcmeAccount.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
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
                                ${AcmeAccount.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>timestamp_last_authenticated</th>
                        <td><timestamp>${AcmeAccount.timestamp_last_authenticated or ''}</timestamp>
                            % if AcmeAccount.is_can_authenticate:
                                <form action="${admin_prefix}/acme-account/${AcmeAccount.id}/acme-server/authenticate" method="POST">
                                    <button class="btn btn-xs btn-primary" type="submit"  name="submit" value="submit">
                                        <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                        Authenticate Against ACME Server
                                    </button>
                                </form>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>active?</th>
                        <td>
                            <span class="label label-${'success' if AcmeAccount.is_active else 'warning'}">
                                ${'active' if AcmeAccount.is_active else 'inactive'}
                            </span>
                            &nbsp;
                            % if not AcmeAccount.is_active:
                                <form action="${admin_prefix}/acme-account/${AcmeAccount.id}/mark" method="POST" style="display:inline;">
                                    <input type="hidden" name="action" value="active"/>
                                    <button class="btn btn-xs btn-info" type="submit">
                                        <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                        active
                                    </button>
                                </form>
                            % else:
                                % if not AcmeAccount.is_global_default:
                                    <form action="${admin_prefix}/acme-account/${AcmeAccount.id}/mark" method="POST" style="display:inline;">
                                        <input type="hidden" name="action" value="inactive"/>
                                        <button class="btn btn-xs btn-danger" type="submit">
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
                        <th>Global Default</th>
                        <td>
                            % if AcmeAccount.is_global_default:
                                <span class="label label-success">Global Default</span>
                            % else:
                                <span class="label label-default"></span>
                            % endif
                            &nbsp;
                            % if AcmeAccount.is_global_default_candidate:
                                <form action="${admin_prefix}/acme-account/${AcmeAccount.id}/mark" method="POST" style="display:inline;">
                                    <input type="hidden" name="action" value="global_default"/>
                                    <button class="btn btn-xs btn-primary" type="submit">
                                        <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                        Set Global Default
                                    </button>
                                </form>
                            % endif
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
                        <th>account url</th>
                        <td><code>${AcmeAccount.account_url or ''}</code></td>
                    </tr>
                    <tr>
                        <th>terms of service</th>
                        <td><code>${AcmeAccount.terms_of_service or ''}</code></td>
                    </tr>
                    <tr>
                        <th>timestamp_created</th>
                        <td><timestamp>${AcmeAccount.timestamp_created or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>timestamp_last_certificate_request</th>
                        <td><timestamp>${AcmeAccount.timestamp_last_certificate_request or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>timestamp_last_certificate_issue</th>
                        <td><timestamp>${AcmeAccount.timestamp_last_certificate_issue or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>count_certificate_requests</th>
                        <td><span class="badge">${AcmeAccount.count_certificate_requests or ''}</span></td>
                    </tr>
                    <tr>
                        <th>count_certificates_issued</th>
                        <td><span class="badge">${AcmeAccount.count_certificates_issued or ''}</span></td>
                    </tr>
                    <tr>
                        <th>AcmeAccountKey</th>
                        <td>
                            <table class="table table-striped table-condensed">
                                <tr>
                                    <th>AcmeAccountKey</th>
                                    <td>
                                        <span class="label label-default"
                                        >
                                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                            AcmeAccountKey-${AcmeAccount.acme_account_key.id}
                                        </span>
                                    </td>
                                </tr>
                                <tr>
                                    <th>key_pem_md5</th>
                                    <td><code>${AcmeAccount.acme_account_key.key_pem_md5}</code></td>
                                </tr>
                                <tr>
                                    <th>key_pem_modulus_md5</th>
                                    <td>
                                        <code>${AcmeAccount.acme_account_key.key_pem_modulus_md5}</code>
                                        <a
                                            class="btn btn-xs btn-info"
                                            href="${admin_prefix}/search?${AcmeAccount.acme_account_key.key_pem_modulus_search}"
                                        >
                                            <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                                        </a>
                                    </td>
                                </tr>
                                <tr>
                                    <th>key_pem</th>
                                    <td>
                                        ## ${'tracked' if AcmeAccount.acme_account_key.key_pem else 'untracked'}
                                        ## <textarea class="form-control">${AcmeAccount.acme_account_key.key_pem}</textarea>
                                        <a class="btn btn-xs btn-info" href="${admin_prefix}/acme-account/${AcmeAccount.id}/key.pem">key.pem</a>
                                        <a class="btn btn-xs btn-info" href="${admin_prefix}/acme-account/${AcmeAccount.id}/key.pem.txt">key.pem.txt</a>
                                        <a class="btn btn-xs btn-info" href="${admin_prefix}/acme-account/${AcmeAccount.id}/key.key">key.key (der)</a>
                                    </td>
                                </tr>                        
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <th>PrivateKey cycle</th>
                        <td>
                            <code>${AcmeAccount.private_key_cycle}</code>
                            <a  href="${admin_prefix}/acme-account/${AcmeAccount.id}/edit"
                                class="btn btn-xs btn-info"
                            >
                                <span class="glyphicon glyphicon-pencil" aria-hidden="true"></span>
                                Edit
                            </a>                        
                        </td>
                    </tr>
                    ${admin_partials.table_tr_OperationsEventCreated(AcmeAccount)}
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
                            ${admin_partials.table_AcmeAuthorizations(AcmeAccount.acme_authorizations__5, perspective="AcmeAccount")}
                            % if AcmeAccount.acme_authorizations__5:
                                ${admin_partials.nav_pager("%s/acme-account/%s/acme-authorizations" % (admin_prefix, AcmeAccount.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeAuthorizations Pending</th>
                        <td>
                            ${admin_partials.table_AcmeAuthorizations(AcmeAccount.acme_authorizations_pending__5, perspective="AcmeAccount")}
                            % if AcmeAccount.acme_authorizations_pending__5:
                                ${admin_partials.nav_pager("%s/acme-account/%s/acme-authorizations?status=active" % (admin_prefix, AcmeAccount.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>ServerCertificate(s)</th>
                        <td>
                            ${admin_partials.table_ServerCertificates(AcmeAccount.server_certificates__5, show_domains=True, show_expiring_days=True)}
                            % if AcmeAccount.server_certificates__5:
                                ${admin_partials.nav_pager("%s/acme-account/%s/server-certificates" % (admin_prefix, AcmeAccount.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>QueueCertificate(s)</th>
                        <td>
                            ${admin_partials.table_QueueCertificates(AcmeAccount.queue_certificates__5, perspective="AcmeAccount")}
                            % if AcmeAccount.queue_certificates__5:
                                ${admin_partials.nav_pager("%s/acme-account/%s/queue-certificates" % (admin_prefix, AcmeAccount.id))}
                            % endif
                        </td>
                    </tr>


                    <tr>
                        <th>AcmeOrder(s)</th>
                        <td>
                            ${admin_partials.table_AcmeOrders(AcmeAccount.acme_orders__5, perspective="AcmeAccount")}
                            % if AcmeAccount.acme_orders__5:
                                ${admin_partials.nav_pager("%s/acme-account/%s/acme-orders" % (admin_prefix, AcmeAccount.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeOrderless(s)</th>
                        <td>
                            ${admin_partials.table_AcmeOrderlesss(AcmeAccount.acme_orderlesss__5, perspective="AcmeAccount")}
                        </td>
                    </tr>


                    <tr>
                        <th>PrivateKey(s) Owned</th>
                        <td>
                            ${admin_partials.table_PrivateKeys(AcmeAccount.private_keys__owned__5, perspective="AcmeAccount")}
                            % if AcmeAccount.private_keys__owned__5:
                                ${admin_partials.nav_pager("%s/acme-account/%s/private-keys" % (admin_prefix, AcmeAccount.id))}
                            % endif
                        </td>
                    </tr>

                </tbody>
            </table>
        </div>
    </div>
</%block>
