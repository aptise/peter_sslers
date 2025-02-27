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
    ${admin_partials.handle_querystring_result()}

    <div class="row">
        <div class="col-sm-12">
            <table class="table table-striped table-condensed">
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
                            % if AcmeAccount.name:
                                &nbsp;
                                <span class="label label-default">
                                    ${AcmeAccount.name}
                                </span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>timestamp_last_authenticated</th>
                        <td><timestamp>${AcmeAccount.timestamp_last_authenticated or ''}</timestamp>
                            ## is_can_authenticate only ensures an acme-v2 endpoint
                            % if AcmeAccount.is_can_authenticate:
                                <form action="${admin_prefix}/acme-account/${AcmeAccount.id}/acme-server/authenticate" method="POST">
                                    <button class="btn btn-xs btn-primary" type="submit"  name="submit" value="submit">
                                        <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                        Authenticate Against ACME Server
                                    </button>
                                </form>
                                <form action="${admin_prefix}/acme-account/${AcmeAccount.id}/acme-server/check" method="POST">
                                    <button class="btn btn-xs btn-primary" type="submit"  name="submit" value="submit">
                                        <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                        Check Against ACME Server
                                    </button>
                                </form>
                                <em>`Authenticate` will register the account if it does not already exist on the server. 
                                    `Check` will not register a new account if it does not already exist.
                                    </em>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>active?</th>
                        <td>
                            % if AcmeAccount.timestamp_deactivated:
                                <span class="label label-warning">deactivated</span>
                            % else:
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
                                    % if not AcmeAccount.is_can_unset_active:
                                        <form action="${admin_prefix}/acme-account/${AcmeAccount.id}/mark" method="POST" style="display:inline;">
                                            <input type="hidden" name="action" value="inactive"/>
                                            <button class="btn btn-xs btn-danger" type="submit">
                                                <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                                inactive
                                            </button>
                                        </form>
                                    % endif
                                % endif
                            % endif
                            % if AcmeAccount.is_can_deactivate:
                                &nbsp;
                                <a class="btn btn-xs btn-danger" href="${admin_prefix}/acme-account/${AcmeAccount.id}/acme-server/deactivate">
                                    <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                    Deactivate on ACME Server
                                </a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>Enrollment Policies</th>
                        <td>
                            % if AcmeAccount.enrollment_policies__primary:
                                <b>Configured as Primary</b>
                                <ul>
                                    % for ep in AcmeAccount.enrollment_policies__primary:
                                        <li>
                                            <a class="btn btn-xs btn-info" href="${admin_prefix}/enrollment-policy/${ep.slug}">
                                                <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                                                EnrollmentPolicy-${ep.name}
                                            </a>
                                        </li>
                                    % endfor
                                </ul>
                            % endif
                            % if AcmeAccount.enrollment_policies__backup:
                                <b>Configured as Backup</b>
                                <ul>
                                    % for ep in AcmeAccount.enrollment_policies__backup:
                                        <li>
                                            <a class="btn btn-xs btn-info" href="${admin_prefix}/enrollment-policy/${ep.slug}">
                                                <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                                                EnrollmentPolicy-${ep.name}
                                            </a>
                                        </li>
                                    % endfor
                                </ul>
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
                        <th>AcmeServer</th>
                        <td>
                            <a
                                class="label label-info"
                                href="${admin_prefix}/acme-server/${AcmeAccount.acme_server_id}"
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
                        <th>account url</th>
                        <td><code>${AcmeAccount.account_url or ''}</code></td>
                    </tr>
                    <tr>
                        <th>terms of service</th>
                        <td>
                            <code>${AcmeAccount.terms_of_service or ''}</code>

                            <a
                                class="btn btn-xs btn-info"
                                href="${admin_prefix}/acme-account/${AcmeAccount.id}/terms-of-service"
                            >
                                <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                            </a>

                        </td>
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
                        <th>count_acme_orders</th>
                        <td><span class="badge">${AcmeAccount.count_acme_orders or ''}</span></td>
                    </tr>
                    <tr>
                        <th>count_certificate_signeds</th>
                        <td><span class="badge">${AcmeAccount.count_certificate_signeds or ''}</span></td>
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
                                    <th>key_technology</th>
                                    <td><span class="label label-default">${AcmeAccount.acme_account_key.key_technology}</span></td>
                                </tr>
                                <tr>
                                    <th>key_pem_md5</th>
                                    <td><code>${AcmeAccount.acme_account_key.key_pem_md5}</code></td>
                                </tr>
                                <tr>
                                    <th>spki_sha256</th>
                                    <td>
                                        <code>${AcmeAccount.acme_account_key.spki_sha256}</code>
                                        <a
                                            class="btn btn-xs btn-info"
                                            href="${admin_prefix}/search?${AcmeAccount.acme_account_key.key_spki_search}"
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
                                <tr>
                                    <th>Key Change</th>
                                    <td>
                                        % if AcmeAccount.is_can_key_change:
                                            <a class="btn btn-xs btn-warning" href="${admin_prefix}/acme-account/${AcmeAccount.id}/acme-server/key-change">
                                                <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                                KeyChange on ACME Server
                                            </a>
                                            <p>This will use the Account default of <code>${AcmeAccount.private_key_technology}</code></p>
                                        % endif
                                        <hr/>
                                        <a href="${admin_prefix}/acme-account/${AcmeAccount.id}/acme-account-keys" class="label label-info">
                                            <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                                            Historical AcmeAccountKeys
                                        </a>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <th>PrivateKey Technology</th>
                        <td>
                            <code>${AcmeAccount.private_key_technology}</code>
                            <a  href="${admin_prefix}/acme-account/${AcmeAccount.id}/edit"
                                class="btn btn-xs btn-info"
                            >
                                <span class="glyphicon glyphicon-pencil" aria-hidden="true"></span>
                                Edit
                            </a>
                            <em>key rollovers will use this technology setting.</em>      
                        </td>
                    </tr>
                    <tr><td colspan="2">Order Defautls<hr/></td></tr>
                    <tr>
                        <th>Order Defaults: PrivateKey Cycle</th>
                        <td>
                            <code>${AcmeAccount.order_default_private_key_cycle}</code>
                            <a  href="${admin_prefix}/acme-account/${AcmeAccount.id}/edit"
                                class="btn btn-xs btn-info"
                            >
                                <span class="glyphicon glyphicon-pencil" aria-hidden="true"></span>
                                Edit
                            </a>                        
                        </td>
                    </tr>
                    <tr>
                        <th>Order Defaults: PrivateKey Technology</th>
                        <td>
                            <code>${AcmeAccount.order_default_private_key_technology}</code>
                            <a  href="${admin_prefix}/acme-account/${AcmeAccount.id}/edit"
                                class="btn btn-xs btn-info"
                            >
                                <span class="glyphicon glyphicon-pencil" aria-hidden="true"></span>
                                Edit
                            </a>                        
                        </td>
                    </tr>
                    <tr>
                        <th>Order Defaults: Acme Profile</th>
                        <td>
                            <code>${AcmeAccount.order_default_acme_profile or ""}</code>
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
                        <th>CertificateSigned(s)</th>
                        <td>
                            ${admin_partials.table_CertificateSigneds(AcmeAccount.certificate_signeds__5, show_domains=True, show_expiring_days=True)}
                            % if AcmeAccount.certificate_signeds__5:
                                ${admin_partials.nav_pager("%s/acme-account/%s/certificate-signeds" % (admin_prefix, AcmeAccount.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>RenewalConfigurations(s) - Primary</th>
                        <td>
                            ${admin_partials.table_RenewalConfigurations(AcmeAccount.renewal_configurations__primary__5, perspective="AcmeAccount")}
                            % if AcmeAccount.renewal_configurations__primary__5:
                                ${admin_partials.nav_pager("%s/acme-account/%s/renewal-configurations" % (admin_prefix, AcmeAccount.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>RenewalConfigurations(s) - Backup</th>
                        <td>
                            ${admin_partials.table_RenewalConfigurations(AcmeAccount.renewal_configurations__backup__5, perspective="AcmeAccount")}
                            % if AcmeAccount.renewal_configurations__backup__5:
                                ${admin_partials.nav_pager("%s/acme-account/%s/renewal-configurations-backup" % (admin_prefix, AcmeAccount.id))}
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
