<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-orders/all">AcmeOrders</a></li>
        <li><a href="${admin_prefix}/acme-order/${AcmeOrder.id}">Focus [${AcmeOrder.id}]</a></li>
        <li class="active">Audit</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>ACME Order - Focus - Audit</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-order/${AcmeOrder.id}/audit.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <table class="table table-striped table-condensed">
                <tbody>
                    <tr>
                        <th>id</th>
                        <td>
                            <span class="label label-default">
                                ${AcmeOrder.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>timestamp_created</th>
                        <td><timestamp>${AcmeOrder.timestamp_created or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>Order Type</th>
                        <td><span class="label label-default">${AcmeOrder.acme_order_type}</span></td>
                    </tr>

                    <tr>
                        <th>Processing Strategy</th>
                        <td><span class="label label-default">${AcmeOrder.acme_order_processing_strategy}</span></td>
                    </tr>
                    <tr>
                        <th>Processing Status</th>
                        <td><span class="label label-default">${AcmeOrder.acme_order_processing_status}</span></td>
                    </tr>
                    <tr>
                        <th>is_processing</th>
                        <td>                        
                            % if AcmeOrder.is_processing is True:
                                <div class="label label-success">
                                    <span class="glyphicon glyphicon-ok" aria-hidden="true"></span>
                                </div>
                            % elif AcmeOrder.is_processing is None:
                                <div class="label label-default">
                                    <span class="glyphicon glyphicon-ok-sign" aria-hidden="true"></span>
                                </div>
                            % elif AcmeOrder.is_processing is False:
                                <div class="label label-warning">
                                    <span class="glyphicon glyphicon-remove-sign" aria-hidden="true"></span>
                                </div>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>status</th>
                        <td><code>${AcmeOrder.acme_status_order or ''}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>timestamp_expires</th>
                        <td><timestamp>${AcmeOrder.timestamp_expires or ''}</timestamp>
                        </td>
                    </tr>
                    <tr>
                        <th>is_save_alternate_chains</th>
                        <td><code>${AcmeOrder.is_save_alternate_chains or ''}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>RenewalConfiguration</th>
                        <td>
                            <a
                                class="label label-info"
                                href="${admin_prefix}/renewal-configuration/${AcmeOrder.renewal_configuration_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                RenewalConfiguration-${AcmeOrder.renewal_configuration_id}
                            </a>
                            <table class="table table-striped table-condensed">
                                <tr>
                                    <th>PrivateKey Cycling [Primary]</th>
                                    <td>${AcmeOrder.renewal_configuration.private_key_cycle__primary or ""}</td>
                                </tr>
                                <tr>
                                    <th>PrivateKey Technology [Primary]</th>
                                    <td>${AcmeOrder.renewal_configuration.private_key_technology__primary or ""}</td>
                                </tr>
                                <tr>
                                    <th>Acme Profile [Primary]</th>
                                    <td>${AcmeOrder.renewal_configuration.acme_profile__primary or ""}</td>
                                </tr>
                                <tr>
                                    <th>AcmeAccount [Primary]</th>
                                    <td>
                                        <a
                                            class="label label-info"
                                            href="${admin_prefix}/acme-account/${AcmeOrder.renewal_configuration.acme_account_id__primary}"
                                        >
                                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                            AcmeAccount-${AcmeOrder.renewal_configuration.acme_account_id__primary}
                                        </a>
                                        <table class="table table-striped table-condensed">
                                            <tr>
                                                <th>AcmeServer</th>
                                                <td>
                                                    <a
                                                        class="label label-info"
                                                        href="${admin_prefix}/acme-servers"
                                                    >
                                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                        AcmeServer-${AcmeOrder.renewal_configuration.acme_account__primary.acme_server_id}
                                                        [${AcmeOrder.renewal_configuration.acme_account__primary.acme_server.name}]
                                                        (${AcmeOrder.renewal_configuration.acme_account__primary.acme_server.url})
                                                    </a>
                                                </td>
                                            </tr>
                                            <tr>
                                                <th>contact</th>
                                                <td>${AcmeOrder.renewal_configuration.acme_account__primary.contact or ""}</td>
                                            </tr>
                                            <tr>
                                                <th>Default PrivateKey Cycling</th>
                                                <td>${AcmeOrder.renewal_configuration.acme_account__primary.order_default_private_key_cycle or ""}</td>
                                            </tr>
                                            <tr>
                                                <th>Default PrivateKey Technology</th>
                                                <td>${AcmeOrder.renewal_configuration.acme_account__primary.order_default_private_key_technology or ""}</td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>                                
                                <tr>
                                    <th>PrivateKey Cycling [Backup]</th>
                                    <td>${AcmeOrder.renewal_configuration.private_key_cycle__backup or ""}</td>
                                </tr>
                                <tr>
                                    <th>PrivateKey Technology [Backup]</th>
                                    <td>${AcmeOrder.renewal_configuration.private_key_technology__backup or ""}</td>
                                </tr>
                                <tr>
                                    <th>Acme Profile [Backup]</th>
                                    <td>${AcmeOrder.renewal_configuration.acme_profile__backup or ""}</td>
                                </tr>
                                <tr>
                                    <th>AcmeAccount [Backup]</th>
                                    <td>
                                        % if AcmeOrder.renewal_configuration.acme_account_id__backup:
                                            <a
                                                class="label label-info"
                                                href="${admin_prefix}/acme-account/${AcmeOrder.renewal_configuration.acme_account_id__backup}"
                                            >
                                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                AcmeAccount-${AcmeOrder.renewal_configuration.acme_account_id__backup}
                                            </a>
                                            <table class="table table-striped table-condensed">
                                                <tr>
                                                    <th>AcmeServer</th>
                                                    <td>
                                                        <a
                                                            class="label label-info"
                                                            href="${admin_prefix}/acme-servers"
                                                        >
                                                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                            AcmeServer-${AcmeOrder.renewal_configuration.acme_account__backup.acme_server_id}
                                                            [${AcmeOrder.renewal_configuration.acme_account__backup.acme_server.name}]
                                                            (${AcmeOrder.renewal_configuration.acme_account__backup.acme_server.url})
                                                        </a>
                                                    </td>
                                                </tr>
                                                <tr>
                                                    <th>contact</th>
                                                    <td>${AcmeOrder.renewal_configuration.acme_account__backup.contact or ""}</td>
                                                </tr>
                                                <tr>
                                                    <th>Default PrivateKey Cycling</th>
                                                    <td>${AcmeOrder.renewal_configuration.acme_account__backup.order_default_private_key_cycle or ""}</td>
                                                </tr>
                                                <tr>
                                                    <th>Default PrivateKey Technology</th>
                                                    <td>${AcmeOrder.renewal_configuration.acme_account__backup.order_default_private_key_technology or ""}</td>
                                                </tr>
                                            </table>
                                        % endif
                                    </td>
                                </tr>         
                            </table>
                        </td>
                    </tr>

                    <tr>
                        <th>PrivateKey</th>
                        <td>
                            % if AcmeOrder.private_key_id == 0:
                                <span class="label label-default">placeholder key</span>
                            % else:
                                <a
                                    class="label label-info"
                                    href="${admin_prefix}/private-key/${AcmeOrder.private_key_id}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    PrivateKey-${AcmeOrder.private_key_id}
                                </a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>PrivateKeyStrategy - requested</th>
                        <td><code>${AcmeOrder.private_key_strategy__requested}</code></td>
                    </tr>
                    <tr>
                        <th>PrivateKeyStrategy - final</th>
                        <td><code>${AcmeOrder.private_key_strategy__final}</code></td>
                    </tr>
                    <tr>
                        <th>UniqueFQDNSet</th>
                        <td>
                            <a
                                class="label label-info"
                                href="${admin_prefix}/unique-fqdn-set/${AcmeOrder.unique_fqdn_set_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                UniqueFQDNSet-${AcmeOrder.unique_fqdn_set_id}
                            </a>
                            <br/>
                            <code>${', '.join(AcmeOrder.domains_as_list)}</code>
                        </td>
                    </tr>

                    <tr>
                        <th>ACME Authorizations/Challenges</th>
                        <td>
                            ${admin_partials.table_AcmeAuthorizationChallenges(AcmeOrder, perspective='AcmeOrder')}
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</%block>
