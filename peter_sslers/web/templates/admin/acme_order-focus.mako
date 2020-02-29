<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-orders">AcmeOrder</a></li>
        <li class="active">Focus [${AcmeOrder.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>ACME Order - Focus</h2>
    <p>${request.text_library.info_AcmeOrders[1]}</p>

    ${admin_partials.standard_error_display()}
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-order/${AcmeOrder.id}.json" class="btn btn-xs btn-info">
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
                            ACME Server Operations
                        </th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <th>Sync</th>
                        <td>
                            <% sync_btn_class = '' if AcmeOrder.is_can_acme_server_sync else 'disabled' %>
                            <a
                                href="${admin_prefix}/acme-order/${AcmeOrder.id}/acme-server-sync"
                                class="btn btn-xs btn-info ${sync_btn_class}"
                            >
                                <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                Sync Order Against ACME Server
                            </a>
                        
                        </td>
                    </tr>
                    <tr>
                        <th>Cleanup</th>
                        <td>
                            <p>
                                <% deactivate_btn_class = '' if AcmeOrder.is_can_acme_server_deactivate_authorizations else 'disabled' %>
                                <a
                                    href="${admin_prefix}/acme-order/${AcmeOrder.id}/acme-server-deactivate-authorizations"
                                    class="btn btn-xs btn-info ${deactivate_btn_class}"
                                >
                                    <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                    Deactivate Authorizations on ACME Server
                                </a>
                            </p>
                            <p>
                                <% finalize_btn_class = '' if AcmeOrder.is_can_finalize else 'disabled' %>
                                <a
                                    href="${admin_prefix}/acme-order/${AcmeOrder.id}/finalize"
                                    class="btn btn-xs btn-info ${finalize_btn_class}"
                                >
                                    <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                    Finalize Order
                                </a>
                            </p>
                            <p>
                                <% retry_btn_class = '' if AcmeOrder.is_can_retry else 'disabled' %>
                                <a
                                    href="${admin_prefix}/acme-order/${AcmeOrder.id}/retry"
                                    class="btn btn-xs btn-info ${retry_btn_class}"
                                >
                                    <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                    Retry (New) Order
                                </a>
                            </p>
                        </td>
                    </tr>
                </tbody>
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
                        <th>is_active</th>
                        <td>
                        
                            % if AcmeOrder.is_active is True:
                                <div class="label label-success">
                                    <span class="glyphicon glyphicon-ok" aria-hidden="true"></span>
                                </div>
                            % elif AcmeOrder.is_active is None:
                                <div class="label label-default">
                                    <span class="glyphicon glyphicon-ok-sign" aria-hidden="true"></span>
                                </div>
                            % elif AcmeOrder.is_active is False:
                                <div class="label label-warning">
                                    <span class="glyphicon glyphicon-remove-sign" aria-hidden="true"></span>
                                </div>
                            % endif
                        
                            % if AcmeOrder.is_active:
                                <a
                                    href="${admin_prefix}/acme-order/${AcmeOrder.id}/mark?operation=deactivate"
                                    class="btn btn-xs btn-danger"
                                >
                                    <span class="glyphicon glyphicon-warning-sign" aria-hidden="true"></span>
                                    Deactivate
                                </a>
                            % endif
                        </td>
                    </tr>


                    <tr>
                        <th>is_auto_renew</th>
                        <td>
                            <span class="label label-${'success' if AcmeOrder.is_auto_renew else 'warning'}">
                                ${'AutoRenew' if AcmeOrder.is_auto_renew else 'manual'}
                            </span>
                            &nbsp;
                            % if AcmeOrder.is_auto_renew:
                                <form action="${admin_prefix}/acme-order/${AcmeOrder.id}/mark" method="POST" style="display:inline;">
                                    <input type="hidden" name="operation" value="renew.manual"/>
                                    <button class="btn btn-xs btn-warning" type="submit">
                                        <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                        deactivate auto-renew
                                    </button>
                                </form>
                            % else:
                                <form action="${admin_prefix}/acme-order/${AcmeOrder.id}/mark" method="POST" style="display:inline;">
                                    <input type="hidden" name="operation" value="renew.auto"/>
                                    <button class="btn btn-xs btn-success" type="submit">
                                        <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                        enable auto-renew
                                    </button>
                                </form>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>is_renewed</th>
                        <td>
                            <span class="label label-${'success' if AcmeOrder.is_renewed else 'default'}">
                                ${'Renewed' if AcmeOrder.is_renewed else 'not-renewed-yet'}
                            </span>
                            &nbsp;

                            <% renew_btn_class = '' if AcmeOrder.is_renewable_queue else 'disabled' %>
                            <a  class="btn btn-xs btn-primary ${renew_btn_class}"
                                href="${admin_prefix}/acme-order/${AcmeOrder.id}/renew/queue"
                                title="Queue a renewal with same AcmeAccount."
                            >
                                <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                Queue a Renewal
                            </a>
                            &nbsp;

                            <% renew_btn_class = '' if AcmeOrder.is_renewable_quick else 'disabled' %>
                            <a  class="btn btn-xs btn-primary ${renew_btn_class}"
                                href="${admin_prefix}/acme-order/${AcmeOrder.id}/renew/quick"
                                title="Renew immediately with the same AcmeAccount."
                            >
                                <span class="glyphicon glyphicon-fast-forward" aria-hidden="true"></span>
                                Quick Renewal
                            </a>
                            &nbsp;

                            <% renew_btn_class = '' if AcmeOrder.is_renewable_custom else 'disabled' %>
                            <a  class="btn btn-xs btn-primary ${renew_btn_class}"
                                href="${admin_prefix}/acme-order/${AcmeOrder.id}/renew/custom"
                                title="Select a new AccountKey for renewal."
                            >
                                <span class="glyphicon glyphicon-wrench" aria-hidden="true"></span>
                                Custom Renewal
                            </a>
                        </td>
                    </tr>
                


                    <tr>
                        <th>status</th>
                        <td><code>${AcmeOrder.acme_status_order or ''}</code>
                            % if AcmeOrder.is_can_mark_invalid:
                                <a
                                    href="${admin_prefix}/acme-order/${AcmeOrder.id}/mark?operation=invalid"
                                    class="btn btn-xs btn-danger"
                                >
                                    <span class="glyphicon glyphicon-warning-sign" aria-hidden="true"></span>
                                    Mark 'invalid'
                                </a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>order_url</th>
                        <td><code>${AcmeOrder.order_url or ''}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>timestamp_expires</th>
                        <td><timestamp>${AcmeOrder.timestamp_expires or ''}</timestamp>
                        </td>
                    </tr>
                    <tr>
                        <th>timestamp_updated</th>
                        <td><timestamp>${AcmeOrder.timestamp_updated or ''}</timestamp>
                        </td>
                    </tr>
                    <tr>
                        <th>finalize_url</th>
                        <td><code>${AcmeOrder.finalize_url or ''}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>acme_account_key_id</th>
                        <td>
                            <a
                                class="label label-info"
                                href="${admin_prefix}/acme-account-key/${AcmeOrder.acme_account_key_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeAccountKey-${AcmeOrder.acme_account_key_id}
                            </a>
                        </td>
                    </tr>
                    <tr>
                        <th>certificate_request_id</th>
                        <td>
                            % if AcmeOrder.certificate_request_id:
                                <a
                                    class="label label-info"
                                    href="${admin_prefix}/certificate-request/${AcmeOrder.certificate_request_id}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    CertificateRequest-${AcmeOrder.certificate_request_id}
                                </a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>private_key_id</th>
                        <td>
                            % if AcmeOrder.private_key_id is not None:
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
                        <th>server_certificate_id</th>
                        <td>
                            % if AcmeOrder.server_certificate_id:
                                <a
                                    class="label label-info"
                                    href="${admin_prefix}/server-certificate/${AcmeOrder.server_certificate_id}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    Certificate-${AcmeOrder.server_certificate_id}
                                </a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>unique_fqdn_set_id</th>
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
                        <th><hr/></th>
                        <th><hr/></th>
                    </tr>

                    <tr>
                        <th>acme_order_id__retry_of</th>
                        <td>
                            % if AcmeOrder.acme_order_id__retry_of:
                                <a
                                    class="label label-info"
                                    href="${admin_prefix}/acme-order/${AcmeOrder.acme_order_id__retry_of}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeOrder-${AcmeOrder.acme_order_id__retry_of}
                                </a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>acme_order_id__renewal_of</th>
                        <td>
                            % if AcmeOrder.acme_order_id__renewal_of:
                                <a
                                    class="label label-info"
                                    href="${admin_prefix}/acme-order/${AcmeOrder.acme_order_id__renewal_of}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeOrder-${AcmeOrder.acme_order_id__renewal_of}
                                </a>
                            % endif
                        </td>
                    </tr>
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
                        <th>ACME Authorizations</th>
                        <td>
                            ${admin_partials.table_AcmeAuthorizations(AcmeOrder, perspective='AcmeOrder.to_acme_authorizations')}
                        </td>
                    </tr>
                    
                    <tr>
                        <th>ACME Events</th>
                        <td>
                            % if AcmeOrder.acme_event_logs__5:
                                ${admin_partials.table_AcmeEventLogs(AcmeOrder.acme_event_logs__5, perspective='AcmeOrder')}
                                ${admin_partials.nav_pager("%s/acme-order/%s/acme-event-logs" % (admin_prefix, AcmeOrder.id))}
                            % endif
                        </td>
                    </tr>
                    
                    
                </tbody>
        </div>
    </div>
</%block>
