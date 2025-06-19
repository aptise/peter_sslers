<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-orders/all">AcmeOrders</a></li>
        <li class="active">Focus [${AcmeOrder.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>ACME Order - Focus</h2>
    <p>An ACME order is essentially a "Certificate Signing Request".</p>
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
            <table class="table table-striped table-condensed">
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
                            <table class="table table-condensed table-striped">
                                <tr>
                                    <td>
                                        <% _btn_class = '' if AcmeOrder.is_can_acme_server_sync else 'disabled' %>
                                        <form method="POST"
                                            action="${admin_prefix}/acme-order/${AcmeOrder.id}/acme-server/sync"
                                            id="form-acme_server-sync"
                                        >
                                            <button class="btn btn-xs btn-primary ${_btn_class}" id="btn-sync">
                                                <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                                Sync Order Against ACME Server
                                            </button>
                                        </form>
                                    </td>
                                    <td>
                                        Interrogates the ACME Server
                                    </td>
                                </tr>
                                <tr>
                                    <td>
                                        <% _btn_class = '' if AcmeOrder.is_can_acme_server_sync else 'disabled' %>
                                        <form method="POST"
                                            action="${admin_prefix}/acme-order/${AcmeOrder.id}/acme-server/sync-authorizations"
                                            id="form-acme_server-sync_authorizations"
                                        >
                                            <button class="btn btn-xs btn-primary ${_btn_class}" id="btn-sync_authorizations">
                                                <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                                Sync Authorizations Against ACME Server
                                            </button>
                                        </form>
                                    </td>
                                    <td>
                                        Loops pending/potentially pending authoriations to sync
                                    </td>
                                </tr>
                                <tr>
                                    <td>
                                        % if AcmeOrder.is_can_acme_process:
                                            <form method="POST"
                                                action="${admin_prefix}/acme-order/${AcmeOrder.id}/acme-process"
                                                id="form-acme_process"
                                            >
                                                <button class="btn btn-xs btn-primary" id="btn-acme_process">
                                                    <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                                    Process on AcmeServer
                                                </button>
                                            </form>
                                        % else:
                                            <button class="btn btn-xs btn-primary disabled" id="btn-acme_process">
                                                <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                                Process on AcmeServer
                                            </button>
                                        % endif
                                    </td>
                                    <td>
                                        Starts processing
                                        <%
                                            process_data = AcmeOrder.acme_process_steps
                                        %>
                                        % if AcmeOrder.is_can_acme_process:
                                            <ul class="list list-unstyled">
                                                <li>
                                                    Authorizations Remaining?
                                                    <span
                                                        class="label label-default" 
                                                        data-process-authorizations_remaining="${process_data['authorizations_remaining']}"
                                                    >${process_data["authorizations_remaining"]}</span>
                                                </li>
                                                <li>
                                                    Potential Finalize?
                                                    <span
                                                        class="label label-default" 
                                                        data-process-finalize="${process_data['finalize']}"
                                                    >${process_data["finalize"]}</span>
                                                </li>
                                                <li>
                                                    Potential Download?
                                                    <span
                                                        class="label label-default" 
                                                        data-process-download="${process_data['download']}"
                                                    >${process_data["download"]}</span>
                                                </li>
                                                <li>
                                                    Next Step
                                                    <span
                                                        class="label label-default" 
                                                        data-process-next_step="${process_data['next_step']}"
                                                    >${process_data["next_step"]}</span>
                                                </li>
                                            </ul>
                                        % endif
                                    </td>
                                </tr>
                            </table>
                        <td>
                    </tr>
                    <tr>
                        <th>Cleanup</th>
                        <td>
                            <table class="table table-condensed table-striped">
                                <tr>
                                    <td>
                                        <% _btn_class = '' if AcmeOrder.is_can_acme_server_deactivate_authorizations else 'disabled' %>
                                        <form method="POST"
                                            action="${admin_prefix}/acme-order/${AcmeOrder.id}/acme-server/deactivate-authorizations"
                                            id="form-acme_server-deactivate_authorizations"
                                        >
                                            <button class="btn btn-xs btn-danger ${_btn_class}" id="btn-deactivate_authorizations">
                                                <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                                Deactivate Authorizations
                                            </button>
                                        </form>
                                    </td>
                                    <td>
                                        Loops pending/potentially pending Activations and deactivates them on the ACME Server
                                    </td>
                                </tr>
                                <tr>
                                    <td>
                                        % if AcmeOrder.is_can_acme_finalize:
                                            <form method="POST"
                                                action="${admin_prefix}/acme-order/${AcmeOrder.id}/acme-finalize"
                                                id="form-acme_finalize"
                                            >
                                                <button class="btn btn-xs btn-primary" id="btn-acme_finalize">
                                                    <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                                    Finalize Order
                                                </button>
                                            </form>
                                        % else:
                                            <button class="btn btn-xs btn-primary disabled" id="btn-acme_finalize">
                                                <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                                Finalize Order
                                            </button>
                                        % endif
                                    </td>
                                    <td>
                                        Only available if the order is "ready" to be finalized.
                                    </td>
                                </tr>
                                <tr>
                                    <td>
                                        % if AcmeOrder.is_can_retry:
                                            <form action="${admin_prefix}/acme-order/${AcmeOrder.id}/retry" method="POST" style="display:inline;" id="acme_order-retry">
                                                <button class="btn btn-xs btn-primary" type="submit" name="submit" value="submit">
                                                    <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                                    Retry (New) Order
                                                </button>
                                            </form>
                                        % else:
                                            <a
                                                href="#"
                                                class="btn btn-xs btn-primary disabled"
                                            >
                                                <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                                Retry (New) Order
                                            </a>
                                        % endif
                                    </td>
                                    <td>
                                        Only available if the order has recently failed.
                                    </td>
                                </tr>
                                <tr>
                                    <td>
                                        % if AcmeOrder.is_can_acme_server_download_certificate:
                                            <form action="${admin_prefix}/acme-order/${AcmeOrder.id}/acme-server/download-certificate" method="POST" style="display:inline;" id="acme_order-download_certificate">
                                                <button class="btn btn-xs btn-primary" type="submit" name="submit" value="submit">
                                                    <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                                    ACME Server - (re)Download Certificate
                                                </button>
                                            </form>
                                        % endif
                                    </td>
                                    <td>
                                        If the certificate is missing, re-download it
                                    </td>
                                </tr>
                            </table>
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
                            &nbsp;
                            |
                            &nbsp;
                            <a
                                href="${admin_prefix}/acme-order/${AcmeOrder.id}/audit"
                                class="label label-info"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                Audit Report
                            </a>
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
                                    Processing
                                </div>
                            % elif AcmeOrder.is_processing is None:
                                <div class="label label-default">
                                    <span class="glyphicon glyphicon-remove-sign" aria-hidden="true"></span>
                                    Not Processing, Order Failure
                                </div>
                            % elif AcmeOrder.is_processing is False:
                                <div class="label label-warning">
                                    <span class="glyphicon glyphicon-remove-sign" aria-hidden="true"></span>
                                    Not Processing, Manual Failure
                                </div>
                            % endif
                            % if AcmeOrder.is_processing:
                                <form method="POST"
                                    action="${admin_prefix}/acme-order/${AcmeOrder.id}/mark"
                                    id="form-deactivate_order"
                                >
                                    <input type="hidden" name="action" value="deactivate" />
                                    <button class="btn btn-xs btn-danger" id="btn-deactivate_order">
                                        <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                        Deactivate
                                    </button>
                                </form>
                            % endif
                        </td>
                    </tr>                    
                    <tr>
                        <th>status</th>
                        <td><code>${AcmeOrder.acme_status_order or ''}</code>
                            % if AcmeOrder.is_can_mark_invalid:
                                <form
                                    action="${admin_prefix}/acme-order/${AcmeOrder.id}/mark"
                                    method="POST"
                                    id="form-acme_order-mark_invalid"
                                >
                                    <input type="hidden" name="action" value="invalid"/>
                                    <button
                                        class="btn btn-xs btn-danger"
                                    >
                                        <span class="glyphicon glyphicon-warning-sign" aria-hidden="true"></span>
                                        Mark 'invalid'
                                    </a>
                                </form>
                            % endif
                        </td>
                    </tr>                    
                    <tr>
                        <th>Renewals</th>
                        <td>
                            <% quick_btn_class = '' if AcmeOrder.is_renewable_quick else 'disabled' %>
                            <%
                                _replaces = ""
                                if AcmeOrder.certificate_signed and not AcmeOrder.certificate_signed.ari_identifier__replaced_by:
                                    _replaces = "?replaces.id=%s" % AcmeOrder.certificate_signed_id
                                else:
                                    if AcmeOrder.certificate_type_id == model_websafe.CertificateType.MANAGED_PRIMARY:
                                        _replaces = "?replaces.id=primary"
                                    elif AcmeOrder.certificate_type_id == model_websafe.CertificateType.MANAGED_BACKUP:
                                        _replaces = "?replaces.id=backup"
                            %>
                            <a  class="btn btn-xs btn-primary ${quick_btn_class}"
                                href="${admin_prefix}/renewal-configuration/${AcmeOrder.renewal_configuration_id}/new-order${_replaces}"
                                title="Quick Renewal"
                            >
                                <span class="glyphicon glyphicon-fast-forward" aria-hidden="true"></span>
                                Renew Order
                            </a>
                            &nbsp;

                            <% custom_btn_class = '' if AcmeOrder.is_renewable_custom else 'disabled' %>
                            <a  class="btn btn-xs btn-primary ${custom_btn_class}"
                                href="${admin_prefix}/renewal-configuration/${AcmeOrder.renewal_configuration_id}/new-configuration"
                                title="New Renewal Configuration"
                            >
                                <span class="glyphicon glyphicon-wrench" aria-hidden="true"></span>
                                New Renewal Configuration
                            </a>
                        </td>
                    </tr>
                </tbody>
                <thead>
                    <tr>
                        <th colspan="2">
                            Order Object
                        </th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <th>profile</th>
                        <td>
                            % if AcmeOrder.profile:
                                <code>${AcmeOrder.profile or ''}</code>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>order_url</th>
                        <td><code>${AcmeOrder.order_url or ''}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>finalize_url</th>
                        <td><code>${AcmeOrder.finalize_url or ''}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>certificate_url</th>
                        <td><code>${AcmeOrder.certificate_url or ''}</code>
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
                </tbody>
                <thead>
                    <tr>
                        <th colspan="2">
                            Order Details
                        </th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <th>RenewalConfiguration</th>
                        <td>
                            % if AcmeOrder.renewal_configuration_id:
                                <a
                                    class="label label-info"
                                    href="${admin_prefix}/renewal-configuration/${AcmeOrder.renewal_configuration_id}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    RenewalConfiguration-${AcmeOrder.renewal_configuration_id}
                                </a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>CertificateSigned</th>
                        <td>
                            % if AcmeOrder.certificate_signed_id:
                                <a
                                    class="label label-info"
                                    href="${admin_prefix}/certificate-signed/${AcmeOrder.certificate_signed_id}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    CertificateSigned-${AcmeOrder.certificate_signed_id}
                                </a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>note</th>
                        <td>
                            % if AcmeOrder.note:
                                <code>${AcmeOrder.note or ''}</code>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>replaces (actual)</th>
                        <td>
                            % if AcmeOrder.replaces:
                                <code>${AcmeOrder.replaces or ''}</code>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>replaces_requested</th>
                        <td>
                            % if AcmeOrder.replaces__requested:
                                <code>${AcmeOrder.replaces__requested or ''}</code>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>certificate_signed_id__replaces</th>
                        <td>
                            % if AcmeOrder.certificate_signed_id__replaces:
                                <a
                                    class="label label-info"
                                    href="${admin_prefix}/certificate-signed/${AcmeOrder.certificate_signed_id__replaces}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    CertificateSigned-${AcmeOrder.certificate_signed_id__replaces}
                                </a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>is_save_alternate_chains</th>
                        <td>
                            % if AcmeOrder.is_save_alternate_chains:
                                <code>${AcmeOrder.is_save_alternate_chains or ''}</code>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>PrivateKey Cycle</th>
                        <td>
                            <code>${AcmeOrder.private_key_cycle}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>CertificateType</th>
                        <td>
                            ##<code>${AcmeOrder.certificate_type}</code>
                            % if AcmeOrder.certificate_type_id == model_websafe.CertificateType.MANAGED_PRIMARY:
                                <span class="label label-success">${AcmeOrder.certificate_type}</span>
                            % elif AcmeOrder.certificate_type_id == model_websafe.CertificateType.MANAGED_BACKUP:
                                <span class="label label-warning">${AcmeOrder.certificate_type}</span>
                            % elif AcmeOrder.certificate_type_id == model_websafe.CertificateType.RAW_IMPORTED:
                                ## impossible in AcmeOrder context
                                <span class="label label-default">${AcmeOrder.certificate_type}</span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeAccount</th>
                        <td>
                            <a
                                class="label label-info"
                                href="${admin_prefix}/acme-account/${AcmeOrder.acme_account_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeAccount-${AcmeOrder.acme_account_id}
                            </a>
                            % if AcmeOrder.acme_account.name:
                                <span class="label label-default">
                                    ${AcmeOrder.acme_account.name}
                                </span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeServer</th>
                        <td>
                            <a
                                class="label label-info"
                                href="${admin_prefix}/acme-server/${AcmeOrder.acme_account.acme_server_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeServer-${AcmeOrder.acme_account.acme_server_id}
                            </a>
                            <span class="label label-default">
                                ${AcmeOrder.acme_account.acme_server.name}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>CertificateRequest</th>
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
                        <th>PrivateKey</th>
                        <td>
                            % if AcmeOrder.private_key_id == 0:
                                <span class="label label-default">placeholder key</span>
                                <code>type: ${AcmeOrder.private_key_deferred}</code>
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
                        <th>PrivateKey (Deferred)</th>
                        <td>
                            % if AcmeOrder.private_key_deferred_id:
                                <span class="label label-default">private_key_deferred_id</span>
                                <code>type: ${model_websafe.PrivateKeyDeferred._mapping[AcmeOrder.private_key_deferred_id]}</code>
                            % endif
                        </td>
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
                        <th>UniquelyChallengedFQDNSet</th>
                        <td>
                            <a
                                class="label label-info"
                                href="${admin_prefix}/uniquely-challenged-fqdn-set/${AcmeOrder.uniquely_challenged_fqdn_set_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                UniquelyChallengedFQDNSet-${AcmeOrder.uniquely_challenged_fqdn_set_id}
                            </a>
                            <br/>
                            <code>${AcmeOrder.uniquely_challenged_fqdn_set.domain_names}</code>
                        </td>
                    </tr>
                    <tr>
                        <th><hr/></th>
                        <th><hr/></th>
                    </tr>

                    <tr>
                        <th>AcmeOrder - Retry Of</th>
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
                        <th>AcmeOrder - Renewal Of</th>
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
