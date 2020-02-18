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
    
    <p>
        <% sync_btn_class = '' if AcmeOrder.is_can_acme_server_sync else 'disabled' %>
        <a
            href="${admin_prefix}/acme-order/${AcmeOrder.id}/acme-server-sync"
            class="btn btn-xs btn-info ${sync_btn_class}"
        >
            <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
            Sync Order Against ACME Server
        </a>

        <% deactivate_btn_class = '' if AcmeOrder.is_can_acme_server_deactivate_authorizations else 'disabled' %>
        <a
            href="${admin_prefix}/acme-order/${AcmeOrder.id}/acme-server-deactivate-authorizations"
            class="btn btn-xs btn-info ${deactivate_btn_class}"
        >
            <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
            Deactivate Authorizations on ACME Server
        </a>

        <% retry_btn_class = '' if AcmeOrder.is_can_retry else 'disabled' %>
        <a
            href="${admin_prefix}/acme-order/${AcmeOrder.id}/retry"
            class="btn btn-xs btn-info ${retry_btn_class}"
        >
            <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
            Retry (New) Order
        </a>
    </p>    
    
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
                                ${AcmeOrder.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>timestamp_created</th>
                        <td><timestamp>${AcmeOrder.timestamp_created or ''}</timestamp>
                        </td>
                    </tr>
                    <tr>
                        <th>is_active</th>
                        <td>
                        
                            % if AcmeOrder.is_active:
                                <div class="label label-success">
                                    <span class="glyphicon glyphicon-ok" aria-hidden="true"></span>
                                </div>
                            % else:
                                <div class="label label-danger">
                                    <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
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
                        <th>resource_url</th>
                        <td><code>${AcmeOrder.resource_url or ''}</code>
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
                        <th>server_certificate_id</th>
                        <td>
                            % if AcmeOrder.server_certificate_id:
                                <a
                                    class="label label-info"
                                    href="${admin_prefix}/certificate/${AcmeOrder.server_certificate_id}"
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
                            % if AcmeOrder.unique_fqdn_set_id:
                                <a
                                    class="label label-info"
                                    href="${admin_prefix}/unique-fqdn-set/${AcmeOrder.unique_fqdn_set_id}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    UniqueFQDNSet-${AcmeOrder.unique_fqdn_set_id}
                                </a>
                            % endif
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
                </tbody>
        </div>
    </div>
</%block>
