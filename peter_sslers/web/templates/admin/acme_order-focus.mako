<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-orders">ACME Orders</a></li>
        <li class="active">Focus [${AcmeOrder.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>ACME Order - Focus</h2>
    <p>${request.text_library.info_AcmeOrders[1]}</p>

    ${admin_partials.standard_error_display()}
</%block>


<%block name="page_header_nav">
</%block>


<%block name="content_main">
    ${admin_partials.handle_querystring_result()}
    

    <p>
        % if AcmeOrder.is_can_acme_server_sync:
            <a
                href="${admin_prefix}/acme-order/${AcmeOrder.id}/acme-server-sync"
                class="label label-info"
            >
                <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                Sync Order Against ACME Server
            </a>
        % endif
        % if AcmeOrder.is_can_retry:
            <a
                href="${admin_prefix}/acme-order/${AcmeOrder.id}/retry"
                class="label label-info"
            >
                <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                Retry (New) Order
            </a>
        % endif
        <a
            href="${admin_prefix}/acme-order/${AcmeOrder.id}/acme-authorizations"
            class="label label-info"
        >
            <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
            Related AcmeAuthorizations
        </a>
    </p>    
    
    <div class="row">
        <div class="col-sm-12">
            <table class="table">
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
                    <td><timestamp>${AcmeOrder.timestamp_created  or ''}</timestamp>
                    </td>
                </tr>
                <tr>
                    <th>status</th>
                    <td><code>${AcmeOrder.status  or ''}</code>
                    </td>
                </tr>
                <tr>
                    <th>resource_url</th>
                    <td><code>${AcmeOrder.resource_url or ''}</code>
                    </td>
                </tr>
                <tr>
                    <th>timestamp_expires</th>
                    <td><timestamp>${AcmeOrder.timestamp_expires  or ''}</timestamp>
                    </td>
                </tr>
                <tr>
                    <th>timestamp_finalized</th>
                    <td><timestamp>${AcmeOrder.timestamp_finalized  or ''}</timestamp>
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
                                UniqueFqdnSet-${AcmeOrder.unique_fqdn_set_id}
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


            </table>
        </div>
    </div>
</%block>
