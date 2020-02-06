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
                    <th>timestamp_finalized</th>
                    <td><timestamp>${AcmeOrder.timestamp_finalized  or ''}</timestamp>
                    </td>
                </tr>
                <tr>
                    <th>acme_account_key_id</th>
                    <td>
                        <a
                            class="label label-info"
                            href="${admin_prefix}/account-key/${AcmeOrder.acme_account_key_id}"
                        >
                            ${AcmeOrder.acme_account_key_id}
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
                                ${AcmeOrder.certificate_request_id}
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
                                ${AcmeOrder.server_certificate_id}
                            </a>
                        % endif
                    </td>
                </tr>



            </table>
        </div>
    </div>
</%block>