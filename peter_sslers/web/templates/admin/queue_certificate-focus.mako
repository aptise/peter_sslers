<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/queue-certificates">Queue: Certificates</a></li>
        <li class="active">Focus [${QueueCertificate.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Queue: Certificates | Focus</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            ${admin_partials.handle_querystring_result()}
            <table class="table">
                <tr>
                    <th>id</th>
                    <td>
                        <span class="label label-default">
                            ${QueueCertificate.id}
                        </span>
                    </td>
                </tr>
                <tr>
                    <th>is_active</th>
                    <td>
                        <span class="label label-${'success' if QueueCertificate.is_active else 'warning'}">
                            ${'Active' if QueueCertificate.is_active else 'inactive'}
                        </span>
                        % if QueueCertificate.is_active:
                            &nbsp;
                            <form action="${admin_prefix}/queue-certificate/${QueueCertificate.id}/mark" method="POST" style="display:inline;">
                                <input type="hidden" name="action" value="cancel"/>
                                <button class="btn btn-xs btn-warning" type="submit">
                                    <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                    cancel
                                </button>
                            </form>
                        % else:
                            <span class="label label-default">cancelled</span>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>Covering</th>
                    <td>
                        <a class="label label-info"
                            href="${admin_prefix}/unique-fqdn-set/${QueueCertificate.unique_fqdn_set_id}"
                        >
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            UniqueFQDNSet-${QueueCertificate.unique_fqdn_set_id}</a>
                        <hr/>
                        <code>${QueueCertificate.unique_fqdn_set.domains_as_string}</code>
                    </td>
                </tr>
                <tr>
                    <th>AcmeAccountKey</th>
                    <td>
                        <a class="label label-info"
                            href="${admin_prefix}/acme-account-key/${QueueCertificate.acme_account_key_id}"
                        >
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            AcmeAccountKey-${QueueCertificate.acme_account_key_id}</a>
                        </hr/>
                    </td>
                </tr>
                <tr>
                    <th>PrivateKey</th>
                    <td>
                        <a class="label label-info"
                            href="${admin_prefix}/private-key/${QueueCertificate.private_key_id}"
                        >
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            PrivateKey-${QueueCertificate.private_key_id}</a>
                        </hr/>
                        <code>${QueueCertificate.private_key_id}</code>
                    </td>
                </tr>
                <tr>
                    <th>PrivateKeyCycle - renewals</th>
                    <td><code>${QueueCertificate.private_key_cycle__renewal}</code></td>
                </tr>
                    <tr>
                        <th>PrivateKeyStrategy - requested</th>
                        <td><code>${QueueCertificate.private_key_strategy__requested}</code></td>
                    </tr>
                <tr>
                    <th>Source</th>
                    <td>
                        % if QueueCertificate.acme_order_id__source:
                            <a class="label label-info"
                                href="${admin_prefix}/acme-order/${QueueCertificate.acme_order_id__source}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeOrder-${QueueCertificate.acme_order_id__source}</a>
                        % endif
                        % if QueueCertificate.server_certificate_id__source:
                            <a class="label label-info"
                                href="${admin_prefix}/server-certificate/${QueueCertificate.server_certificate_id__source}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ServerCertificate-${QueueCertificate.server_certificate_id__source}</a>
                        % endif
                        % if QueueCertificate.unique_fqdn_set_id__source:
                            <a class="label label-info"
                                href="${admin_prefix}/unique-fqdn-set/${QueueCertificate.unique_fqdn_set_id__source}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                UniqueFQDNSet-${QueueCertificate.unique_fqdn_set_id__source}</a>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>timestamp_entered</th>
                    <td>
                        <timestamp>${QueueCertificate.timestamp_entered or ''}</timestamp>
                    </td>
                </tr>
                <tr>
                    <th>timestamp_processed</th>
                    <td>
                        <timestamp>${QueueCertificate.timestamp_processed or ''}</timestamp>
                    </td>
                </tr>
                <tr>
                    <th>process_result</th>
                    <td>
                        ${QueueCertificate.process_result or ''}
                    </td>
                </tr>
                <tr>
                    <th>Generated</th>
                    <td>
                        % if QueueCertificate.acme_order_id__generated:
                            <a class="label label-info"
                                href="${admin_prefix}/acme-order/${QueueCertificate.acme_order_id__generated}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeOrder-${QueueCertificate.acme_order_id__generated}</a>
                        % endif
                        % if QueueCertificate.server_certificate_id__generated:
                            <a class="label label-info"
                                href="${admin_prefix}/server-certificate/${QueueCertificate.server_certificate_id__generated}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ServerCertificate-${QueueCertificate.server_certificate_id__generated}</a>
                        % endif
                        % if QueueCertificate.certificate_request_id__generated:
                            <a class="label label-info"
                                href="${admin_prefix}/certificate-request/${QueueCertificate.certificate_request_id__generated}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                CertificateRquest-${QueueCertificate.certificate_request_id__generated}</a>
                        % endif
                    </td>
                </tr>
                ${admin_partials.table_tr_OperationsEventCreated(QueueCertificate)}
            </table>

            <h4>Process History</h4>
            % if QueueCertificate.operations_object_events:
                ${admin_partials.table_OperationsObjectEvents(QueueCertificate.operations_object_events, table_context=None)}
            % endif
        </div>
    </div>
</%block>
