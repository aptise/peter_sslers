<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Acme Event Logs</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Acme Event Log</h2>
</%block>



<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if SslAcmeEventLogs:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>timestamp_event</th>
                            <th>acme_event_id</th>
                            <th>ssl_acme_account_key_id</th>
                            <th>ssl_certificate_request_id</th>
                        </tr>
                    </thead>
                    <tbody>
                    % for logged in SslAcmeEventLogs:
                        <tr>
                            <td>
                                <a  class="label label-info"
                                    href="${admin_prefix}/acme-event-log/${logged.id}"
                                >
                                    event-${logged.id}
                                </a>
                            </td>
                            <td>${logged.timestamp_event}</td>
                            <td><span class="label label-default">${logged.acme_event}</span></td>
                            <td>
                                % if logged.ssl_acme_account_key_id:
                                    <a  class="label label-info"
                                        href="${admin_prefix}/account-key/${logged.ssl_acme_account_key_id}"
                                    >
                                        account-${logged.ssl_acme_account_key_id}
                                    </a>
                                % endif
                            </td>
                            <td>
                                % if logged.ssl_certificate_request_id:
                                    <a  class="label label-info"
                                        href="${admin_prefix}/certificate-request/${logged.ssl_certificate_request_id}"
                                    >
                                        csr-${logged.ssl_certificate_request_id}
                                    </a>
                                % endif
                            </td>
                        </tr>
                    % endfor
                    </tbody>
                </table>
            % else:
                <em>
                    No Logs
                </em>
            % endif
        </div>
    </div>
</%block>
