<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-event-logs">Acme Event Logs</a></li>
        <li class="active">Focus: ${AcmeEventLog.id}</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Acme Event Log: Focus ${AcmeEventLog.id}</h2>
</%block>



<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <table class="table table-striped table-condensed">
                <tr>
                    <th>id</th>
                    <td><span class="label label-default">${AcmeEventLog.id}</span></td>
                </tr>
                <tr>
                    <th>timestamp_event</th>
                    <td>${AcmeEventLog.timestamp_event}</td>
                </tr>
                <tr>
                    <th>acme_event</th>
                    <td><span class="label label-default">${AcmeEventLog.acme_event}</span></td>
                </tr>
                <tr>
                    <th>acme_account_key_id</th>
                    <td>
                        % if AcmeEventLog.acme_account_key_id:
                            <a  class="label label-info"
                                href="${admin_prefix}/acme-account-key/${AcmeEventLog.acme_account_key_id}"
                            >
                                account-${AcmeEventLog.acme_account_key_id}
                            </a>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>certificate_request_id</th>
                    <td>
                        % if AcmeEventLog.certificate_request_id:
                            <a  class="label label-info"
                                href="${admin_prefix}/certificate-request/${AcmeEventLog.certificate_request_id}"
                            >
                                csr-${AcmeEventLog.certificate_request_id}
                            </a>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>challenges?</th>
                    <td>
                        % if AcmeEventLog.acme_challenge_logs:
                            <ul>
                            % for challenge in AcmeEventLog.acme_challenge_logs:
                                <li>
                                    <a  class="label label-info"
                                        href="${admin_prefix}/acme-challenge-log/${challenge.id}"
                                    >
                                        challenge-${challenge.id}
                                    </a>
                                </li>
                            % endfor
                            </ul>
                        % endif
                    </td>
                </tr>
            </table>
        </div>
    </div>
</%block>
