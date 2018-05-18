<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-event-logs">Acme Challenge Logs</a></li>
        <li class="active">Focus: ${SslAcmeChallengeLog.id}</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Acme Challenge Log: Focus ${SslAcmeChallengeLog.id}</h2>
</%block>



<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <table class="table table-striped table-condensed">
                <tr>
                    <th>id</th>
                    <td><span class="label label-default">${SslAcmeChallengeLog.id}</span></td>
                </tr>
                <tr>
                    <th>acme_event_log</th>
                    <td>
                        <a  class="label label-info"
                            href="${admin_prefix}/acme-event-log/${SslAcmeChallengeLog.ssl_acme_event_log_id}"
                        >
                            event-${SslAcmeChallengeLog.ssl_acme_event_log_id}
                        </a>
                    </td>
                </tr>
                <tr>
                    <th>timestamp_created</th>
                    <td>${SslAcmeChallengeLog.timestamp_created}</td>
                </tr>
                <tr>
                    <th>domain</th>
                    <td><code>${SslAcmeChallengeLog.domain}</code></td>
                </tr>
                <tr>
                    <th>acme_challenge_type</th>
                    <td><span class="label label-default">${SslAcmeChallengeLog.acme_challenge_type}</span></td>
                </tr>
                <tr>
                    <th>acme_challenge</th>
                    <td><code>${SslAcmeChallengeLog.acme_challenge}</code></td>
                </tr>
                <tr>
                    <th>timestamp_challenge_trigger</th>
                    <td>${SslAcmeChallengeLog.timestamp_challenge_trigger or ''}</td>
                </tr>
                <tr>
                    <th>count_polled</th>
                    <td><span class="badge">${SslAcmeChallengeLog.count_polled or ''}</span></td>
                </tr>
                <tr>
                    <th>timestamp_challenge_pass</th>
                    <td>${SslAcmeChallengeLog.timestamp_challenge_pass or ''}</td>
                </tr>
                <tr>
                    <th>acme_challenge_fail_type</th>
                    <td>${SslAcmeChallengeLog.acme_challenge_fail_type or ''}</td>
                </tr>
            </table>
        </div>
    </div>
</%block>

