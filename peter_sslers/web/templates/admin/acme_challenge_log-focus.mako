<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-event-logs">Acme Challenge Logs</a></li>
        <li class="active">Focus: ${AcmeChallenge.id}</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Acme Challenge Log: Focus ${AcmeChallenge.id}</h2>
</%block>



<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <table class="table table-striped table-condensed">
                <tr>
                    <th>id</th>
                    <td><span class="label label-default">${AcmeChallenge.id}</span></td>
                </tr>
                <tr>
                    <th>acme_event_log</th>
                    <td>
                        <a  class="label label-info"
                            href="${admin_prefix}/acme-event-log/${AcmeChallenge.acme_event_log_id}"
                        >
                            event-${AcmeChallenge.acme_event_log_id}
                        </a>
                    </td>
                </tr>
                <tr>
                    <th>account/provider</th>
                    <td>
                        via log event
                        <a  class="label label-info"
                            href="${admin_prefix}/acme-account-keys/${AcmeChallenge.acme_event_log.acme_account_key_id}"
                        >
                            account-${AcmeChallenge.acme_event_log.acme_account_key_id}
                        </a>
                    </td>
                </tr>
                <tr>
                    <th>timestamp_created</th>
                    <td>${AcmeChallenge.timestamp_created}</td>
                </tr>
                <tr>
                    <th>domain</th>
                    <td><code>${AcmeChallenge.domain}</code></td>
                </tr>
                <tr>
                    <th>acme_challenge_type</th>
                    <td><span class="label label-default">${AcmeChallenge.acme_challenge_type}</span></td>
                </tr>
                <tr>
                    <th>acme_challenge</th>
                    <td><code>${AcmeChallenge.acme_challenge}</code></td>
                </tr>
                <tr>
                    <th>timestamp_challenge_trigger</th>
                    <td>${AcmeChallenge.timestamp_challenge_trigger or ''}</td>
                </tr>
                <tr>
                    <th>count_polled</th>
                    <td><span class="badge">${AcmeChallenge.count_polled or ''}</span></td>
                </tr>
                <tr>
                    <th>timestamp_challenge_pass</th>
                    <td>${AcmeChallenge.timestamp_challenge_pass or ''}</td>
                </tr>
                <tr>
                    <th>acme_challenge_fail_type</th>
                    <td>${AcmeChallenge.acme_challenge_fail_type or ''}</td>
                </tr>
            </table>
        </div>
    </div>
</%block>

