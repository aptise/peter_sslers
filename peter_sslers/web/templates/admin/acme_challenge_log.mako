<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Acme Challenge Logs</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Acme Challenge Log</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if SslAcmeChallenges:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>event-id</th>
                            <th>challenge-id</th>
                            <th>timestamp_created</th>
                            <th>acme_challenge_type</th>
                            <th>domain</th>
                            <th>acme_challenge</th>
                            <th>triggered?</th>
                            <th>count_polled</th>
                            <th>passed?</th>
                            <th>failed?</th>
                        </tr>
                    </thead>
                    <tbody>
                    % for logged in SslAcmeChallenges:
                        <tr>
                            <td>
                                <a  class="label label-info"
                                    href="${admin_prefix}/acme-event-log/${logged.ssl_acme_event_log_id}"
                                >
                                    event-${logged.ssl_acme_event_log_id}
                                </a>
                            </td>
                            <td>
                                <a  class="label label-info"
                                    href="${admin_prefix}/acme-challenge-log/${logged.id}"
                                >
                                    challenge-${logged.id}
                                </a>
                            </td>
                            <td>${logged.timestamp_created}</td>
                            <td><span class="label label-default">${logged.acme_challenge_type}</span></td>
                            <td>${logged.domain}</td>
                            <td>${logged.acme_challenge}</td>
                            <td>${True if logged.timestamp_challenge_trigger else False}</td>
                            <td><span class="badge">${logged.count_polled}</span></td>
                            <td>${True if logged.timestamp_challenge_pass else False}</td>
                            <td>${logged.acme_challenge_fail_type if logged.acme_challenge_fail_type_id else False}</td>
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
