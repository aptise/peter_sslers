<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-event-logs">Acme Challenge</a></li>
        <li class="active">Focus: ${AcmeChallenge.id}</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Acme Challenge: Focus ${AcmeChallenge.id}</h2>
</%block>



<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <table class="table table-striped table-condensed">
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
                        <td><span class="label label-default">${AcmeChallenge.id}</span></td>
                    </tr>
                    <tr>
                        <th>AcmeAuthorization</th>
                        <td>
                            via log event
                            <a  class="label label-info"
                                href="${admin_prefix}/acme-authorization/${AcmeChallenge.acme_authorization_id}"
                            >
                                AcmeAuthorization-${AcmeChallenge.acme_authorization_id}
                            </a>
                        </td>
                    </tr>
                    <tr>
                        <th>challenge_url</th>
                        <td>${AcmeChallenge.challenge_url}</td>
                    </tr>
                    <tr>
                        <th>timestamp_created</th>
                        <td>${AcmeChallenge.timestamp_created}</td>
                    </tr>
                    <tr>
                        <th>status</th>
                        <td><code>${AcmeChallenge.status}</code></td>
                    </tr>
                    <tr>
                        <th>token</th>
                        <td><code>${AcmeChallenge.token}</code></td>
                    </tr>
                    <tr>
                        <th>timestamp_updated</th>
                        <td>${AcmeChallenge.timestamp_updated}</td>
                    </tr>
                    <tr>
                        <th>keyauthorization</th>
                        <td><code>${AcmeChallenge.keyauthorization}</code></td>
                    </tr>
                </tbody>
                <thead>
                    <tr>
                        <th colspan="2">
                            Polls
                        </th>
                    </tr>
                </thead>
                <tbody>
                    % for poll in AcmeChallenge.acme_challenge_polls:
                        <tr>
                            <td>
                                <a  class="label label-info"
                                    href="${admin_prefix}/acme-challenge-poll/${poll.id}"
                                >
                                    AcmeChallengePoll-${poll.id}
                                </a>
                            </td>
                            <td>${poll.timestamp_polled}</td>
                            <td>${poll.remote_ip_address}</td>
                        </tr>
                    % endfor
                </tbody>
            </table>
        </div>
    </div>
</%block>

