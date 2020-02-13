<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-challenges">Acme Challenge</a></li>
        <li class="active">Focus: ${AcmeChallenge.id}</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Acme Challenge: Focus ${AcmeChallenge.id}</h2>
</%block>



<%block name="content_main">

    <p>
        % if AcmeChallenge.is_can_acme_server_sync:
            <a
                href="${admin_prefix}/acme-challenge/${AcmeChallenge.id}/acme-server-sync"
                class="btn btn-xs btn-info"
            >
                <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                Sync AcmeChallenge Against ACME Server
            </a>
        % endif
    </p>   

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
                            <a  class="label label-info"
                                href="${admin_prefix}/acme-authorization/${AcmeChallenge.acme_authorization_id}"
                            >
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeAuthorization-${AcmeChallenge.acme_authorization_id}
                            </a>
                        </td>
                    </tr>
                    <tr>
                        <th>acme_challenge_type</th>
                        <td><span class="label label-default">${AcmeChallenge.acme_challenge_type}</span></td>
                    </tr>
                    <tr>
                        <th>challenge_url</th>
                        <td>${AcmeChallenge.challenge_url}</td>
                    </tr>
                    <tr>
                        <th>timestamp_created</th>
                        <td><timestamp>${AcmeChallenge.timestamp_created}</timestamp></td>
                    </tr>
                    <tr>
                        <th>status</th>
                        <td><code>${AcmeChallenge.status_text}</code></td>
                    </tr>
                    <tr>
                        <th>token</th>
                        <td><code>${AcmeChallenge.token}</code></td>
                    </tr>
                    <tr>
                        <th>timestamp_updated</th>
                        <td><timestamp>${AcmeChallenge.timestamp_updated}</timestamp></td>
                    </tr>
                    <tr>
                        <th>keyauthorization</th>
                        <td><code>${AcmeChallenge.keyauthorization}</code></td>
                    </tr>
                </tbody>
                <thead>
                    <tr>
                        <th colspan="2">
                        </th>
                    </tr>
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
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeChallengePoll-${poll.id}
                                </a>
                            </td>
                            <td><timestamp>${poll.timestamp_polled}</timestamp></td>
                            <td>${poll.remote_ip_address}</td>
                        </tr>
                    % endfor
                </tbody>
            </table>
        </div>
    </div>
</%block>

