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



<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-challenge/${AcmeChallenge.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    ${admin_partials.handle_querystring_result()}

    <div class="row">
        <div class="col-sm-12">
            <table class="table table-striped table-condensed">
                <thead>
                    <tr>
                        <th colspan="2">
                            ACME Server Operations
                        </th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <th>Sync</th>
                        <td>
                    
                            <% _btn_class = '' if AcmeChallenge.is_can_acme_server_sync else 'disabled' %>
                            <form method="POST"
                                action="${admin_prefix}/acme-challenge/${AcmeChallenge.id}/acme-server/sync"
                                id="form-acme_server-sync"
                            >
                                <button class="btn btn-xs btn-info ${_btn_class}" id="btn-acme_challenge-sync">
                                    <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                    Sync AcmeChallenge Against ACME Server
                                </button>
                            </form>

                            <% _btn_class = '' if AcmeChallenge.is_can_acme_server_trigger else 'disabled' %>
                            <form method="POST"
                                action="${admin_prefix}/acme-challenge/${AcmeChallenge.id}/acme-server/trigger"
                                id="form-acme_server-trigger"
                            >
                                <button class="btn btn-xs btn-info ${_btn_class}" id="btn-acme_challenge-trigger">
                                    <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                    Trigger ACME Server
                                </button>
                                % if AcmeChallenge.is_can_acme_server_trigger:
                                    <p><em>${AcmeChallenge.challenge_instructions_short}</em></p>
                                    % if not AcmeChallenge.is_configured_to_answer:
                                        This installation is NOT configured to answer this challenge.
                                        You must submit the challenge <code>token</code> to trigger.
                                        <input type="textfield" name="token" value="" class="form-control"/>
                                    % endif
                                % endif
                            </form>
                        </td>
                    </tr>
                </tbody>
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
                            % if AcmeChallenge.acme_authorization_id:
                                <a  class="label label-info"
                                    href="${admin_prefix}/acme-authorization/${AcmeChallenge.acme_authorization_id}"
                                >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeAuthorization-${AcmeChallenge.acme_authorization_id}
                                </a>
                                <hr/>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeOrders</th>
                        <td>
                            % for acmeOrder in AcmeChallenge.acme_orders:
                                <a  class="label label-info"
                                    href="${admin_prefix}/acme-order/${acmeOrder.id}"
                                >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeOrder-${acmeOrder.id}
                                </a>
                                <hr/>
                            % endfor
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeOrder2AcmeChallengeTypeSpecifics</th>
                        <td>
                            <em>If no ChallengeTypes are preferred, the default HTTP-01 challenge will be used.</em>
                            % if AcmeChallenge.acme_order_2_acme_challenge_type_specifics:
                                <table class=" table-striped table-condensed">
                                    <thead>
                                        <tr>
                                            <th>AcmeOrder</th>
                                            <th>Preferred Challenge Type</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        % for order2Challenge in AcmeChallenge.acme_order_2_acme_challenge_type_specifics:
                                            <tr>
                                                <td>
                                                    <a class="label label-info" href="${admin_prefix}/acme-order/${order2Challenge.acme_order_id}">
                                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                    AcmeOrder-${order2Challenge.acme_order_id}</a>
                                                </td>
                                                <td>
                                                    <code>${order2Challenge.acme_challenge_type}</code>
                                                </td>
                                            </tr>
                                        % endfor
                                    </tbody>
                                </table>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>domain</th>
                        <td>
                            % if AcmeChallenge.domain_id:
                                <a  class="label label-info"
                                    href="${admin_prefix}/domain/${AcmeChallenge.domain_id}"
                                >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    Domain-${AcmeChallenge.domain_id}
                                </a>
                                <code>${AcmeChallenge.domain.domain_name}</code>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>acme_challenge_type</th>
                        <td><span class="label label-default">${AcmeChallenge.acme_challenge_type}</span></td>
                    </tr>
                    
                    <tr>
                        <th>test</th>
                        <td>
                            % if AcmeChallenge.acme_challenge_type == "http-01":
                                % if AcmeChallenge.token:
                                    <a href="http://${AcmeChallenge.domain.domain_name}/.well-known/acme-challenge/${AcmeChallenge.token}?test=1"
                                       target="_blank"
                                       class="btn btn-success"
                                    >
                                        <span class="glyphicon glyphicon-link" aria-hidden="true"></span>
                                    </a>
                                % endif
                            % endif
                        </td>
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
                        <td><code>${AcmeChallenge.acme_status_challenge}</code></td>
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
                                <span class="label label-default">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    ${poll.id}
                                </span>
                            </td>
                            <td><timestamp>${poll.timestamp_polled}</timestamp></td>
                            <td>${poll.remote_ip_address.remote_ip_address}</td>
                        </tr>
                    % endfor
                </tbody>
            </table>
        </div>
    </div>
</%block>

