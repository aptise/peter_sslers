<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-orderlesss">AcmeOrderless</a></li>
        <li><a href="${admin_prefix}/acme-orderless/${AcmeOrderless.id}">Focus - ${AcmeOrderless.id}</a></li>
        <li><a href="#">AcmeChallenge Focus</a></li>
    </ol>
</%block>


<%block name="page_header_col">
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-orderless/${AcmeOrderless.id}/acme-challenge/${AcmeChallenge.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">

            <p>Challenge for
                <a  class="label label-default"
                    href="${admin_prefix}/acme-orderless/${AcmeOrderless.id}"
                >
                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                    AcmeOrderless-${AcmeOrderless.id}
                </a>
            </p>

            <p>
                The AcmeOrderless, and this challenge, is
                % if AcmeOrderless.is_processing:
                    <span class="label label-success">active</span>
                % else:
                    <span class="label label-danger">deactivated</span>
                % endif
            </p>

        </div>
    </div>
    <div class="row">
        <div class="col-sm-12">
            <h5>AcmeChallenge Details</h5>
            
            <table class="table table-condensed table-striped">
                <tr>
                    <th>id</th>
                    <td>
                        <span class="label label-default">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            AcmeChallenge-${AcmeChallenge.id}
                        </span>
                    </td>
                </tr>
                <tr>
                    <th>domain</th>
                    <td>
                        <a class="label label-info" href="${admin_prefix}/domain/${AcmeChallenge.domain_id}">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            ${AcmeChallenge.domain_id}
                            |
                            ${AcmeChallenge.domain_name}
                        </a>
                    </td>
                </tr>
                <tr>
                    <th>type</th>
                    <td>
                        <span class="label label-default">${AcmeChallenge.acme_challenge_type}</span>
                    </td>
                </tr>
                <tr>
                    <th>status</th>
                    <td>
                        <span class="label label-default">${AcmeChallenge.acme_status_challenge}</span>
                    </td>
                </tr>

                <tr>
                    <th>token</th>
                    <td>
                        <code>${AcmeChallenge.token or ''}</code>
                    </td>
                </tr>
                <tr>
                    <th>keyauthorization</th>
                    <td>
                        <code>${AcmeChallenge.keyauthorization or ''}</code>
                    </td>
                </tr>
                % if AcmeOrderless.acme_account_id:
                    <tr>
                        <th>challenge_url</th>
                        <td>
                            <code>${AcmeChallenge.challenge_url or 'n/a'}</code>
                            <em>(this is not the URL on your server, but the ACME Server URL)</em>
                        </td>
                    </tr>
                % endif
                <tr>
                    <th>timestamp_updated</th>
                    <td>
                        <timestamp>${AcmeChallenge.timestamp_updated or ''}</timestamp>
                    </td>
                </tr>
                <tr>
                    <th>test</th>
                    <td>
                        % if AcmeChallenge.acme_challenge_type == "http-01":
                            % if AcmeChallenge.token:
                                <a href="http://${AcmeChallenge.domain.domain_name}/.well-known/acme-challenge/${AcmeChallenge.token}?test=1"
                                   target="_blank"
                                   class="btn btn-${"success" if AcmeOrderless.is_processing else "danger"}"
                                >
                                    <span class="glyphicon glyphicon-link" aria-hidden="true"></span>
                                </a>
                            % endif
                        % endif
                    </td>
                </tr>
                
            </table>

            <h5>AcmeChallengePolls</h5>
            % if not AcmeChallenge.acme_challenge_polls:
                <p>no polls</p>
            % else:
                <table class="table table-condensed table-striped">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>timestamp_polled</th>
                            <th>remote_ip_address</th>
                        </tr>
                    </thead>
                    <tbody>
                        % for poll in AcmeChallenge.acme_challenge_polls:
                            <tr>
                                <td>${poll.id}</td>
                                <td>${poll.timestamp_polled}</td>
                                <td>${poll.remote_ip_address.remote_ip_address}</td>
                            </tr>
                        % endfor
                    </tbody>
                </table>
            % endif


        </div>
    </div>
</%block>
