<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-orderlesss">ACME Orderless</a></li>
        <li><a href="${admin_prefix}/acme-orderlesss/${AcmeOrderless.id}">Focus - ${AcmeOrderless.id}</a></li>
        <li><a href="#">Challenge Focus</a></li>
    </ol>
</%block>


<%block name="page_header_col">
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

        </div>
    </div>
    <div class="row">
        <div class="col-sm-12">
            <h5>AcmeOrderlessChallenge Details</h5>
            
            <table class="table table-condensed table-striped">
                <tr>
                    <th>id</th>
                    <td>
                        <span class="label label-default">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            AcmeOrderlessChallenge-${AcmeOrderlessChallenge.id}
                        </span>
                    </td>
                </tr>
                <tr>
                    <th>domain</th>
                    <td>
                        <a class="label label-info" href="${admin_prefix}/domain/${AcmeOrderlessChallenge.domain_id}">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            ${AcmeOrderlessChallenge.domain_id}
                            |
                            ${AcmeOrderlessChallenge.domain_name}
                        </a>
                    </td>
                </tr>
                <tr>
                    <th>type</th>
                    <td>
                        <span class="label label-default">${AcmeOrderlessChallenge.acme_challenge_type}</span>
                    </td>
                </tr>
                <tr>
                    <th>status</th>
                    <td>
                        <span class="label label-default">${AcmeOrderlessChallenge.acme_status_challenge}</span>
                    </td>
                </tr>

                <tr>
                    <th>token</th>
                    <td>
                        <code>${AcmeOrderlessChallenge.token or ''}</code>
                    </td>
                </tr>
                <tr>
                    <th>keyauthorization</th>
                    <td>
                        <code>${AcmeOrderlessChallenge.keyauthorization or ''}</code>
                    </td>
                </tr>
                <tr>
                    <th>challenge_url</th>
                    <td>
                        <code>${AcmeOrderlessChallenge.challenge_url or ''}</code>
                        (this is not the URL on your server, but the ACME Server URL)
                    </td>
                </tr>

                <tr>
                    <th>timestamp_updated</th>
                    <td>
                        <timestamp>${AcmeOrderlessChallenge.timestamp_updated or ''}</timestamp>
                    </td>
                </tr>
            </table>

            <h5>AcmeOrderlessChallengePolls</h5>
            % if not AcmeOrderlessChallenge.acme_orderless_challenge_polls:
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
                        % for poll in AcmeOrderlessChallenge.acme_orderless_challenge_polls:
                            <tr>
                                <td>${poll.id}</td>
                                <td>${poll.timestamp_polled}</td>
                                <td>${poll.remote_ip_address}</td>
                            </tr>
                        % endfor
                    </tbody>
                </table>
            % endif


        </div>
    </div>
</%block>
