<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-polling-errors">Acme Polling Errors</a></li>
        <li class="active">Focus: ${AcmePollingError.id}</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Acme Polling Error: Focus ${AcmePollingError.id}</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-polling-error/${AcmePollingError.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>



<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <table class="table table-striped table-condensed">
                <tr>
                    <th>id</th>
                    <td><span class="label label-default">${AcmePollingError.id}</span></td>
                </tr>
                <tr>
                    <th>timestamp_created</th>
                    <td><timestamp>${AcmePollingError.timestamp_created}</timestamp></td>
                </tr>
                <tr>
                    <th>acme_polling_error_endpoint</th>
                    <td>
                        <code>${AcmePollingError.acme_polling_error_endpoint}</code>
                    </td>
                </tr>
                <tr>
                    <th>timestamp_validated</th>
                    <td>
                        % if AcmePollingError.timestamp_validated:
                            <timestamp>${AcmePollingError.timestamp_validated}</timestamp>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>subproblems_len</th>
                    <td>
                        % if AcmePollingError.subproblems_len:
                            <code>${AcmePollingError.subproblems_len}</code>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>acme_order_id</th>
                    <td>
                        % if AcmePollingError.acme_order_id:
                            <a  class="label label-info"
                                href="${admin_prefix}/acme-order/${AcmePollingError.acme_order_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeOrder-${AcmePollingError.acme_order_id}
                            </a>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>acme_authorization_id</th>
                    <td>
                        % if AcmePollingError.acme_authorization_id:
                            <a  class="label label-info"
                                href="${admin_prefix}/acme-authorization/${AcmePollingError.acme_authorization_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeAuthorization-${AcmePollingError.acme_authorization_id}
                            </a>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>acme_challenge_id</th>
                    <td>
                        % if AcmePollingError.acme_challenge_id:
                            <a  class="label label-info"
                                href="${admin_prefix}/acme-challenge/${AcmePollingError.acme_challenge_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeChallenge-${AcmePollingError.acme_challenge_id}
                            </a>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>response</th>
                    <td>
                        % if AcmePollingError.response:
                            <code>${AcmePollingError.response}</code>
                        % endif
                    </td>
                </tr>
            </table>
        </div>
    </div>
</%block>
