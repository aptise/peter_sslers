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


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-event-log/${AcmeEventLog.id}.json" class="btn btn-xs btn-info">
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
                    <td><span class="label label-default">${AcmeEventLog.id}</span></td>
                </tr>
                <tr>
                    <th>timestamp_event</th>
                    <td><timestamp>${AcmeEventLog.timestamp_event}</timestamp></td>
                </tr>
                <tr>
                    <th>acme_event</th>
                    <td><span class="label label-default">${AcmeEventLog.acme_event}</span></td>
                </tr>
                <tr>
                    <th>acme_account_id</th>
                    <td>
                        % if AcmeEventLog.acme_account_id:
                            <a  class="label label-info"
                                href="${admin_prefix}/acme-account/${AcmeEventLog.acme_account_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeAccount-${AcmeEventLog.acme_account_id}
                            </a>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>acme_authorization_id</th>
                    <td>
                        % if AcmeEventLog.acme_authorization_id:
                            <a  class="label label-info"
                                href="${admin_prefix}/acme-authorization/${AcmeEventLog.acme_authorization_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeAuthorization-${AcmeEventLog.acme_authorization_id}
                            </a>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>acme_challenge_id</th>
                    <td>
                        % if AcmeEventLog.acme_challenge_id:
                            <a  class="label label-info"
                                href="${admin_prefix}/acme-challenge/${AcmeEventLog.acme_challenge_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeChallenge-${AcmeEventLog.acme_challenge_id}
                            </a>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>acme_order_id</th>
                    <td>
                        % if AcmeEventLog.acme_order_id:
                            <a  class="label label-info"
                                href="${admin_prefix}/acme-order/${AcmeEventLog.acme_order_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeOrder-${AcmeEventLog.acme_order_id}
                            </a>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>x509_certificate_request_id</th>
                    <td>
                        % if AcmeEventLog.x509_certificate_request_id:
                            <a  class="label label-info"
                                href="${admin_prefix}/x509-certificate-request/${AcmeEventLog.x509_certificate_request_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                X509CertificateRequest-${AcmeEventLog.x509_certificate_request_id}
                            </a>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>x509_certificate_id</th>
                    <td>
                        % if AcmeEventLog.x509_certificate_id:
                            <a  class="label label-info"
                                href="${admin_prefix}/x509-certificate/${AcmeEventLog.x509_certificate_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                X509Certificate-${AcmeEventLog.x509_certificate_id}
                            </a>
                        % endif
                    </td>
                </tr>
            </table>
        </div>
    </div>
</%block>
