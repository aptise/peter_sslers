<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/operations/log">Operations</a></li>
        <li class="active">Certificate Downloads</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Certificate Downloads</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">

            % if OperationsEvents:
                ${admin_partials.nav_pagination(pager)}
                <%
                    event_id = None
                    if show_event is not None:
                        event_id = request.params.get('event.id')
                %>
                <table class="table table-striped table-condensed">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>event timestamp</th>
                            <th>is_certificates_discovered</th>
                            <th>is_certificates_updated</th>
                        </tr>
                    </thead>
                    <tbody>
                        % for event in OperationsEvents:
                            <tr class="${'success' if event_id == str(event.id) else ''}">
                                <td>
                                    <a  href="${admin_prefix}/operations/log/item/${event.id}"
                                        class="label label-info"
                                    >
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        ${event.id}
                                    </a>
                                </td>
                                <td><timestamp>${event.timestamp_event}</timestamp></td>
                                <td>
                                    % if event.event_payload_json['is_certificates_discovered']:
                                        <span class="label label-success">Y</span>
                                    % endif
                                </td>
                                <td>
                                    % if event.event_payload_json['is_certificates_updated']:
                                        <span class="label label-success">Y</span>
                                    % endif
                                </td>
                            </tr>
                        % endfor
                    </tbody>
                </table>
            % else:
                <em>
                    no certificate Downloads
                </em>
            % endif

        </div>
        <div class="col-sm-3">
            <ul class="nav nav-pills nav-stacked">
                <li class="active">
                    <a  href="${admin_prefix}/operations/certificate-ca-downloads"
                    >
                        <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                        Certificate Downloads Log
                    </a>
                </li>
                <li>
                    <form action="${admin_prefix}/api/certificate-ca/letsencrypt-sync"
                          method="POST"
                          id="form-certificate_ca-letsencrypt_sync"
                    >
                        <button class="btn btn-primary">
                            <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                            Download LetsEcnrypt certificate-cas
                        </button>
                    </form>
                </li>
                <li>
                    <a  href="${admin_prefix}/operations/log"
                    >
                        <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                        Full Operations Log
                    </a>
                </li>
            </ul>
        </div>
    </div>
</%block>
