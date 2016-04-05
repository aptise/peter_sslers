<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li><a href="/.well-known/admin/operations/log">Operations</a></li>
        <li class="active">Certificate Probes</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Certificate Probes</h2>
</%block>


<%block name="content_main">

    <div class="row">
        <div class="col-sm-9">

            % if LetsencryptOperationsEvents:
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
                        % for event in LetsencryptOperationsEvents:
                            <tr class="${'success' if event_id == str(event.id) else ''}">
                                <td><span class="label label-default">${event.id}</span></td>
                                <td><timestamp>${event.timestamp_operation}</timestamp></td>
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
                    no certificate probes
                </em>
            % endif

        </div>
        <div class="col-sm-3">

            <ul>
                <li>
                    <a  href="/.well-known/admin/operations/ca-certificate-probes/probe"
                        class="label label-primary"
                    >
                        <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                        Probe for new certificates
                    </a>
                    <br/>
                    <em>Checks for new certs on the public internet</em>
                </li>
                <li>
                    <a  href="/.well-known/admin/operations/log"
                        class="label label-info"
                    >
                        <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                        Full Operations Log
                    </a>
                </li>
            </ul>

        </div>
    </div>



</%block>


