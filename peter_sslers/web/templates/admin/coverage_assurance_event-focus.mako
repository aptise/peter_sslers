<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/coverage-assurance-events">Coverage Assurance Events</a></li>
        <li class="active">Focus [${CoverageAssuranceEvent.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Coverage Assurance Event Focus</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">

            ${admin_partials.handle_querystring_result()}
            
            <table class="table">
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
                        <td>
                            <span class="label label-default">
                                ${CoverageAssuranceEvent.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>timestamp_created</th>
                        <td><timestamp>${CoverageAssuranceEvent.timestamp_created}</timestamp></td>
                    </tr>
                    <tr>
                        <th>Event Type</th>
                        <td><code>${CoverageAssuranceEvent.coverage_assurance_event_type}</code></td>
                    </tr>
                    <tr>
                        <th>Event Status</th>
                        <td><code>${CoverageAssuranceEvent.coverage_assurance_event_status}</code></td>
                    </tr>
                    <tr>
                        <th>Event Resolution</th>
                        <td>
                            <code>${CoverageAssuranceEvent.coverage_assurance_resolution}</code>
                            % for _option_text in model_websafe.CoverageAssuranceResolution.OPTIONS_ALL:
                                % if _option_text != CoverageAssuranceEvent.coverage_assurance_resolution:
                                    <form
                                        method="POST"
                                        action="${admin_prefix}/coverage-assurance-event/${CoverageAssuranceEvent.id}/mark"
                                        id="form-mark-${_option_text}"
                                    >
                                        <input type="hidden" name="action" value="resolution"/>
                                        <button class="btn btn-xs btn-danger" type="submit" name="resolution" value="${_option_text}">
                                            mark `${_option_text}`
                                        </button>
                                    </form>
                                % endif
                            % endfor
                        </td>
                    </tr>
                    <tr>
                        <th>Private Key</th>
                        <td>
                            % if CoverageAssuranceEvent.private_key_id:
                                <a  class="label label-info"
                                    href="${admin_prefix}/private-key/${CoverageAssuranceEvent.private_key_id}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    PrivateKey-${CoverageAssuranceEvent.private_key_id}</a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>ServerCertificate</th>
                        <td>
                            % if CoverageAssuranceEvent.server_certificate_id:
                                <a  class="label label-info"
                                    href="${admin_prefix}/server-certificate/${CoverageAssuranceEvent.server_certificate_id}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    ServerCertificate-${CoverageAssuranceEvent.server_certificate_id}</a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>QueueCertificate</th>
                        <td>
                            % if CoverageAssuranceEvent.queue_certificate_id:
                                <a  class="label label-info"
                                    href="${admin_prefix}/queue-certificate/${CoverageAssuranceEvent.queue_certificate_id}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    QueueCertificate-${CoverageAssuranceEvent.queue_certificate_id}</a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>Children</th>
                        <td>
                            % if CoverageAssuranceEvent.children__5:
                                ${admin_partials.table_CoverageAssuranceEvents(CoverageAssuranceEvent.children__5)}
                                ${admin_partials.nav_pager("%s/coverage-assurance-event/%s/children" % (admin_prefix, CoverageAssuranceEvent.id))}
                            % endif
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</%block>
