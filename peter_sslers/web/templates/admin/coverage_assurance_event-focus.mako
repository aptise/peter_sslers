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
                        <td><timestamp>${CoverageAssuranceEvent.coverage_assurance_event_type}</timestamp></td>
                    </tr>
                    <tr>
                        <th>Event Status</th>
                        <td><timestamp>${CoverageAssuranceEvent.coverage_assurance_event_status}</timestamp></td>
                    </tr>
                    <tr>
                        <th>Event Resolution</th>
                        <td><timestamp>${CoverageAssuranceEvent.coverage_assurance_event_resolution}</timestamp></td>
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
                </tbody>
            </table>
        </div>
    </div>
</%block>
