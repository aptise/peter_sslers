<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Coverage Assurance Events</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Coverage Assurance Events</h2>
</%block>


<%block name="page_header_nav">
    <ul class="nav nav-pills nav-stacked">
      <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="${admin_prefix}/coverage-assurance-events/all">All</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'unresolved' else ''}"><a href="${admin_prefix}/coverage-assurance-events/unresolved">Unresolved</a></li>
    </ul>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if CoverageAssuranceEvents:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>timestamp created</th>
                            <th>Event Type</th>
                            <th>Event Status</th>
                            <th>Resolution</th>
                            <th>Private Key</th>
                            <th>Server Certificate</th>
                        </tr>
                    </thead>
                    % for cae in CoverageAssuranceEvents:
                        <tr>
                            <td>
                                <a  class="label label-info"
                                    href="${admin_prefix}/coverage-assurance-event/${cae.id}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    CoverageAssuranceEvent-${cae.id}</a>
                            </td>
                            <td><code>${cae.coverage_assurance_event_type}</code></td>
                            <td><code>${cae.coverage_assurance_event_status}</code></td>
                            <td><code>${cae.coverage_assurance_event_resolution}</code></td>
                            <td>
                                % if cae.private_key_id:
                                    <a  class="label label-info"
                                        href="${admin_prefix}/private-key/${cae.private_key_id}"
                                    >
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        PrivateKey-${cae.private_key_id}</a>
                                % endif
                            </td>
                            <td>
                                % if cae.server_certificate_id:
                                    <a  class="label label-info"
                                        href="${admin_prefix}/server-certificate/${cae.server_certificate_id}"
                                    >
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        ServerCertificate-${cae.server_certificate_id}</a>
                                % endif
                            </td>
                        </tr>
                    % endfor
                </table>
            % else:
                <em>
                    No CoverageAssuranceEvents
                </em>
            % endif
            </div>
        </div>
    </div>
</%block>
