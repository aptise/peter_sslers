<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/unique-fqdn-sets">Unique FQDN Sets</a></li>
        <li class="active">Focus</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Unique FQDN Set: Focus</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a  class="btn btn-info btn-xs"
            href="${admin_prefix}/unique-fqdn-set/${UniqueFQDNSet.id}/calendar.json"
        >
            <span class="glyphicon glyphicon-calendar" aria-hidden="true"></span>
            calendar.json
        </a>
        <a href="${admin_prefix}/unique-fqdn-set/${UniqueFQDNSet.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            ${admin_partials.handle_querystring_result()}
            <table class="table table-striped table-condensed">
                <tbody>
                    <tr>
                        <th>id</th>
                        <td>
                            <span class="label label-default">
                                ${UniqueFQDNSet.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>first seen</th>
                        <td>
                            <timestamp>
                                ${UniqueFQDNSet.timestamp_first_seen}
                            </timestamp>
                        </td>
                    </tr>
                    <tr>
                        <th>domain_ids_string</th>
                        <td>
                            <code>
                                ${UniqueFQDNSet.domain_ids_string}
                            </code>
                        </td>
                    </tr>
                    <tr>
                        <th>domains</th>
                        <td>
                            <table class="table table-striped table-condensed">
                                % for to_domain in UniqueFQDNSet.to_domains:
                                    <tr>
                                        <td>
                                            <a  class="label label-info"
                                                href="${admin_prefix}/domain/${to_domain.domain.id}"
                                            >
                                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                Domain-${to_domain.domain.id}
                                            </a>
                                        </td>
                                        <td>
                                            <span class="label label-${'success' if to_domain.domain.is_active else 'warning'}">
                                                ${'Active' if to_domain.domain.is_active else 'inactive'}
                                            </span>
                                        </td>
                                        <td><code>${to_domain.domain.domain_name}</code></td>
                                    </tr>
                                % endfor
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <th>Renew?</th>
                        <td>
                            &nbsp;
                            <a  class="btn btn-xs btn-primary"
                                href="${admin_prefix}/unique-fqdn-set/${UniqueFQDNSet.id}/renew/queue"
                                title="Queue a renewal with the system defaults."
                            >
                                <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                queue a renewal with system defaults
                            </a>

                        </td>
                    </tr>
                    ${admin_partials.table_tr_event_created(UniqueFQDNSet)}
                    <tr>
                        <th>Latest Certificates</th>
                        <td>
                <%
                    latest_certificate = UniqueFQDNSet.latest_certificate
                    latest_active_certificate = UniqueFQDNSet.latest_active_certificate
                %>
                <table class="table table-striped table-condensed">
                    <thead>
                        <tr>
                            <th>Cert</th>
                            <th>id</th>
                            <th>is active?</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <th>Latest Certificate</th>
                            % if latest_certificate:
                                <td>
                                    <a  class="label label-info"
                                        href="${admin_prefix}/certificate/${latest_certificate.id}"
                                    >
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        cert-${latest_certificate.id}
                                    </a>
                                </td>
                                <td>
                                    <span class="label label-${'success' if latest_certificate.is_active else 'warning'}">
                                        ${'Active' if latest_certificate.is_active else 'inactive'}
                                    </span>
                                </td>
                            % endif
                        </tr>
                        <tr>
                            <th>Latest Active Certificate</th>
                            % if latest_active_certificate:
                                <td>
                                    <a  class="label label-info"
                                        href="${admin_prefix}/certificate/${latest_active_certificate.id}"
                                    >
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        cert-${latest_active_certificate.id}
                                    </a>
                                </td>
                                <td>
                                    <span class="label label-${'success' if latest_active_certificate.is_active else 'warning'}">
                                        ${'Active' if latest_active_certificate.is_active else 'inactive'}
                                    </span>
                                </td>
                            % endif
                        </tr>
                    </tbody>
                </table>
                        </td>
                    </tr>
                    <tr>
                        <th>Certificates</th>
                        <td>
                            ${admin_partials.table_certificates__list(UniqueFQDNSet.server_certificates__5, show_domains=False, show_expiring_days=True)}
                            % if UniqueFQDNSet.server_certificates__5:
                                ${admin_partials.nav_pager("%s/unique-fqdn-set/%s/certificates" % (admin_prefix, UniqueFQDNSet.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>CertificateRequests</th>
                        <td>
                            ${admin_partials.table_certificate_requests__list(UniqueFQDNSet.certificate_requests__5)}
                            % if UniqueFQDNSet.certificate_requests__5:
                                ${admin_partials.nav_pager("%s/unique-fqdn-set/%s/certificate-requests" % (admin_prefix, UniqueFQDNSet.id))}
                            % endif
                        </td>
                    </tr>
                    % if False:
                        <tr>
                            <th>Queue: Renewals</th>
                            <td>
                                ${admin_partials.table_queue_renewal__list(UniqueFQDNSet.queue_renewal__active, show_certificate=True)}
                            </td>
                        </tr>
                    % endif
                </tbody>
            </table>
        </div>
    </div>
</%block>
