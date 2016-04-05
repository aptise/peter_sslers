<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li><a href="/.well-known/admin/unique-fqdn-sets">Unique FQDN Sets</a></li>
        <li class="active">Focus</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Unique FQDN Set: Focus</h2>
</%block>
    

<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            <table class="table table-striped table-condensed">
                <tbody>
                    <tr>
                        <th>id</th>
                        <td>
                            <span class="label label-default">
                                ${LetsencryptUniqueFQDNSet.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>first seen</th>
                        <td>
                            <timestamp>
                                ${LetsencryptUniqueFQDNSet.timestamp_first_seen}
                            </timestamp>
                        </td>
                    </tr>
                    <tr>
                        <th>domain_ids_string</th>
                        <td>
                            <code>
                                ${LetsencryptUniqueFQDNSet.domain_ids_string}
                            </code>
                        </td>
                    </tr>
                    <tr>
                        <th>domains</th>
                        <td>
                            <table class="table table-striped table-condensed">
                                % for to_domain in LetsencryptUniqueFQDNSet.to_domains:
                                    <tr>
                                        <td>
                                            <a  class="btn btn-xs btn-info"
                                                href="/.well-known/admin/domain/${to_domain.domain.id}"
                                            >
                                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                ${to_domain.domain.id}
                                            </a>
                                        </td>
                                        <td>
                                            <span class="label label-${'success' if to_domain.domain.is_active else 'warning'}">
                                                ${'Active' if to_domain.domain.is_active else 'inactive'}
                                            </span>
                                        </td>
                                        <td>${to_domain.domain.domain_name}</td>
                                    </tr>
                                % endfor
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <td>Latest Certificates</td>
                        <td>
                <%
                    latest_certificate = LetsencryptUniqueFQDNSet.latest_certificate
                    latest_active_certificate = LetsencryptUniqueFQDNSet.latest_active_certificate
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
                                        href="/.well-known/admin/certificate/${latest_certificate.id}"
                                        >
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        ${latest_certificate.id}
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
                                        href="/.well-known/admin/certificate/${latest_active_certificate.id}"
                                        >
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        ${latest_active_certificate.id}
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
                        <th>certificates history</th>
                        <td>
                            ${admin_partials.table_certificates__list(LetsencryptUniqueFQDNSet.signed_certificates_5, show_domains=True, show_expiring_days=True)}
                            % if LetsencryptUniqueFQDNSet.signed_certificates_5:
                                ${admin_partials.nav_pager("/.well-known/admin/unique-fqdn-set/%s/certificates" % LetsencryptUniqueFQDNSet.id)}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>certificate requests</th>
                        <td>
                            ${admin_partials.table_certificate_requests__list(LetsencryptUniqueFQDNSet.certificate_requests_5)}
                            % if LetsencryptUniqueFQDNSet.certificate_requests_5:
                                ${admin_partials.nav_pager("/.well-known/admin/unique-fqdn-set/%s/certificate-requests" % LetsencryptUniqueFQDNSet.id)}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>renewal queue</th>
                        <td>
                            ${admin_partials.table_renewal_queue__list(LetsencryptUniqueFQDNSet.renewal_queue, show_certificate=True)}
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
        <div class="col-sm-3">
            <a  class="btn btn-info"
                href="/.well-known/admin/unique-fqdn-set/${LetsencryptUniqueFQDNSet.id}/calendar"
            >
                Calendar
            </a>
        </div>
    </div>
</%block>
