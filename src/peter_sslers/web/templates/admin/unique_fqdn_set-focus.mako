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
                                ${UniqueFQDNSet.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>first seen</th>
                        <td>
                            <timestamp>
                                ${UniqueFQDNSet.timestamp_created}
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
                        <th>count_domains</th>
                        <td>
                            <code>
                                ${UniqueFQDNSet.count_domains}
                            </code>
                        </td>
                    </tr>
                    <tr>
                        <th></th>
                        <td>
                            <form method="POST" id="form-update-recents" action="${admin_prefix}/unique-fqdn-set/${UniqueFQDNSet.id}/update-recents">
                                <button class="btn btn-xs btn-primary">
                                    <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                    Update Recents
                                </button>
                            </form>
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
                                        <td><code>${to_domain.domain.domain_name}</code></td>
                                    </tr>
                                % endfor
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <th>Modify?</th>
                        <td>
                            &nbsp;
                            <a  class="btn btn-xs btn-primary"
                                href="${admin_prefix}/unique-fqdn-set/${UniqueFQDNSet.id}/modify"
                                title="Modify this UniqueFQDNSet"
                            >
                                <span class="glyphicon glyphicon-pencil" aria-hidden="true"></span>
                                Modify this UniqueFQDNSet
                            </a>
                            &nbsp;
                            Modifying will create A NEW UniqueFQDNSet.
                        </td>
                    </tr>
                    ${admin_partials.table_tr_OperationsEventCreated(UniqueFQDNSet)}
                </tbody>
                <thead>
                    <tr>
                        <th colspan="2">
                        <hr/>
                        </th>
                    </tr>
                    <tr>
                        <th colspan="2">
                            Relations Library
                        </th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <th>Latest X509Certificates</th>
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
                                                    href="${admin_prefix}/x509-certificate/${latest_certificate.id}"
                                                >
                                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                    X509Certificate-${latest_certificate.id}
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
                                                    href="${admin_prefix}/x509-certificate/${latest_active_certificate.id}"
                                                >
                                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                    X509Certificate-${latest_active_certificate.id}
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
                        <th>X509Certificates</th>
                        <td>
                            ${admin_partials.table_X509Certificates(UniqueFQDNSet.x509_certificates__5, show_domains=False, show_days_to_expiry=True)}
                            % if UniqueFQDNSet.x509_certificates__5:
                                ${admin_partials.nav_pager("%s/unique-fqdn-set/%s/x509-certificates" % (admin_prefix, UniqueFQDNSet.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>ACME Orders</th>
                        <td>
                            ${admin_partials.table_AcmeOrders(UniqueFQDNSet.acme_orders__5, perspective="UniqueFQDNSet")}
                            % if UniqueFQDNSet.acme_orders__5:
                                ${admin_partials.nav_pager("%s/unique-fqdn-set/%s/acme-orders" % (admin_prefix, UniqueFQDNSet.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>X509CertificateRequests</th>
                        <td>
                            ${admin_partials.table_X509CertificateRequests(UniqueFQDNSet.x509_certificate_requests__5, perspective="UniqueFQDNSet")}
                            % if UniqueFQDNSet.x509_certificate_requests__5:
                                ${admin_partials.nav_pager("%s/unique-fqdn-set/%s/x509-certificate-requests" % (admin_prefix, UniqueFQDNSet.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>UniquelyChallengedFQDNSets</th>
                        <td>
                            ${admin_partials.table_UniquelyChallengedFQDNSets(UniqueFQDNSet.uniquely_challenged_fqdn_sets__5, perspective="UniqueFQDNSet")}
                            % if UniqueFQDNSet.uniquely_challenged_fqdn_sets__5:
                                ${admin_partials.nav_pager("%s/unique-fqdn-set/%s/uniquely-challenged-fqdn-sets" % (admin_prefix, UniqueFQDNSet.id))}
                            % endif
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</%block>
