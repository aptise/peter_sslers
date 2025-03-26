<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/domains">Domains</a></li>
        <li class="active">Focus [${Domain.id}-${Domain.domain_name}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Domain Focus</h2>
    <%
        operation = request.params.get('operation', None)
    %>
    % if operation in ('nginx_cache_expire', ):
        <%
            result = request.params.get('result', None)
            if result != 'success':
                result = 'result'
            event_id = request.params.get('event.id', None)
        %>
        <div class="alert alert-${result}">
            <p>
                Result of <b>${operation}</b>: ${result}
            </p>
            % if event_id:
                <p>
                    Event ID:
                    <a href="${admin_prefix}/operations/log/item/${event_id}"
                       class="label label-info"
                    >
                        <span class="glyphicon glyphicon-list-alt" aria-hidden="true"></span>
                        ${event_id}
                    </a>
                </p>
            % endif
        </div>
    % endif
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a  class="btn btn-xs btn-info"
            href="${admin_prefix}/domain/${Domain.id}/calendar.json"
            target="_blank"
        >
            <span class="glyphicon glyphicon-calendar" aria-hidden="true"></span>
            calendar.json</a>
        <a  class="btn btn-xs btn-info"
            href="${admin_prefix}/domain/${Domain.id}.json"
        >
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json</a>
    </p>
</%block>



<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            ${admin_partials.handle_querystring_result()}
            
            % if AcmeChallenges_Active:
                <div class="alert alert-danger">
                    This Domain has an ACTIVE challenge. No new Orders/Challenges can be processed for this domain while the existing order is active.
                    <ul class="list list-unstyled">
                        % for AcmeChallenge in AcmeChallenges_Active:
                            <li>
                                <a  class="label label-info"
                                    href="${admin_prefix}/acme-challenge/${AcmeChallenge.id}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeChallenge-${AcmeChallenge.id}
                                </a>
                            </li>
                        % endfor
                    </ul>
                </div>
            % endif

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
                                ${Domain.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>domain_name</th>
                        <td><code>${Domain.domain_name}</code></td>
                    </tr>
                    <tr>
                        <th>registered</th>
                        <td><code>${Domain.registered}</code></td>
                    </tr>
                    <tr>
                        <th>suffix</th>
                        <td><code>${Domain.suffix}</code></td>
                    </tr>
                    <tr>
                        <th>timestamp_created</th>
                        <td><timestamp>${Domain.timestamp_created}</timestamp></td>
                    </tr>
                    <tr>
                        <th>json_config</th>
                        <td>
                            <a  class="btn btn-xs btn-info"
                                href="${admin_prefix}/domain/${Domain.id}/config.json"
                            >
                                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                                config.json</a>
                        </td>
                    </tr>
                    % if request.api_context.application_settings['enable_nginx']:
                        <tr>
                            <th>Nginx cache</th>
                            <td>
                                <span class="btn-group">
                                    <form action="${admin_prefix}/domain/${Domain.id}/nginx-cache-expire" method="POST">
                                        <button class="btn btn-xs btn-primary" type="submit"  name="submit" value="submit">
                                            <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                            nginx-cache-expire
                                        </button>
                                    </form>
                                    <a  class="btn btn-xs btn-primary"
                                        href="${admin_prefix}/domain/${Domain.id}/nginx-cache-expire.json"
                                        target="_blank"
                                    >
                                        <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                        .json</a>
                                </span<
                            </td>
                        </tr>
                    % endif
                    <tr>
                        <th>AcmeDnsConfigurations</th>
                        <td>
                            ${admin_partials.table_AcmeDnsServerAccounts5_via_Domain(Domain)}
                        </td>
                    </tr>
                    <tr>
                        <th>New Certificate</th>
                        <td>
                            <a  class="btn btn-xs btn-primary"
                                href="${admin_prefix}/acme-order/new/freeform?domain_names_http01=${Domain.domain_name}"
                            >
                                <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                ACME Order - New</a>
                        </td>
                    </tr>
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
                        <th>CertificateSigneds Recent</th>
                        <td>
                            <table class="table table-striped table-condensed">
                                <tr>
                                    <th>latest_single</th>
                                    <td>
                                        % if Domain.certificate_signed_id__latest_single:
                                            ${admin_partials.table_CertificateSigneds([Domain.certificate_signed__latest_single,], show_domains=True, show_expiring_days=True)}
                                        % endif
                                    </td>
                                </tr>
                                <tr>
                                    <th>latest_multi</th>
                                    <td>
                                        % if Domain.certificate_signed_id__latest_multi:
                                            ${admin_partials.table_CertificateSigneds([Domain.certificate_signed__latest_multi,], show_domains=True, show_expiring_days=True)}
                                        % endif
                                    </td>
                                </tr>
                            </table>

                            <form method="POST" id="form-update-recents" action="${admin_prefix}/domain/${Domain.id}/update-recents">
                                <button class="btn btn-xs btn-primary">
                                    <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                    Update Recents
                                </button>
                            </form>

                        </td>
                    </tr>
                    <tr>
                        <th>RenewalConfigurations</th>
                        <td>
                            ${admin_partials.table_RenewalConfigurations(Domain.renewal_configurations__5, perspective="Domain")}
                            % if Domain.renewal_configurations__5:
                                ${admin_partials.nav_pager("%s/domain/%s/renewal-configurations" % (admin_prefix, Domain.id))}
                            % endif
                        </td>
                    </tr>

                    <tr>
                        <th>UniquelyChallengedFQDNSets</th>
                        <td>
                            ${admin_partials.table_UniquelyChallengedFQDNSets([i.uniquely_challenged_fqdn_set for i in Domain.to_uniquely_challenged_fqdn_sets__5], perspective="Domain")}
                            % if Domain.to_unique_fqdn_sets__5:
                                ${admin_partials.nav_pager("%s/domain/%s/uniquely-challenged-fqdn-sets" % (admin_prefix, Domain.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>UniqueFQDNSets</th>
                        <td>
                            ${admin_partials.table_UniqueFQDNSets([i.unique_fqdn_set for i in Domain.to_unique_fqdn_sets__5], perspective="Domain")}
                            % if Domain.to_unique_fqdn_sets__5:
                                ${admin_partials.nav_pager("%s/domain/%s/unique-fqdn-sets" % (admin_prefix, Domain.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>CertificateSigneds ALL</th>
                        <td>
                            % if Domain.certificate_signeds__5:
                            ${admin_partials.table_CertificateSigneds(Domain.certificate_signeds__5, show_domains=True, show_expiring_days=True)}
                            % else:
                                No ACTIVE recents; inactive items will not appear on this view.
                            % endif
                            ${admin_partials.nav_pager("%s/domain/%s/certificate-signeds" % (admin_prefix, Domain.id))}
                        </td>
                    </tr>
                    <tr>
                        <th>CertificateSigneds Single Primary</th>
                        <td>
                            % if Domain.certificate_signeds__single_primary_5:
                            ${admin_partials.table_CertificateSigneds(Domain.certificate_signeds__single_primary_5, show_domains=True, show_expiring_days=True)}
                            % else:
                                No ACTIVE recents; inactive items will not appear on this view.
                            % endif
                            ${admin_partials.nav_pager("%s/domain/%s/certificate-signeds" % (admin_prefix, Domain.id))}
                        </td>
                    </tr>
                    <tr>
                        <th>CertificateSigneds Single Backup</th>
                        <td>
                            % if Domain.certificate_signeds__single_backup_5:
                            ${admin_partials.table_CertificateSigneds(Domain.certificate_signeds__single_backup_5, show_domains=True, show_expiring_days=True)}
                            % else:
                                No ACTIVE recents; inactive items will not appear on this view.
                            % endif
                            ${admin_partials.nav_pager("%s/domain/%s/certificate-signeds" % (admin_prefix, Domain.id))}
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeOrders</th>
                        <td>
                            ${admin_partials.table_AcmeOrders(Domain.acme_orders__5, perspective="Domain")}
                            % if Domain.acme_orders__5:
                                ${admin_partials.nav_pager("%s/domain/%s/acme-orders" % (admin_prefix, Domain.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeAuthorizations</th>
                        <td>
                            ${admin_partials.table_AcmeAuthorizations(Domain.acme_authorizations__5, perspective="Domain")}
                            % if Domain.acme_authorizations__5:
                                ${admin_partials.nav_pager("%s/domain/%s/acme-authorizations" % (admin_prefix, Domain.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeAuthorizationPotentials</th>
                        <td>
                            ${admin_partials.table_AcmeAuthorizationPotentials(Domain.acme_authorization_potentials__5, perspective="Domain")}
                            % if Domain.acme_authorization_potentials__5:
                                ${admin_partials.nav_pager("%s/domain/%s/acme-authz-potentials" % (admin_prefix, Domain.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeChallenges</th>
                        <td>
                            ${admin_partials.table_AcmeChallenges(Domain.acme_challenges__5, perspective="Domain")}
                            % if Domain.acme_challenges__5:
                                ${admin_partials.nav_pager("%s/domain/%s/acme-challenges" % (admin_prefix, Domain.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>CertificateRequests</th>
                        <td>
                            ${admin_partials.table_CertificateRequests(Domain.certificate_requests__5, perspective="Domain")}
                            % if Domain.certificate_requests__5:
                                ${admin_partials.nav_pager("%s/domain/%s/certificate-requests" % (admin_prefix, Domain.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>DomainAutocerts</th>
                        <td>
                            ${admin_partials.table_DomainAutocerts(Domain.domain_autocerts__5, perspective="Domain")}
                            % if Domain.domain_autocerts__5:
                                ${admin_partials.nav_pager("%s/domain/%s/domain-autocerts" % (admin_prefix, Domain.id))}
                            % endif
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</%block>
