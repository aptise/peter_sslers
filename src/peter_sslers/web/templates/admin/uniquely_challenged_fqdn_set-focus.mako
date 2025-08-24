<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/uniquely-challenged-fqdn-sets">Uniquely Challenged FQDN Sets</a></li>
        <li class="active">Focus [${UniquelyChallengedFQDNSet.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Uniquely Challenged FQDN Set: Focus</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/uniquely-challenged-fqdn-set/${UniquelyChallengedFQDNSet.id}.json" class="btn btn-xs btn-info">
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
                                ${UniquelyChallengedFQDNSet.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>first seen</th>
                        <td>
                            <timestamp>
                                ${UniquelyChallengedFQDNSet.timestamp_created}
                            </timestamp>
                        </td>
                    </tr>
                    <tr>
                        <th>domain_challenges_serialized</th>
                        <td>
                            <code>
                                ${UniquelyChallengedFQDNSet.domain_challenges_serialized}
                            </code>
                        </td>
                    </tr>
                    <tr>
                        <th>domain_names</th>
                        <td>
                            <code>
                                ${UniquelyChallengedFQDNSet.domain_names}
                            </code>
                        </td>
                    </tr>
                    <tr>
                        <th>unique_fqdn_set</th>
                        <td>
                            <a  class="label label-info"
                                href="${admin_prefix}/unique-fqdn-set/${UniquelyChallengedFQDNSet.unique_fqdn_set_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                UniqueFQDNSet-${UniquelyChallengedFQDNSet.unique_fqdn_set_id}
                            </a>
                        </td>

                    <tr>
                        <th>Domains</th>
                        <td>
                            <table class="table table-striped table-condensed">
                                <tr>
                                    <th>Domain</th>
                                    <th>Challenge Type</th>
                                    <th>Integrations?</th>
                                </tr>
                                % for to_domain in UniquelyChallengedFQDNSet.to_domains:
                                    <tr>
                                        <td>
                                            <a href="${admin_prefix}/domain/${to_domain.domain_id}"
                                             class="label label-info"
                                            >
                                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                Domain-${to_domain.domain_id}
                                            </a>
                                            <code>${to_domain.domain.domain_name}</code>
                                        </td>
                                        <td>
                                            <span class="label label-default">
                                                ${to_domain.acme_challenge_type}
                                            </span>
                                        </td>
                                        <td>
                                            % if to_domain.acme_challenge_type == "dns-01":
                                            ${admin_partials.table_AcmeDnsServerAccounts5_via_Domain(to_domain.domain)}
                                            % endif
                                        </td>
                                    </tr>
                                % endfor
                            </table>
                        </td>
                    </tr>




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
                        <th>ACME Orders</th>
                        <td>
                            ${admin_partials.table_AcmeOrders(UniquelyChallengedFQDNSet.acme_orders__5, perspective="UniquelyChallengedFQDNSet")}
                            % if UniquelyChallengedFQDNSet.acme_orders__5:
                                ${admin_partials.nav_pager("%s/uniquely-challenged-fqdn-set/%s/acme-orders" % (admin_prefix, UniquelyChallengedFQDNSet.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>Certificates Signed</th>
                        <td>
                            ${admin_partials.table_X509Certificates(UniquelyChallengedFQDNSet.x509_certificates__5, perspective="UniquelyChallengedFQDNSet")}
                            % if UniquelyChallengedFQDNSet.x509_certificates__5:
                                ${admin_partials.nav_pager("%s/uniquely-challenged-fqdn-set/%s/certificates-signed" % (admin_prefix, UniquelyChallengedFQDNSet.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>Renewal Configurations</th>
                        <td>
                            ${admin_partials.table_RenewalConfigurations(UniquelyChallengedFQDNSet.renewal_configurations__5, perspective="UniquelyChallengedFQDNSet")}
                            % if UniquelyChallengedFQDNSet.renewal_configurations__5:
                                ${admin_partials.nav_pager("%s/uniquely-challenged-fqdn-set/%s/acme-orders" % (admin_prefix, UniquelyChallengedFQDNSet.id))}
                            % endif
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</%block>
