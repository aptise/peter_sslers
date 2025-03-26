<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/renewal-configurations/all">Renewal Configuration</a></li>
        <li class="active">Focus: ${RenewalConfiguration.id}</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Renewal Configuration | Focus: ${RenewalConfiguration.id}</h2>
    
    ${admin_partials.handle_querystring_result()}
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/renewal-configuration/${RenewalConfiguration.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-file-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-6">

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
                                ${RenewalConfiguration.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>label</th>
                        <td><code>${RenewalConfiguration.label or ''}</code></td>
                    </tr>
                    <tr>
                        <th>timestamp_created</th>
                        <td><timestamp>${RenewalConfiguration.timestamp_created or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>acme_profile__primary</th>
                        <td><code>${RenewalConfiguration.acme_profile__primary or ''}</code></td>
                    </tr>
                    <tr>
                        <th>acme_profile__backup</th>
                        <td><code>${RenewalConfiguration.acme_profile__backup or ''}</code></td>
                    </tr>
                    <tr>
                        <th>is_active</th>
                        <td>
                            <code>${RenewalConfiguration.is_active or ''}</code>


                            % if not RenewalConfiguration.is_active:
                                <form action="${admin_prefix}/renewal-configuration/${RenewalConfiguration.id}/mark" method="POST" style="display:inline;" id="form-renewal_configuration-mark-active">
                                    <input type="hidden" name="action" value="active"/>
                                    <button class="btn btn-xs btn-success" type="submit">
                                        <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                        Activate
                                    </button>
                                </form>
                            % else:
                                <form action="${admin_prefix}/renewal-configuration/${RenewalConfiguration.id}/mark" method="POST" style="display:inline;" id="form-renewal_configuration-mark-inactive">
                                    <input type="hidden" name="action" value="inactive"/>
                                    <button class="btn btn-xs btn-danger" type="submit">
                                        <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                        Deactivate
                                    </button>
                                </form>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>private_key_cycle__primary</th>
                        <td>
                            <code>${RenewalConfiguration.private_key_cycle__primary}</code>
                            % if RenewalConfiguration.private_key_cycle__primary == "account_default":
                                <span class="label label-default">
                                    [${RenewalConfiguration.private_key_cycle__primary__effective}]
                                </span>
                            % endif
                            % if RenewalConfiguration.private_key_cycle__primary == "single_use__reuse_1_year" or RenewalConfiguration.private_key_cycle__primary__effective == "single_use__reuse_1_year":
                                % if RenewalConfiguration.private_key_reuse:
                                    <a  class="btn btn-xs btn-primary"
                                        href="${admin_prefix}/private-key/${RenewalConfiguration.private_key_reuse.id}"
                                    >
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        PrivateKey-${RenewalConfiguration.private_key_reuse.id}
                                    </a>
                                % else:
                                    No PrivateKey
                                % endif
                            
                            % endif
                            
                        </td>
                    </tr>
                    <tr>
                        <th>key_technology</th>
                        <td><code>${RenewalConfiguration.private_key_technology__primary}</code>
                            % if RenewalConfiguration.private_key_technology__primary == "account_default":
                                <span class="label label-default">
                                    [${RenewalConfiguration.private_key_technology__primary__effective}]
                                </span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>acme_account__primary</th>
                        <td>
                            <a  class="label label-info"
                                href="${admin_prefix}/acme-account/${RenewalConfiguration.acme_account_id__primary}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeAccount-${RenewalConfiguration.acme_account_id__primary}
                            </a>
                            <span class="label label-default">
                                ${RenewalConfiguration.acme_account__primary.acme_server.name}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>acme_account__backup</th>
                        <td>
                            % if RenewalConfiguration.acme_account_id__backup:
                                <a  class="label label-info"
                                    href="${admin_prefix}/acme-account/${RenewalConfiguration.acme_account_id__backup}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeAccount-${RenewalConfiguration.acme_account_id__backup}
                                </a>
                                <span class="label label-default">
                                    ${RenewalConfiguration.acme_account__backup.acme_server.name}
                                </span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>unique_fqdn_set</th>
                        <td>
                            <a  class="label label-info"
                                href="${admin_prefix}/unique-fqdn-set/${RenewalConfiguration.unique_fqdn_set_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                UniqueFQDNSet-${RenewalConfiguration.unique_fqdn_set_id}
                            </a>
                            <br/>
                            <code>${', '.join(RenewalConfiguration.domains_as_list)}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>uniquely_challenged_fqdn_set</th>
                        <td>
                            <a  class="label label-info"
                                href="${admin_prefix}/uniquely-challenged-fqdn-set/${RenewalConfiguration.uniquely_challenged_fqdn_set_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                UniquelyChallengedFQDNSet-${RenewalConfiguration.uniquely_challenged_fqdn_set_id}
                            </a>
                            <br/>
                            <code>${RenewalConfiguration.uniquely_challenged_fqdn_set.domain_names}</code>


                            % if RenewalConfiguration.uniquely_challenged_fqdn_set.to_domains__dns_01:
                                <hr/>
                                DNS-01 Domains
                                
                                <table class="table table-striped tabled-condensed">
                                    <tr>
                                        <th>domain</th>
                                        <th>AcmeDNSServerAccounts</th>
                                    </tr>
                                    % for to_domain in RenewalConfiguration.uniquely_challenged_fqdn_set.to_domains__dns_01:
                                        <tr>
                                            <td>
                                                <a
                                                    href="${admin_prefix}/domain/${to_domain.domain.id}"
                                                    class="label label-info">
                                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                    ${to_domain.domain.id}
                                                </a>
                                                <span class="label label-default">
                                                    ${to_domain.domain.domain_name}
                                                </span>
                                            </td>
                                            <td>
                                                ${admin_partials.table_AcmeDnsServerAccounts5_via_Domain(to_domain.domain)}
                                            </td>
                                        </tr>
                                    % endfor
                                </table>
                            
                            % endif


                        </td>
                    </tr>

                    <tr>
                        <th></th>
                        <td>
                            <a  class="btn btn-xs btn-primary"
                                href="${admin_prefix}/renewal-configuration/${RenewalConfiguration.id}/new-order"
                                title="Renew immediately."
                            >
                                <span class="glyphicon glyphicon-fast-forward" aria-hidden="true"></span>
                                New Order
                            </a>

                            <a  class="btn btn-xs btn-primary"
                                href="${admin_prefix}/renewal-configuration/${RenewalConfiguration.id}/new-configuration"
                                title="New Renewal Configuration"
                            >
                                <span class="glyphicon glyphicon-wrench" aria-hidden="true"></span>
                                New Renewal Configuration
                            </a>
                        </td>
                    </tr>
                    <tr>
                        <th>is_save_alternate_chains</th>
                        <td><code>${RenewalConfiguration.is_save_alternate_chains or ''}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>note</th>
                        <td><code>${RenewalConfiguration.note or ''}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>is_export_filesystem</th>
                        <td><code>${RenewalConfiguration.is_export_filesystem}</code>
                            % if not RenewalConfiguration.enrollment_factory_id__via:
                                % if RenewalConfiguration.is_export_filesystem == "off":
                                    <form action="${admin_prefix}/renewal-configuration/${RenewalConfiguration.id}/mark" method="POST" style="display:inline;" id="form-renewal_configuration-mark-export_on">
                                        <input type="hidden" name="action" value="is_export_filesystem-on"/>
                                        <button class="btn btn-xs btn-success" type="submit">
                                            <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                            On
                                        </button>
                                    </form>
                                % else:
                                    <form action="${admin_prefix}/renewal-configuration/${RenewalConfiguration.id}/mark" method="POST" style="display:inline;" id="form-renewal_configuration-mark-export_off">
                                        <input type="hidden" name="action" value="is_export_filesystem-off"/>
                                        <button class="btn btn-xs btn-danger" type="submit">
                                            <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                            Off
                                        </button>
                                    </form>
                                % endif
                            % endif
                        </td>
                    </tr>

                    <tr>
                        <th>enrollment_factory__via</th>
                        <td>
                            % if RenewalConfiguration.enrollment_factory_id__via:
                            <a href="${admin_prefix}/enrollment-factory/${RenewalConfiguration.enrollment_factory_id__via}"
                                title="EnrollmentFactory"
                                class="label label-info"
                            >
                                <span class="glyphicon glyphicon-wrench" aria-hidden="true"></span>
                                EnrollmentFactory-${RenewalConfiguration.enrollment_factory_id__via}
                            </a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>system_configuration__via</th>
                        <td>
                            % if RenewalConfiguration.system_configuration_id__via:
                            <a href="${admin_prefix}/system-configuration/${RenewalConfiguration.system_configuration_id__via}"
                                title="SystemConfiguration"
                                class="label label-info"
                            >
                                <span class="glyphicon glyphicon-wrench" aria-hidden="true"></span>
                                SystemConfiguration-${RenewalConfiguration.system_configuration_id__via}
                            </a>
                            % endif
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
                        <th>CertificateSigneds - ALL</th>
                        <td>
                            ${admin_partials.table_CertificateSigneds(RenewalConfiguration.certificate_signeds__5, perspective='RenewalConfiguration')}
                            % if RenewalConfiguration.certificate_signeds__5:
                                ${admin_partials.nav_pager("%s/renewal-configuration/%s/certificate-signeds" % (admin_prefix, RenewalConfiguration.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>CertificateSigneds - Primary</th>
                        <td>
                            ${admin_partials.table_CertificateSigneds(RenewalConfiguration.certificate_signeds__primary__5, perspective='RenewalConfiguration')}
                        </td>
                    </tr>
                    <tr>
                        <th>CertificateSigneds - Backup</th>
                        <td>
                            ${admin_partials.table_CertificateSigneds(RenewalConfiguration.certificate_signeds__backup__5, perspective='RenewalConfiguration')}
                        </td>
                    </tr>
                    <tr>
                        <th>Certificate Lineages</th>
                        <td>
                            <a href="${admin_prefix}/renewal-configuration/${RenewalConfiguration.id}/lineages"
                                title="Lineages"
                                class="label label-info"
                            >
                                <span class="glyphicon glyphicon-wrench" aria-hidden="true"></span>
                                Calculate Lineages
                            </a>                            
                        </td>
                    </tr>
                </tbody>
                <tbody>
                    <tr>
                        <th>ACME Orders</th>
                        <td>
                            ${admin_partials.table_AcmeOrders(RenewalConfiguration.acme_orders__5, perspective='RenewalConfiguration')}
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</%block>
