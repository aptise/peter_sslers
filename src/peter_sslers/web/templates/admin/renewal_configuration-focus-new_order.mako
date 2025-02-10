<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/renewal-configurations">RenewalConfiguration</a></li>
        <li><a href="${admin_prefix}/renewal-configuration/${RenewalConfiguration.id}">Focus [${RenewalConfiguration.id}]</a></li>
        <li class="active">New Order</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>RenewalConfiguration - Focus ${RenewalConfiguration.id} - New Order</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/renewal-configuration/${RenewalConfiguration.id}/new-order.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    ${admin_partials.handle_querystring_result()}
    <div class="row">
        <div class="col-sm-12">

            <h4>Renew the following?</h4>

            <form action="${admin_prefix}/renewal-configuration/${RenewalConfiguration.id}/new-order" method="POST" style="display:inline;"
                id="form-renewal_configuration-new_order"
            >

            <table class="table table-striped table-condensed">
                <tbody>
                    <tr>
                        <th>id</th>
                        <td>
                            <span class="label label-default">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ${RenewalConfiguration.id}
                            </span>
                        </td>
                        <td></td>
                    </tr>
                    <tr>
                        <th>AcmeAccount</th>
                        <td>
                            <a
                                class="label label-info"
                                href="${admin_prefix}/acme-account/${RenewalConfiguration.acme_account_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeAccount-${RenewalConfiguration.acme_account_id}
                            </a>
                            <a
                                class="label label-info"
                                href="${admin_prefix}/acme-server/${RenewalConfiguration.acme_account.acme_server_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeServer-${RenewalConfiguration.acme_account.acme_server_id}
                                |
                                ${RenewalConfiguration.acme_account.acme_server.server}
                            </a>
                        </td>
                        <td><code>${RenewalConfiguration.acme_account.acme_account_key.key_pem_sample}</code></td>
                    </tr>
                    <tr>
                        <th>PrivateKey</th>
                        <td>
                        </td>
                    </tr>
                    <tr>
                        <th>UniqueFQDNSet</th>
                        <td>
                            <a
                                class="label label-info"
                                href="${admin_prefix}/unique-fqdn-set/${RenewalConfiguration.unique_fqdn_set_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                UniqueFQDNSet-${RenewalConfiguration.unique_fqdn_set_id}
                            </a>
                        </td>
                        <td>
                            <code>${', '.join(RenewalConfiguration.domains_as_list)}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>UniquelyChallengedFQDNSet</th>
                        <td>
                            <a
                                class="label label-info"
                                href="${admin_prefix}/uniquely-challenged-fqdn-set/${RenewalConfiguration.uniquely_challenged_fqdn_set_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                UniquelyChallengedFQDNSet-${RenewalConfiguration.uniquely_challenged_fqdn_set_id}
                            </a>
                        </td>
                        <td>
                            <code>${RenewalConfiguration.uniquely_challenged_fqdn_set.domain_names}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>private_key_cycle</th>
                        <td>
                            <code>${RenewalConfiguration.private_key_cycle}</code>
                            % if RenewalConfiguration.private_key_cycle == "account_default":
                                <span class="label label-default">
                                    AcmeAccount[${RenewalConfiguration.acme_account.order_default_private_key_cycle}]
                                </span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>key_technology</th>
                        <td><code>${RenewalConfiguration.key_technology}</code>
                            % if RenewalConfiguration.private_key_cycle == "account_default":
                                <span class="label label-default">
                                    AcmeAccount[${RenewalConfiguration.acme_account.order_default_private_key_technology}]
                                </span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>replaces</th>
                        <td>
                            <%
                                intended_replacement = request.params.get("replaces.id")
                                if intended_replacement:
                                    intended_replacement = int(intended_replacement)
                                _selected = ""
                                if not CertificateSigned_replaces_candidates:
                                    _selected = ' checked="checked"'
                                else:
                                    _candidate_ids = [i.id for i in CertificateSigned_replaces_candidates]
                                    if (not intended_replacement) or (intended_replacement not in _candidate_ids):
                                        intended_replacement = _candidate_ids[-1]
                            %>
                            <div class="radio">
                                <div class="form-control-static">
                                    <label for="replaces-none">
                                        <input type="radio" name="replaces"${_selected} id="replaces-none" value=""/>
                                    </label>
                                    <span
                                        class="label label-info"
                                    >
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        New Order/Lineage
                                    </span>
                                </div>
                            </div>
                            % for dbCert in CertificateSigned_replaces_candidates:
                                <%
                                    _selected = ""
                                    if dbCert.id == intended_replacement:
                                        _selected = ' checked="checked"'
                                %>
                            
                                <div class="radio">
                                    <div class="form-control-static">
                                        <label for="replaces-${dbCert.id}">
                                            <input type="radio" name="replaces"${_selected} id="replaces-${dbCert.id}" value="${dbCert.ari_identifier}"/>
                                        </label>
                                        <a
                                            class="label label-info"
                                            href="${admin_prefix}/certificate-signed/${dbCert.id}"
                                        >
                                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                            CertificateSigned-${dbCert.id} | notAfter ${dbCert.timestamp_not_after_isoformat}
                                        </a>
                                    </div>
                                </div>
                            % endfor
                        </td>
                    </tr>
                    <tr>
                        <th>ACME profile</th>
                        <td><code>${RenewalConfiguration.acme_profile}</code></td>
                    </tr>
                    <tr>
                        <th>note</th>
                        <td>${admin_partials.formgroup__note()}</td>
                    </tr>
                    <tr>
                        <th></th>
                        <td>
                            ${admin_partials.formgroup__processing_strategy()}
                        </td>
                    </tr>
                    <tr>
                        <th></th>
                        <td>
                            <button class="btn btn-xs btn-primary" type="submit">
                                <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                Renew!
                            </button>
                        </td>
                    </tr>
                </tbody>
            </table>
            </form>
        </div>
    </div>
</%block>
