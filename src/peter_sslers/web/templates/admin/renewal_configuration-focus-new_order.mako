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
                        <th>AcmeAccount Primary</th>
                        <td>
                            <a
                                class="label label-info"
                                href="${admin_prefix}/acme-account/${RenewalConfiguration.acme_account_id__primary}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeAccount-${RenewalConfiguration.acme_account_id__primary}
                            </a>
                            <a
                                class="label label-info"
                                href="${admin_prefix}/acme-server/${RenewalConfiguration.acme_account__primary.acme_server_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeServer-${RenewalConfiguration.acme_account__primary.acme_server_id}
                            </a>
                            <span class="label label-default">
                                ${RenewalConfiguration.acme_account__primary.acme_server.name}
                            </span>
                            <br/>
                            <code>${RenewalConfiguration.acme_account__primary.acme_account_key.key_pem_sample}</code>
                        </td>
                    </tr>
                    % if RenewalConfiguration.acme_account__backup:
                        <tr>
                            <th>AcmeAccount Backup</th>
                            <td>
                                <a
                                    class="label label-info"
                                    href="${admin_prefix}/acme-account/${RenewalConfiguration.acme_account_id__backup}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeAccount-${RenewalConfiguration.acme_account_id__backup}
                                </a>
                                <a
                                    class="label label-info"
                                    href="${admin_prefix}/acme-server/${RenewalConfiguration.acme_account__backup.acme_server_id}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeServer-${RenewalConfiguration.acme_account__backup.acme_server_id}
                                </a>
                                <span class="label label-default">
                                    ${RenewalConfiguration.acme_account__backup.acme_server.server}
                                </span>
                                <br/>
                                <code>${RenewalConfiguration.acme_account__backup.acme_account_key.key_pem_sample}</code>
                            </td>
                        </tr>
                    % endif
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
                        <th>private_key_cycle [Primary]</th>
                        <td>
                            <code>${RenewalConfiguration.private_key_cycle__primary}</code>
                            % if RenewalConfiguration.private_key_cycle__primary == "account_default":
                                <span class="label label-default">
                                    AcmeAccount[${RenewalConfiguration.acme_account__primary.order_default_private_key_cycle}]
                                </span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>private_key_technology [Primary]</th>
                        <td><code>${RenewalConfiguration.private_key_technology__primary}</code>
                            % if RenewalConfiguration.private_key_technology__primary == "account_default":
                                <span class="label label-default">
                                    AcmeAccount[${RenewalConfiguration.acme_account__primary.order_default_private_key_technology}]
                                </span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>ACME profile [Primary]</th>
                        <td><code>${RenewalConfiguration.acme_profile__primary}</code></td>
                    </tr>
                    <tr>
                        <th>private_key_cycle [Backup]</th>
                        <td>
                            <code>${RenewalConfiguration.private_key_cycle__backup}</code>
                            % if RenewalConfiguration.private_key_cycle__backup == "account_default":
                                <span class="label label-default">
                                    AcmeAccount[${RenewalConfiguration.acme_account__backup.order_default_private_key_cycle}]
                                </span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>private_key_technology [Backup]</th>
                        <td><code>${RenewalConfiguration.private_key_technology__backup}</code>
                            % if RenewalConfiguration.private_key_technology__backup == "account_default":
                                <span class="label label-default">
                                    AcmeAccount[${RenewalConfiguration.acme_account__backup.order_default_private_key_technology}]
                                </span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>ACME profile [Backup]</th>
                        <td><code>${RenewalConfiguration.acme_profile__backup}</code></td>
                    </tr>
                    <tr>
                        <th>replaces</th>
                        <td>
<%
    ## This block covers both PRIMARY and BACKUP
    intended_replacement = request.params.get("replaces.id")
    if intended_replacement:
        intended_replacement = intended_replacement.strip()
        if intended_replacement not in ("primary", "backup"):
            try:
                intended_replacement = int(intended_replacement)
            except:
                pass
    if not intended_replacement:
        intended_replacement = "primary"

    _candidate_ids = [i.id for i in CertificateSigned_replaces_candidates__primary]
    _candidate_ids.append("primary")
    if RenewalConfiguration.acme_account__backup:
        _candidate_ids.extend([i.id for i in CertificateSigned_replaces_candidates__backup])
        _candidate_ids.append("backup")

    if (not intended_replacement) or (intended_replacement not in _candidate_ids):
        intended_replacement = "primary"
%>
                            <table class="table table-striped table-compact">
                                <thead>
                                    <tr>
                                        <th>Primary</th>
                                        % if RenewalConfiguration.acme_account__backup:
                                            <th>Backup</th>
                                        % endif
                                    </tr>
                                </thead>
                                <tbody>
<td>
    <div class="radio">
        <div class="form-control-static">
            <label for="replaces-primary">
                <%
                    _selected = ' checked="checked"' if intended_replacement == "primary" else ""
                %>
                <input type="radio" name="replaces"${_selected} id="replaces-primary" value="primary"/>
            </label>
            <span
                class="label label-info"
            >
                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                New Order/Lineage
            </span>
        </div>
    </div>
    % for dbCert in CertificateSigned_replaces_candidates__primary:
        <%
            _selected = ' checked="checked"' if dbCert.id == intended_replacement else ""
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
% if RenewalConfiguration.acme_account__backup:
    <td>
        <div class="radio">
            <div class="form-control-static">
                <label for="replaces-backup">
                    <%
                        _selected = ' checked="checked"' if intended_replacement == "backup" else ""
                    %>
                    <input type="radio" name="replaces"${_selected} id="replaces-backup" value="backup"/>
                </label>
                <span
                    class="label label-info"
                >
                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                    New Order/Lineage
                </span>
            </div>
        </div>
        % for dbCert in CertificateSigned_replaces_candidates__backup:
            <%
                _selected = ' checked="checked"' if dbCert.id == intended_replacement else ""
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
% endif
                                </tbody>
                            </table>
                        </td>
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
