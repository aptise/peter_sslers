<%def name="table_tr_OperationsEventCreated(dbObject)">
    % if dbObject.operations_event_id__created:
        <tr>
            <th>Event Created At</th>
            <td>
                <a  href="${admin_prefix}/operations/log/item/${dbObject.operations_event_id__created}"
                    class="label label-info"
                >
                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                    ${dbObject.operations_event_id__created}
                </a>
                <span class="label label-default">${dbObject.operations_event__created.event_type_text}</span>
                <timestamp>${dbObject.operations_event__created.timestamp_event or ''}</timestamp>
            </td>
        </tr>
    % endif
</%def>


<%def name="table_AcmeAccounts(data, perspective=None)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th><!-- active --></th>
                <th><!-- is_render_in_selects --></th>
                <th><!-- SystemConfiguration info --></th>
                <th>provider</th>
                <th>timestamp first seen</th>
                <th>key_pem_md5</th>
                ## <th>count certificate requests</th>
                <th>count certificates issued</th>
            </tr>
        </thead>
        <tbody>
            % for account in data:
                <tr>
                    <td><a class="label label-info" href="${admin_prefix}/acme-account/${account.id}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        AcmeAccount-${account.id}</a>
                        % if account.name:
                            <span class="label label-default">${account.name}</span>
                        % endif
                    </td>
                    <td>
                        % if account.is_active:
                            <span class="label label-success">active</span>
                        % elif account.timestamp_deactivated:
                            <span class="label label-warning">deactivated</span>
                        % endif
                    </td>
                    <td>
                        % if account.is_render_in_selects:
                            <span class="label label-success">Render in Select</span>
                        % endif
                    </td>                    
                    <td>
                        <!-- TODO: show SystemConfiguration Info -->
                    </td>
                    <td>
                        <a class="label label-info" href="${admin_prefix}/acme-server/${account.acme_server_id}">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            AcmeServer-${account.acme_server_id}</a>
                            ## <code>${account.acme_server.url}</code>
                            <span class="label label-default">${account.acme_server.name}</span>
                    </td>
                    <td><timestamp>${account.timestamp_created}</timestamp></td>
                    <td><code>${account.acme_account_key.key_pem_md5}</code></td>
                    ## <td><span class="badge">${account.count_acme_orders or ''}</span></td>
                    <td><span class="badge">${account.count_certificate_signeds or ''}</span></td>
                </tr>
            % endfor
        </tbody>
    </table>
</%def>



<%def name="table_AcmeAccountKeys(data, perspective=None)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>acme_account_id</th>
                <th><!-- active --></th>
                <th>source</th>
                <th>key_technology</th>
                % if perspective != "AcmeAccount":
                    <th>provider</th>
                % endif
                <th>timestamp first seen</th>
                <th>key_pem_md5</th>
            </tr>
        </thead>
        <tbody>
            % for key in data:
                <tr>
                    <td>
                        ## <a class="label label-info" href="${admin_prefix}/acme-account-key/${key.id}">
                        ## <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        <span class="label label-default">
                            AcmeAccountKey-${key.id}
                        </span>
                        ##</a>
                        </td>
                    <td><a class="label label-info" href="${admin_prefix}/acme-account/${key.acme_account_id}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        AcmeAccount-${key.acme_account_id}</a></td>
                    <td>
                        % if key.is_active:
                            <span class="label label-success">active</span>
                        % elif key.timestamp_deactivated:
                            <span class="label label-warning">deactivated</span>
                        % endif
                    </td>
                    <td><span class="label label-default">${key.key_technology}</span></td>
                    <td><span class="label label-default">${key.acme_account_key_source}</span></td>
                    % if perspective != "AcmeAccount":
                        <td><span class="label label-info">${key.acme_account.acme_server.name}</span></td>
                    % endif
                    <td><timestamp>${key.timestamp_created}</timestamp></td>
                    <td><code>${key.key_pem_md5}</code></td>
                </tr>
            % endfor
        </tbody>
    </table>
</%def>


<%def name="table_AcmeAuthorizations(data, perspective=None, is_form_enabled=None)">
    <%
        cols = ("id",
                "domain_id",
                "pending",
                "status",
                "timestamp_created",
                "timestamp_expires",
                "timestamp_updated",
                "acme_order_id__created",
                # "authorization_url",
                "wildcard",
               )
        if perspective == 'AcmeAccount':
            cols = [c for c in cols]
            if is_form_enabled:
                cols.insert(0, "*checkbox*")
        elif perspective == 'AcmeOrder.to_acme_authorizations':
            cols = [c for c in cols if c != 'acme_order_id__created']
            data = [d.acme_authorization for d in data.to_acme_authorizations]
        elif perspective == 'AcmeAuthorizations':
            cols = [c for c in cols]
        elif perspective == 'Domain':
            cols = [c for c in cols if c != 'domain_id']
        else:
            raise ValueError("invalid `perspective`")
    %>
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                % for c in cols:
                    <th>
                        % if c == '*checkbox*':
                            <script type="text/javascript">
                                function select_all(){
                                    var inputs = document.querySelectorAll("input[type='checkbox']");
                                    for(var i = 0; i < inputs.length; i++) {
                                        inputs[i].checked = true;
                                    }
                                }
                            </script>
                            <input type="checkbox" name="_select_all" value="" id="_select_all" onclick="javascript:select_all();">
                        % else:
                            ${c}
                        % endif
                    </th>
                % endfor
            </tr>
        </thead>
        <tbody>
            % for acme_authorization in data:
                <tr>
                    % for c in cols:
                        <td>
                            % if c == '*checkbox*':
                                % if acme_authorization.is_acme_server_pending:
                                    <input type="checkbox" name="acme_authorization_id" value="${acme_authorization.id}" class="acme_authorization">
                                % endif
                            % elif c == 'id':
                                <a href="${admin_prefix}/acme-authorization/${acme_authorization.id}" class="label label-info">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeAuthorization-${acme_authorization.id}
                                </a>
                            % elif c == 'pending':
                                % if acme_authorization.is_acme_server_pending:
                                    <span class="label label-success"><span class="glyphicon glyphicon-ok" aria-hidden="true"></span></span>
                                % else:
                                    <span class="label label-default"><span class="glyphicon glyphicon-remove" aria-hidden="true"></span></span>
                                % endif
                            % elif c == 'status':
                                <code>${acme_authorization.acme_status_authorization or ''}</code>
                            % elif c == 'domain_id':
                                % if acme_authorization.domain_id:
                                    <a class="label label-info" href="${admin_prefix}/domain/${acme_authorization.domain_id}">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        Domain-${acme_authorization.domain_id}
                                    </a>
                                    <code>${acme_authorization.domain.domain_name}</code>
                                % endif
                            % elif c == 'timestamp_created':
                                <timestamp>${acme_authorization.timestamp_created or ''}</timestamp>
                            % elif c == 'timestamp_expires':
                                <timestamp>${acme_authorization.timestamp_expires or ''}</timestamp>
                            % elif c == 'timestamp_updated':
                                <timestamp>${acme_authorization.timestamp_updated or ''}</timestamp>
                            % elif c == 'wildcard':
                                <code>${acme_authorization.wildcard or ''}</code>
                            % elif c == 'authorization_url':
                                <code>${acme_authorization.authorization_url or ''}</code>
                            % elif c == 'acme_order_id__created':
                                <a class="label label-info" href="${admin_prefix}/acme-order/${acme_authorization.acme_order_id__created}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeOrder-${acme_authorization.acme_order_id__created}
                                </a>
                            % endif
                        </td>
                    % endfor
                </tr>
            % endfor
        </tbody>
    </table>
</%def>


<%def name="table_AcmeAuthorizationPotentials(data, perspective=None)">
    <%
        cols = ("id",
                "domain_id",
                "timestamp_created",
                "acme_order_id",
               )
        if perspective == 'AcmeAuthorizationPotentials':
            cols = [c for c in cols]
        elif perspective == 'Domain':
            cols = [c for c in cols if c != "domain_id"]
        else:
            raise ValueError("invalid `perspective`")
    %>
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                % for c in cols:
                    <th>
                        ${c}
                    </th>
                % endfor
            </tr>
        </thead>
        <tbody>
            % for acme_authz_potential in data:
                <tr>
                    % for c in cols:
                        <td>
                            % if c == 'id':
                                <a href="${admin_prefix}/acme-authz-potential/${acme_authz_potential.id}" class="label label-info">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeAuthorizationPotential-${acme_authz_potential.id}
                                </a>
                            % elif c == 'domain_id':
                                % if acme_authz_potential.domain_id:
                                    <a class="label label-info" href="${admin_prefix}/domain/${acme_authz_potential.domain_id}">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        Domain-${acme_authz_potential.domain_id}
                                    </a>
                                    <code>${acme_authz_potential.domain.domain_name}</code>
                                % endif
                            % elif c == 'timestamp_created':
                                <timestamp>${acme_authz_potential.timestamp_created or ''}</timestamp>
                            % elif c == 'acme_order_id':
                                <a class="label label-info" href="${admin_prefix}/acme-order/${acme_authz_potential.acme_order_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeOrder-${acme_authz_potential.acme_order_id}
                                </a>
                            % endif
                        </td>
                    % endfor
                </tr>
            % endfor
        </tbody>
    </table>
</%def>


<%def name="table_AcmeAuthorizationChallenges(AcmeOrder, perspective=None)">
<%
    if perspective != 'AcmeOrder':
        raise ValueError("invalid perspective")
%>
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>AcmeAuthorization</th>
                <th>AcmeChallenge http-01</th>
                <th>Domain</th>
                <th>Authorization Status</th>
                <th>Authorization Updated</th>
                <th>Challenge Status (http-01)</th>
                <th>Challenge Updated (http-01)</th>
                <th>Challenge Keyauthorization (http-01)</th>
            </tr>
        </thead>
        <tbody>
            % for to_acme_authorization in AcmeOrder.to_acme_authorizations:
                <%
                    AcmeAuthorization = to_acme_authorization.acme_authorization
                    AcmeChallenge_http01 = AcmeAuthorization.acme_challenge_http_01
                %>
                <tr>
                    <td>
                        <a href="${admin_prefix}/acme-authorization/${AcmeAuthorization.id}" class="label label-info">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            AcmeAuthorization-${AcmeAuthorization.id}
                        </a>
                    </td>
                    <td>
                        % if AcmeChallenge:
                            <a href="${admin_prefix}/acme-challenge/${AcmeChallenge_http01.id}" class="label label-info">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeChallenge-${AcmeChallenge_http01.id}
                            </a>
                        % endif
                    </td>
                    <td>
                        % if AcmeAuthorization.domain_id:
                            <a class="label label-info" href="${admin_prefix}/domain/${AcmeAuthorization.domain_id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                Domain-${AcmeAuthorization.domain_id}
                            </a>
                            <code>${AcmeAuthorization.domain.domain_name}</code>
                        % endif
                    </td>
                    <td>
                        <code>${AcmeAuthorization.acme_status_authorization or ''}</code>
                    </td>
                    <td>
                        <timestamp>${AcmeAuthorization.timestamp_updated or ''}</timestamp>
                    </td>
                    <td>
                        % if AcmeChallenge_http01:
                            <code>${AcmeChallenge_http01.acme_status_challenge or ''}</code>
                        % endif
                    </td>
                    <td>
                        % if AcmeChallenge_http01:
                            <timestamp>${AcmeChallenge_http01.timestamp_updated or ''}</timestamp>
                        % endif
                    </td>
                    <td>
                        % if AcmeChallenge_http01:
                            <code>${AcmeChallenge_http01.keyauthorization or ''}</code>
                        % endif
                    </td>
                </tr>
            % endfor
        </tbody>
    </table>
</%def>


<%def name="table_AcmeChallenges(acme_challenges, perspective=None)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                % if perspective != "AcmeAuthorization":
                    <th>Acme Authorization</th>
                % endif
                <th>timestamp_created</th>
                <th>acme_challenge_type</th>
                <th>status</th>
                <th>domain</th>
                <th>token</th>
                <th>timestamp_updated</th>
            </tr>
        </thead>
        <tbody>
        % for item in acme_challenges:
            <tr>
                <td><a class="label label-info" href="${admin_prefix}/acme-challenge/${item.id}">
                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                    AcmeChallenge-${item.id}</a></td>
                % if perspective != "AcmeAuthorization":
                    <td>
                        % if item.acme_authorization_id:
                            <a class="label label-info" href="${admin_prefix}/acme-authorization/${item.acme_authorization_id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeAuthorization-${item.acme_authorization_id}</a>
                        % endif
                    </td>
                % endif
                <td><timestamp>${item.timestamp_created}</timestamp></td>
                <td><span class="label label-default">${item.acme_challenge_type}</span></td>
                <td><code>${item.acme_status_challenge}</code></td>
                <td><a class="label label-info" href="${admin_prefix}/domain/${item.domain_id}">
                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                    ${item.domain.domain_name}</a></td>
                <td><code>${item.token}</code></td>
                <td><timestamp>${item.timestamp_updated}</timestamp></td>
            </tr>
        % endfor
        </tbody>
    </table>
</%def>


<%def name="table_AcmeDnsServerAccounts(AcmeDnsServerAccounts, perspective=None)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>Focus</th>
                <th>active</th>
                % if perspective != "AcmeDnsServer":
                    <th>AcmeDnsServer</th>
                % endif
                % if perspective != "Domain":
                    <th>Domain</th>
                % endif
                <th>cname source</th>
                <th>cname target</th>
            </tr>
        </thead>
        <tbody>
            % for a2d in AcmeDnsServerAccounts:
                <tr>
                    <td>
                        <a href="${admin_prefix}/acme-dns-server-account/${a2d.id}" class="label label-info">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            AcmeDnsServerAccount-${a2d.id}
                        </a>
                    </td>
                    <td>
                        % if a2d.is_active:
                            <span class="label label-success">active</span>
                        % else:
                            <span class="label label-danger">inactive</span>
                        % endif
                    </td>
                    % if perspective != "AcmeDnsServer":
                        <td>
                            <a href="${admin_prefix}/acme-dns-server/${a2d.acme_dns_server_id}" class="label label-info">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeDnsServer-${a2d.acme_dns_server_id}
                            </a>
                            <spa class="label label-default">${a2d.acme_dns_server.api_url}</span>
                        </td>
                    % endif
                    % if perspective != "Domain":
                        <td>
                            <a href="${admin_prefix}/domain/${a2d.domain_id}" class="label label-info">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                Domain-${a2d.domain_id}
                            </a>
                            <spa class="label label-default">${a2d.domain.domain_name}</span>
                        </td>
                    % endif
                    <td><code>${a2d.cname_source}</code></td>
                    <td><code>${a2d.cname_target}</code></td>
                </tr>
            % endfor
        </tbody>
    </table>
</%def>

<%def name="table_AcmeDnsServerAccounts5_via_Domain(Domain)">
    ## In the future this should support multiple accounts
    ## however, right now we only care about one single account
    % if Domain.acme_dns_server_accounts__5:
        <table class="table table-striped table-condensed">
            <tr>
                <th>id</th>
                <th>cname source</th>
                <th>cname target</th>
            </tr>
            % for acc in Domain.acme_dns_server_accounts__5:
                <tr>
                    <td>
                        <a href="${admin_prefix}/domain/${Domain.id}/acme-dns-server-accounts"
                         class="label label-info"
                        >
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            ${acc.id}
                        </a>
                    </td>
                    <td><code>${acc.cname_source}</code></td>
                    <td><code>${acc.cname_target}</code></td>
                </tr>
            % endfor
        </table>
        <a  class="btn btn-xs btn-primary"
            href="${admin_prefix}/domain/${Domain.id}/acme-dns-server-accounts"
        >
            <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
            All AcmeDnsServerAccounts
        </a>
    % else:
        <a  class="btn btn-xs btn-primary"
            href="${admin_prefix}/domain/${Domain.id}/acme-dns-server/new"
        >
            <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
            AcmeDnsServers - New</a>
    % endif
</%def>



<%def name="table_AcmeEventLogs(acme_event_logs, perspective=None)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>timestamp_event</th>
                <th>acme_event_id</th>
                <th>acme_account_id</th>
                <th>acme_authorization_id</th>
                <th>acme_challenge_id</th>
                <th>acme_order_id</th>
                <th>certificate_request_id</th>
                <th>certificate_signed_id</th>
            </tr>
        </thead>
        <tbody>
        % for logged in acme_event_logs:
            <tr>
                <td>
                    <a  class="label label-info"
                        href="${admin_prefix}/acme-event-log/${logged.id}"
                    >
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        AcmeEvent-${logged.id}
                    </a>
                </td>
                <td><timestamp>${logged.timestamp_event}</timestamp></td>
                <td><span class="label label-default">${logged.acme_event}</span></td>
                <td>
                    % if logged.acme_account_id:
                        <a  class="label label-info"
                            href="${admin_prefix}/acme-account/${logged.acme_account_id}"
                        >
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            AcmeAccount-${logged.acme_account_id}
                        </a>
                    % endif
                </td>
                <td>
                    % if logged.acme_authorization_id:
                        <a  class="label label-info"
                            href="${admin_prefix}/acme-authorization/${logged.acme_authorization_id}"
                        >
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            AcmeAuthorization-${logged.acme_authorization_id}
                        </a>
                    % endif
                </td>
                <td>
                    % if logged.acme_challenge_id:
                        <a  class="label label-info"
                            href="${admin_prefix}/acme-challenge/${logged.acme_challenge_id}"
                        >
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            AcmeChallenge-${logged.acme_challenge_id}
                        </a>
                    % endif
                </td>
                <td>
                    % if logged.acme_order_id:
                        <a  class="label label-info"
                            href="${admin_prefix}/acme-order/${logged.acme_order_id}"
                        >
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            AcmeOrder-${logged.acme_order_id}
                        </a>
                    % endif
                </td>
                <td>
                    % if logged.certificate_request_id:
                        <a  class="label label-info"
                            href="${admin_prefix}/certificate-request/${logged.certificate_request_id}"
                        >
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            CertificateRequest-${logged.certificate_request_id}
                        </a>
                    % endif
                </td>
                <td>
                    % if logged.certificate_signed_id:
                        <a  class="label label-info"
                            href="${admin_prefix}/certificate-signed/${logged.certificate_signed_id}"
                        >
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            CertificateSigned-${logged.certificate_signed_id}
                        </a>
                    % endif
                </td>
            </tr>
        % endfor
        </tbody>
    </table>
</%def>



<%def name="table_AcmeOrders(acme_orders, perspective=None)">
    <%
        cols = ("id",
                "is_processing",
                "status",
                "timestamp_created",
                "timestamp_finalized",
                "acme_account_id",
                "renewal_configuration_id",
                "certificate_request_id",
                "acme_order_types",
                "certificate_signed_id",
                "unique_fqdn_set_id",
               )
        if perspective == 'AcmeOrders':
            cols = [c for c in cols if c != 'certificate_request_id']
        elif perspective == 'CertificateRequest':
            cols = [c for c in cols if c != 'certificate_request_id']
        elif perspective == 'Domain':
            cols = [c for c in cols]
        elif perspective == 'AcmeAuthorization':
            cols = [c for c in cols]
        elif perspective == 'AcmeAccount':
            cols = [c for c in cols if c != "acme_account_id"]
        elif perspective == 'RenewalConfiguration':
            cols = [c for c in cols if c != "renewal_configuration_id"]
        elif perspective == 'UniqueFQDNSet':
            cols = [c for c in cols if c != "unique_fqdn_set_id"]
        elif perspective == 'UniquelyChallengedFQDNSet':
            cols = [c for c in cols if c != "uniquely_challenged_fqdn_set_id"]
        else:
            raise ValueError("invalid `perspective`")
    %>
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                % for c in cols:
                    <th>${c}</th>
                % endfor
            </tr>
        </thead>
        <tbody>
            % for acme_order in acme_orders:
                <tr>
                    % for c in cols:
                        <td>
                            % if c == 'id':
                                <a href="${admin_prefix}/acme-order/${acme_order.id}" class="label label-info">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeOrder-${acme_order.id}
                                </a>
                            % elif c == 'is_processing':
                                % if acme_order.is_processing is True:
                                    <div class="label label-success">
                                        <span class="glyphicon glyphicon-ok" aria-hidden="true"></span>
                                    </div>
                                % elif acme_order.is_processing is None:
                                    <div class="label label-default">
                                        <span class="glyphicon glyphicon-ok-sign" aria-hidden="true"></span>
                                    </div>
                                % elif acme_order.is_processing is False:
                                    <div class="label label-warning">
                                        <span class="glyphicon glyphicon-remove-sign" aria-hidden="true"></span>
                                    </div>
                                % endif
                            % elif c == 'status':
                                <code>${acme_order.acme_status_order or ''}</code>
                            % elif c == 'timestamp_created':
                                <timestamp>${acme_order.timestamp_created or ''}</timestamp>
                            % elif c == 'timestamp_finalized':
                                <timestamp>${acme_order.timestamp_finalized or ''}</timestamp>
                            % elif c == 'acme_account_id':
                                % if acme_order.acme_account_id:
                                    <a href="${admin_prefix}/acme-account/${acme_order.acme_account_id}" class="label label-info">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        AcmeAccount-${acme_order.acme_account_id}
                                    </a>
                                % endif
                            % elif c == 'certificate_request_id':
                                % if acme_order.certificate_request_id:
                                    <a href="${admin_prefix}/certificate-request/${acme_order.certificate_request_id}" class="label label-info">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        CertificateRequest-${acme_order.certificate_request_id}
                                    </a>
                                % endif
                            % elif c == 'acme_order_types':
                                <span class="label label-default">${acme_order.acme_order_type}</span>
                                % if acme_order.certificate_type_id == model_websafe.CertificateType.MANAGED_PRIMARY:
                                    <span class="label label-success">${acme_order.certificate_type}</span>
                                % elif acme_order.certificate_type_id == model_websafe.CertificateType.MANAGED_BACKUP:
                                    <span class="label label-warning">${acme_order.certificate_type}</span>
                                % elif acme_order.certificate_type_id == model_websafe.CertificateType.RAW_IMPORTED:
                                    <span class="label label-default">${acme_order.certificate_type}</span>
                                % endif
                                
                                
                            % elif c == 'certificate_signed_id':
                                % if acme_order.certificate_signed_id:
                                    <a href="${admin_prefix}/certificate-signed/${acme_order.certificate_signed_id}" class="label label-info">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        CertificateSigned-${acme_order.certificate_signed_id}
                                    </a>
                                % endif
                            % elif c == 'renewal_configuration_id':
                                % if acme_order.renewal_configuration_id:
                                    <a href="${admin_prefix}/renewal-configuration/${acme_order.renewal_configuration_id}" class="label label-info">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        RenewalConfiguration-${acme_order.renewal_configuration_id}
                                    </a>
                                % endif
                            % elif c == 'unique_fqdn_set_id':
                                % if acme_order.unique_fqdn_set_id:
                                    <a href="${admin_prefix}/unique-fqdn-set/${acme_order.unique_fqdn_set_id}" class="label label-info">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        UniqueFQDNSet-${acme_order.unique_fqdn_set_id}
                                    </a>
                                % endif
                            % endif
                        </td>
                    % endfor
                </tr>
            % endfor
        </tbody>
    </table>
</%def>


<%def name="table_AcmePollingErrors(acme_polling_errors, perspective=None)">
    <%
        cols = ("id",
                "timestamp_created",
                "timestamp_validated",
                "acme_polling_error_endpoint",
                "subproblems_len",
                "acme_order_id",
                "acme_authorization_id",
                "acme_challenge_id",
               )
    %>
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                % for c in cols:
                    <th>${c}</th>
                % endfor
            </tr>
        </thead>
        <tbody>
            % for acme_polling_error in acme_polling_errors:
                <tr>
                    % for c in cols:
                        <td>
                            % if c == 'id':
                                <a href="${admin_prefix}/acme-polling-error/${acme_polling_error.id}" class="label label-info">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmePollingError-${acme_polling_error.id}
                                </a>
                            % elif c == 'timestamp_created':
                                <timestamp>${acme_polling_error.timestamp_created or ''}</timestamp>
                            % elif c == 'timestamp_validated':
                                <timestamp>${acme_polling_error.timestamp_validated or ''}</timestamp>
                            % elif c == 'acme_polling_error_endpoint':
                                <code>${acme_polling_error.acme_polling_error_endpoint or ''}</code>
                            % elif c == 'subproblems_len':
                                <code>${acme_polling_error.subproblems_len or ''}</code>
                            % elif c == 'acme_order_id':
                                <a href="${admin_prefix}/acme-order/${acme_polling_error.acme_order_id}" class="label label-info">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeOrder-${acme_polling_error.acme_order_id}
                                </a>
                            % elif c == 'acme_authorization_id':
                                <a href="${admin_prefix}/acme-order/${acme_polling_error.acme_authorization_id}" class="label label-info">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeAuthorization-${acme_polling_error.acme_authorization_id}
                                </a>
                            % elif c == 'acme_order_id':
                                <a href="${admin_prefix}/acme-order/${acme_polling_error.acme_challenge_id}" class="label label-info">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeChallenge-${acme_polling_error.acme_challenge_id}
                                </a>
                            % endif
                        </td>
                    % endfor
                </tr>
            % endfor
        </tbody>
    </table>
</%def>


<%def name="table_AriChecks(ari_checks, perspective=None)">
    <%
        cols = ("id",
                "certificate_signed_id",
                "timestamp_created",
                "suggested_window_start",
                "suggested_window_end",
                "timestamp_retry_after",
                "ari_check_status",
               )
        if perspective == 'CertificateSigned':
            cols = [c for c in cols if c != 'certificate_signed_id']
        elif perspective == 'AriChecks':
            pass
        else:
            raise ValueError("invalid `perspective`")
    %>
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                % for c in cols:
                    <th>${c}</th>
                % endfor
            </tr>
        </thead>
        <tbody>
            % for ari_check in ari_checks:
                <tr>
                    % for c in cols:
                        <td>
                            % if c == 'id':
                                <a href="${admin_prefix}/ari-check/${ari_check.id}" class="label label-info">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AriCheck-${ari_check.id}
                                </a>
                            % elif c == 'certificate_signed_id':
                                <a href="${admin_prefix}/certificate-signed/${ari_check.certificate_signed_id}" class="label label-info">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    CertificateSigned-${ari_check.certificate_signed_id}
                                </a>
                            % elif c == 'timestamp_created':
                                <timestamp>${ari_check.timestamp_created or ''}</timestamp>
                            % elif c == 'ari_check_status':
                                % if ari_check.ari_check_status:
                                    <div class="label label-success">
                                        <span class="glyphicon glyphicon-ok" aria-hidden="true"></span>
                                    </div>
                                % else:
                                    <div class="label label-danger">
                                        <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                    </div>
                                % endif
                            % elif c == 'suggested_window_start':
                                <timestamp>${ari_check.suggested_window_start or ''}</timestamp>
                            % elif c == 'suggested_window_end':
                                <timestamp>${ari_check.suggested_window_end or ''}</timestamp>
                            % elif c == 'timestamp_retry_after':
                                <timestamp>${ari_check.timestamp_retry_after or ''}</timestamp>
                            % endif
                        </td>
                    % endfor
                </tr>
            % endfor
        </tbody>
    </table>
</%def>

<%def name="table_CertificateCAChains(certificate_ca_chains, perspective=None)">
    <%
        cols = ("id",
                "display_name",
                "chain_length",
                "certificate_ca_0_id",
                "certificate_ca_n_id",
                "certificate_ca_ids_string",
               )
    %>
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                % for c in cols:
                    <th>${c}</th>
                % endfor
            </tr>
        </thead>
        <tbody>
            % for certificate_ca_chain in certificate_ca_chains:
                <tr>
                    % for c in cols:
                        <td>
                            % if c == 'id':
                                <a  class="label label-info"
                                    href="${admin_prefix}/certificate-ca-chain/${certificate_ca_chain.id}">
                                    <span class="glyphicon certificate_ca_chain-file" aria-hidden="true"></span>
                                    CertificateCAChain-${certificate_ca_chain.id}</a>
                                % else:
                                    ${getattr(certificate_ca_chain, c)}
                                % endif
                        </td>
                    % endfor
                </tr>
            % endfor
        </tbody>
    </table>
</%def>


<%def name="table_CertificateRequests(certificate_requests, perspective=None)">
    <%
        show_domains = True if perspective in ("PrivateKey", 'CertificateRequest', ) else False
        show_certificate = True if perspective in ("CertificateSigned", 'CertificateRequest', ) else False
    %>
    <%
        cols = ("id",
                "type",
                "timestamp_created",
                "AcmeOrder",
                "unique_fqdn_set_id",
               )
        if perspective == 'AcmeAccount':
            cols = [c for c in cols]
        elif perspective == 'CertificateRequest':
            cols = [c for c in cols]
        elif perspective == 'Domain':
            cols = [c for c in cols]
        elif perspective == 'PrivateKey':
            cols = [c for c in cols if c != 'private_key_id']
        elif perspective == 'CertificateSigned':
            cols = [c for c in cols]
        elif perspective == 'UniqueFQDNSet':
            cols = [c for c in cols if c != 'unique_fqdn_set_id']
        else:
            raise ValueError("invalid `perspective`")
    %>
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                % for c in cols:
                    <th>${c}</th>
                % endfor
                % if show_domains:
                     <th>domains</th>
                % endif
            </tr>
        </thead>
        <tbody>
            % for certificate_request in certificate_requests:
                <tr>
                    % for c in cols:
                        % if c == 'id':
                            <td>
                                <a  class="label label-info"
                                    href="${admin_prefix}/certificate-request/${certificate_request.id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    CertificateRequest-${certificate_request.id}</a>
                            </td>
                        % elif c == 'type':
                            <td>
                                <span class="label label-default">${certificate_request.certificate_request_source}</span>
                            </td>
                        % elif c == 'timestamp_created':
                            <td>
                                <timestamp>${certificate_request.timestamp_created}</timestamp>
                            </td>
                        % elif c == 'AcmeOrder':
                            <td>
                                % if certificate_request.certificate_request_source_id == model_websafe.CertificateRequestSource.ACME_ORDER:
                                    <a  class="label label-info"
                                    href="${admin_prefix}/acme-order/${certificate_request.acme_orders[0].id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeOrder-${certificate_request.acme_orders[0].id}</a>
                                % endif
                            </td>
                        % elif c == 'unique_fqdn_set_id':
                            <td>
                                <a  class="label label-info"
                                href="${admin_prefix}/unique-fqdn-set/${certificate_request.unique_fqdn_set_id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                UniqueFQDNSet-${certificate_request.unique_fqdn_set_id}</a>
                            </td>
                        % endif
                    % endfor
                    % if show_domains:
                         <td><code>${certificate_request.domains_as_string}</code></td>
                    % endif
                </tr>
            % endfor
        </tbody>
    </table>
</%def>


<%def name="table_CertificateSigneds(certificates, perspective=None, show_domains=False, show_days_to_expiry=False, show_replace=False)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>active?</th>
                % if perspective != "RenewalConfiguration":
                    <th>auto-renew?</th>
                % endif
                % if (perspective == "RenewalConfiguration") and show_replace:
                    <th></th>
                % endif
                <th>timestamp_not_before</th>
                <th>timestamp_not_after</th>
                % if show_days_to_expiry:
                    <th>days to expiry</th>
                % endif
                % if show_domains:
                    <th>domains</th>
                % endif
            </tr>
        </thead>
        <tbody>
        % for cert in certificates:
            <tr>
                <td><a class="label label-info" href="${admin_prefix}/certificate-signed/${cert.id}">
                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                    CertificateSigned-${cert.id}</a>
                </td>
                <td>
                    % if cert.is_revoked:
                        <span class="label label-danger">
                            revoked
                        </span>
                    % else:
                        <span class="label label-${'success' if cert.is_active else 'warning'}">
                            ${'Active' if cert.is_active else 'inactive'}
                        </span>
                    % endif
                    % if cert.certificate_type_id == model_websafe.CertificateType.MANAGED_PRIMARY:
                        <span class="label label-success">${cert.certificate_type}</span>
                    % elif cert.certificate_type_id == model_websafe.CertificateType.MANAGED_BACKUP:
                        <span class="label label-warning">${cert.certificate_type}</span>
                    % elif cert.certificate_type_id == model_websafe.CertificateType.RAW_IMPORTED:
                        <span class="label label-default">${cert.certificate_type}</span>
                    % endif
                </td>
                % if perspective != "RenewalConfiguration":
                <td>
                    % if cert.acme_order and cert.acme_order.renewal_configuration:
                        <a class="label label-info" href="${admin_prefix}/renewal-configuration/${cert.acme_order.renewal_configuration_id}">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            RenewalConfiguration-${cert.acme_order.renewal_configuration_id}</a>
                            
                            % if cert.acme_order.renewal_configuration.is_active:
                                <span class="label label-success">Active</span>
                            % else:
                                <span class="label label-warning">Inactive</span>
                            % endif
                            
                            % if cert.certificate_signed_id__replaces:
                                <span class="label label-default">replaces ${cert.certificate_signed_id__replaces}</span>
                            % endif
                            % if cert.certificate_signed_id__replaced_by:
                                <span class="label label-default">replaced by ${cert.certificate_signed_id__replaced_by}</span>
                            % endif
                    % else:
                        <span class="label label-warning">
                            unavailable
                        </span>
                    % endif
                </td>
                % endif
                % if (perspective == "RenewalConfiguration") and show_replace:
                    <td>
                        % if cert.acme_order:
                            % if cert.certificate_signed_id__replaces:
                                <span class="label label-default">replaces ${cert.certificate_signed_id__replaces}</span>
                            % endif
                            % if cert.certificate_signed_id__replaced_by:
                                <span class="label label-default">replaced by ${cert.certificate_signed_id__replaced_by}</span>
                            % endif
                    % endif
                    </td>
                % endif
                <td><timestamp>${cert.timestamp_not_before}</timestamp></td>
                <td><timestamp>${cert.timestamp_not_after}</timestamp></td>
                % if show_days_to_expiry:
                    <td>
                        <span class="label label-${cert.days_to_expiry__label}">
                            ${cert.days_to_expiry} days
                        </span>
                    </td>
                % endif
                % if show_domains:
                    <td><code>${cert.domains_as_string}</code></td>
                % endif
            </tr>
        % endfor
        </tbody>
    </table>
</%def>


<%def name="table_CoverageAssuranceEvents(CoverageAssuranceEvents)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>parent(?)</th>
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
                <td>
                    % if cae.coverage_assurance_event_id__parent:
                        <a  class="label label-info"
                            href="${admin_prefix}/coverage-assurance-event/${cae.coverage_assurance_event_id__parent}"
                        >
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            CoverageAssuranceEvent-${cae.coverage_assurance_event_id__parent}</a>
                    % endif
                </td>
                <td><timestamp>${cae.timestamp_created}</timestamp></td>
                <td><code>${cae.coverage_assurance_event_type}</code></td>
                <td><code>${cae.coverage_assurance_event_status}</code></td>
                <td><code>${cae.coverage_assurance_resolution}</code></td>
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
                    % if cae.certificate_signed_id:
                        <a  class="label label-info"
                            href="${admin_prefix}/certificate-signed/${cae.certificate_signed_id}"
                        >
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            CertificateSigned-${cae.certificate_signed_id}</a>
                    % endif
                </td>
            </tr>
        % endfor
    </table>
</%def>


<%def name="table_DomainAutocerts(domain_autocerts, perspective=None)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>domain</th>
                <th>timestamp_created</th>
                <th>timestamp_finished</th>
                <th>is_successful</th>
                <th>acme order</th>
            </tr>
        </thead>
        <tbody>
        % for item in domain_autocerts:
            <tr>
                <td>
                    <a class="label label-info" href="${admin_prefix}/domain-autocert/${item.id}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        DomainAutocert-${item.id}</a>
                </td>
                <td>
                    <a class="label label-info" href="${admin_prefix}/domain/${item.domain_id}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        ${item.domain.domain_name}</a>
                </td>
                <td><timestamp>${item.timestamp_created}</timestamp></td>
                <td><timestamp>${item.timestamp_finished}</timestamp></td>
                <td>
                    % if item.is_successful is True:
                        <span class="label label-success">Success</span>
                    % elif item.is_successful is False:
                        <span class="label label-warning">Failure</span>
                    % endif
                </td>
                <td>
                    % if item.acme_order_id:
                        <a class="label label-info" href="${admin_prefix}/acme-order/${item.acme_order_id}">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            ${item.domain.domain_name}</a>
                    % endif
                </td>
            </tr>
        % endfor
        </tbody>
    </table>
</%def>


<%def name="table_EnrollmentFactorys(data, perspective=None)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>name</th>
            </tr>
        </thead>
        <tbody>
            % for factory in data:
                <tr>
                    <td><a class="label label-info" href="${admin_prefix}/enrollment-factory/${factory.id}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        EnrollmentFactory-${factory.id}</a>
                    </td>
                    <td>
                        <span class="label label-default">${factory.name}</span>
                    </td>
                </tr>
            % endfor
        </tbody>
    </table>
</%def>


<%def name="table_OperationsEvents(OperationsEvents, show_event=None, event_type_listable=None)">
    <%
        event_id = None
        if show_event is not None:
            event_id = request.params.get('event.id')
    %>
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>child of</th>
                <th>event_type</th>
                <th>event timestamp</th>
            </tr>
        </thead>
        <tbody>
            % for event in OperationsEvents:
                <tr class="${'success' if event_id == str(event.id) else ''}">
                    <td>
                        <a  href="${admin_prefix}/operations/log/item/${event.id}"
                            class="label label-info"
                        >
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            ${event.id}
                        </a>
                    </td>
                    <td>
                        % if event.operations_event_id__child_of:
                            <span class="label label-default">${event.operations_event_id__child_of}</span>
                        % endif
                    </td>
                    <td>
                        % if event_type_listable:
                            <a  href="${admin_prefix}/operations/log?event_type=${event.event_type_text}"
                                class="label label-default"
                            >
                                ${event.event_type_text}
                            </a>
                        % else:
                            <span class="label label-default">${event.event_type_text}</span>
                        % endif
                    </td>
                    <td><timestamp>${event.timestamp_event}</timestamp></td>
                </tr>
            % endfor
        </tbody>
    </table>
</%def>


<%def name="table_OperationsEvent_Payload(OperationsEvent, table_context=None)">
    <%
        show_event = True
        if table_context == "log_list":
            pass
    %>
    <table class="table table-striped table-condensed">
        % for section in OperationsEvent.event_payload_json.keys():
            <%
                if section == "certificate_ca.ids":
                    header = "CertificateCAs"
                    ids_ = OperationsEvent.event_payload_json[section]
                    url_template = "%s/certificate-ca" % admin_prefix
                elif section == "certificate_ca.ids_fail":
                    header = "CertificateCAs - Failures"
                    ids_ = OperationsEvent.event_payload_json[section]
                    url_template = "%s/certificate-ca" % admin_prefix
                else:
                    continue
            %>
            <thead>
                <tr>
                    <th colspan="2">${header}</th>
                </tr>
            </thead>
            <tbody>
                % for id_ in ids_:
                    <tr>
                        <td></td>
                        <td>
                            <a class="label label-info" href="${url_template}/${id_}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ${id_}
                            </a>
                        </td>
                    </tr>
                % endfor
            </tbody>
        % endfor
    </table>
</%def>

<%def name="table_OperationsObjectEvents(OperationsObjectEvents, table_context=None)">
    <%
        show_event = True
        if table_context == "log_list":
            pass
    %>
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                % if show_event:
                    <th>event: id</th>
                    <th>event: type</th>
                    <th>event: timestamp</th>
                % endif
                <th>id</th>
                <th>event status</th>
                <th>object</th>
            </tr>
        </thead>
        <tbody>
            % for object_event in OperationsObjectEvents:
                <tr>
                    % if show_event:
                        <td>
                            <a class="label label-info" href="${admin_prefix}/operations/log/item/${object_event.operations_event_id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ${object_event.operations_event_id}
                            </a>
                        </td>
                        <td>
                            <code>${object_event.operations_event.event_type_text}</code>
                        </td>
                        <td>
                            <timestamp>${object_event.operations_event.timestamp_event}</timestamp>
                        </td>
                    % endif
                    <td>
                        <a class="label label-info" href="${admin_prefix}/operations/object-log/item/${object_event.id}">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            ${object_event.id}
                        </a>
                    </td>
                    <td>
                        <code>
                            ${object_event.event_status_text}
                        </code>
                    </td>
                    <td>
                        ${object_event__object(object_event)}
                    </td>
                </tr>
            % endfor
        </tbody>
    </table>
</%def>


<%def name="table_PrivateKeys(data, perspective=None)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>active?</th>
                <th>private_key_type</th>
                <th>key_technology</th>
                <th>source</th>
                <th>timestamp first seen</th>
                <th>key_pem_md5</th>
                <th>count active certificates</th>
                ## <th>count certificate requests</th>
                <th>count certificates issued</th>
            </tr>
        </thead>
        % for key in data:
            <tr>
                <td><a class="label label-info" href="${admin_prefix}/private-key/${key.id}">
                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                    PrivateKey-${key.id}</a></td>
                <td>
                    % if key.is_active:
                        <span class="label label-success">
                            active
                        </span>
                    % else:
                        <span class="label label-${'danger' if key.is_compromised else 'warning'}">
                            ${'compromised' if key.is_compromised else 'inactive'}
                        </span>
                    % endif
                </td>
                <td><span class="label label-default">${key.private_key_type}</span></td>
                <td><span class="label label-default">${key.key_technology}</span></td>
                <td><span class="label label-default">${key.private_key_source}</span></td>
                <td><timestamp>${key.timestamp_created}</timestamp></td>
                <td><code>${key.key_pem_md5}</code></td>
                <td><span class="badge">${key.count_active_certificates or ''}</span></td>
                ## <td><span class="badge">${key.count_acme_orders or ''}</span></td>
                <td><span class="badge">${key.count_certificate_signeds or ''}</span></td>
            </tr>
        % endfor
    </table>
</%def>





<%def name="table_RateLimiteds(data, perspective=None)">
    <%
        cols = ("id",
                "timestamp_created",
                "acme_account_id",
                "acme_server_id",
                "acme_order_id",
                "unique_fqdn_set_id",
                "server_response_body",
                "server_response_headers",
               )
        if perspective == 'RateLimited':
            cols = [c for c in cols]
        else:
            raise ValueError("invalid `perspective`")
    %>
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                % for c in cols:
                    <th>
                        ${c}
                    </th>
                % endfor
            </tr>
        </thead>
        <tbody>
            % for rate_limited in data:
                <tr>
                    % for c in cols:
                        <td>
                            % if c == 'id':
                                <a href="${admin_prefix}/rate-limited/${rate_limited.id}" class="label label-info">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    RateLimited-${rate_limited.id}
                                </a>
                            % elif c == 'acme_account_id':
                                <a class="label label-info" href="${admin_prefix}/acme-account/${rate_limited.acme_account_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeAccount-${rate_limited.acme_account_id}
                                </a>
                            % elif c == 'acme_server':
                                <a class="label label-info" href="${admin_prefix}/acme-server/${rate_limited.acme_server_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeServer-${rate_limited.acme_server_id}
                                </a>
                            % elif c == 'acme_order_id':
                                % if rate_limited.acme_order_id:
                                    <a class="label label-info" href="${admin_prefix}/acme-order/${rate_limited.acme_order_id}">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        AcmeOrder-${rate_limited.acme_order_id}
                                    </a>
                                % endif
                            % elif c == 'server_resposne_body':
                                <code>${rate_limited.server_resposne_body}</code>
                            % elif c == 'server_resposne_headers':
                                <code>${rate_limited.server_resposne_headers}</code>
                            % elif c == 'timestamp_created':
                                <timestamp>${rate_limited.timestamp_created or ''}</timestamp>
                            % elif c == 'unique_fqdn_set_id':
                                % if rate_limited.unique_fqdn_set_id:
                                    <a class="label label-info" href="${admin_prefix}/unique-fqdn-set/${rate_limited.unique_fqdn_set_id}">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        UniqueFQDNSet-${rate_limited.unique_fqdn_set_id}
                                    </a>
                                % endif
                            % else:
                                ${getattr(rate_limited, c)}
                            % endif
                        </td>
                    % endfor
                </tr>
            % endfor
        </tbody>
    </table>
</%def>


<%def name="table_RenewalConfigurations(data, perspective=None)">
    <%
        cols = ("id",
                "timestamp_created",
                "acme_account_id__primary",
                "acme_account_id__backup",
                "unique_fqdn_set_id",
                "uniquely_challenged_fqdn_set_id",
               )
        if perspective == 'RenewalConfiguration':
            cols = [c for c in cols]
        elif perspective == 'AcmeAccount':
            cols = [c for c in cols if c not in ("acme_account_id__primary", "acme_account_id__backup")]
        elif perspective == 'UniquelyChallengedFQDNSet':
            cols = [c for c in cols if c != "uniquely_challenged_fqdn_set_id"]
        elif perspective == 'Domain':
            cols = [c for c in cols]
        elif perspective == 'EnrollmentFactory':
            cols = [c for c in cols]
        else:
            raise ValueError("invalid `perspective`")
    %>
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                % for c in cols:
                    <th>
                        ${c}
                    </th>
                % endfor
            </tr>
        </thead>
        <tbody>
            % for renewal_configuration in data:
                <tr>
                    % for c in cols:
                        <td>
                            % if c == 'id':
                                <a href="${admin_prefix}/renewal-configuration/${renewal_configuration.id}" class="label label-info">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    RenewalConfiguration-${renewal_configuration.id}
                                </a>
                            % elif c == 'acme_account_id__primary':
                                <a class="label label-info" href="${admin_prefix}/acme-account/${renewal_configuration.acme_account_id__primary}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeAccount-${renewal_configuration.acme_account_id__primary}
                                </a>
                            % elif c == 'acme_account_id__backup':
                                <a class="label label-info" href="${admin_prefix}/acme-account/${renewal_configuration.acme_account_id__backup}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeAccount-${renewal_configuration.acme_account_id__backup}
                                </a>
                            % elif c == 'unique_fqdn_set_id':
                                <a class="label label-info" href="${admin_prefix}/unique-fqdn-set/${renewal_configuration.unique_fqdn_set_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    UniqueFQDNSet-${renewal_configuration.unique_fqdn_set_id}
                                </a>
                            % elif c == 'uniquely_challenged_fqdn_set_id':
                                <a class="label label-info" href="${admin_prefix}/uniquely-challenged-fqdn-set/${renewal_configuration.uniquely_challenged_fqdn_set_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    UniquelyChallengedFQDNSet-${renewal_configuration.uniquely_challenged_fqdn_set_id}
                                </a>
                            % elif c == 'timestamp_created':
                                <timestamp>${renewal_configuration.timestamp_created or ''}</timestamp>
                            % elif c == 'is_active':
                                <timestamp>${renewal_configuration.is_active or ''}</timestamp>
                            % endif
                        </td>
                    % endfor
                </tr>
            % endfor
        </tbody>
    </table>
</%def>


<%def name="table_RootStores(root_stores)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>name</th>
            </tr>
        </thead>
        <tbody>
        % for i in root_stores:
            <tr>
                <td>
                    <a  class="label label-info"
                        href="${admin_prefix}/root-store/${i.id}"
                    >
                     <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                     RootStore-${i.id}
                    </a>
                </td>
                <td><code>${i.name}</code></td>
            </tr>
        % endfor
        </tbody>
    </table>
</%def>


<%def name="table_RoutineExecutions(routineExecutions)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>routine</th>
                <th>timestamp_start</th>
                <th>timestamp_end</th>
                <th>count_records_processed</th>
                <th>count_records_success</th>
                <th>count_records_fail</th>
                <th>duration_seconds</th>
                <th>average_speed</th>
                <th>is_dry_run</th>
                <th>routine_execution_id__via</th>
            </tr>
        </thead>
        <tbody>
        % for i in routineExecutions:
            <tr>
                <td>
                    <span class="label label-default">${i.id}</span>
                </td>
                <td>
                    <span class="label label-default">${i.routine}</span>
                </td>
                <td><timestamp>${i.timestamp_start_isoformat}</timestamp></td>
                <td><timestamp>${i.timestamp_end_isoformat}</timestamp></td>
                <td><code>${i.count_records_processed}</code></td>
                <td><code>${i.count_records_success}</code></td>
                <td><code>${i.count_records_fail}</code></td>
                <td><code>${i.duration_seconds}</code></td>
                <td><code>${i.average_speed}</code></td>
                <td>
                    % if is_dry_run:
                        <span class="label label-warning">dry-run</span>
                    % endif
                </td>
                <td>
                    % if routine_execution_id__via:
                        <span class="label label-default">${i.id}</span>
                    % endif
                </td>
            </tr>
        % endfor
        </tbody>
    </table>
</%def>


<%def name="table_SystemConfigurations(data, perspective=None)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>name</th>
                <th>configured?</th>
            </tr>
        </thead>
        <tbody>
            % for policy in data:
                <tr>
                    <td><a class="label label-info" href="${admin_prefix}/system-configuration/${policy.slug}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        SystemConfiguration-${policy.id}</a>
                    </td>
                    <td>
                        <span class="label label-default">${policy.name}</span>
                    </td>
                    <td>
                        % if policy.is_configured:
                            <span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span>
                        % else:
                            <span class="label label-danger"><span class="glyphicon glyphicon-remove" aria-hidden="true"></span></span>
                        % endif
                    </td>
                </tr>
            % endfor
        </tbody>
    </table>
</%def>


<%def name="table_UniqueFQDNSets(unique_fqdn_sets, perspective=None)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>timestamp first seen</th>
                <th>domain ids string</th>
            </tr>
        </thead>
        <tbody>
        % for i in unique_fqdn_sets:
            <tr>
                <td>
                    <a  class="label label-info"
                        href="${admin_prefix}/unique-fqdn-set/${i.id}"
                    >
                     <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                     UniqueFQDNSet-${i.id}
                    </a>
                </td>
                <td>
                    <timestamp>${i.timestamp_created}</timestamp>
                </td>
                <td>
                    ## <code>${i.domain_ids_string}</code>
                    <code>${i.domains_as_string}</code>
                </td>
            </tr>
        % endfor
        </tbody>
    </table>
</%def>


<%def name="table_UniqueFQDNSet_Domains(unique_fqdn_set, perspective=None)">
    % if perspective == 'CertificateRequest':
        <table class="table table-striped table-condensed">
            <thead>
                <tr>
                    <th>domain</th>
                </tr>
            </thead>
            <tbody>
                % for to_d in unique_fqdn_set.to_domains:
                    <tr>
                        <td>
                            <a href="${admin_prefix}/domain/${to_d.domain.id}" class="label label-info">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                Domain-${to_d.domain.id}
                            </a>
                            <code>${to_d.domain.domain_name}</code>
                        </td>
                    </tr>
                % endfor
            </tbody>
        </table>
    % else:
        <!-- table_UniqueFQDNSet_Domains missing perspective -->
    % endif
</%def>


<%def name="table_UniquelyChallengedFQDNSets(uniquely_challenged_fqdn_sets, perspective=None)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>domain_string</th>
            </tr>
        </thead>
        <tbody>
        % for i in uniquely_challenged_fqdn_sets:
            <tr>
                <td>
                    <a  class="label label-info"
                        href="${admin_prefix}/uniquely-challenged-fqdn-set/${i.id}"
                    >
                     <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                     UniquelyChallengedFQDNSet-${i.id}
                    </a>
                </td>
                <td>
                    <code>${i.domain_names}</code>
                </td>
            </tr>
        % endfor
        </tbody>
    </table>
</%def>


<%def name="object_event__object(object_event)">
    % if object_event.certificate_ca_id:
        <a class="label label-info" href="${admin_prefix}/certificate-ca/${object_event.certificate_ca_id}">
            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
            CertificateCA-${object_event.certificate_ca_id}
        </a>
    % elif object_event.certificate_request_id:
        <a class="label label-info" href="${admin_prefix}/certificate-request/${object_event.certificate_request_id}">
            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
            CertificateRequest-${object_event.certificate_request_id}
        </a>
    % elif object_event.domain_id:
        <a class="label label-info" href="${admin_prefix}/domain/${object_event.domain_id}">
            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
            Domain-${object_event.domain_id}
        </a>
        <code>${object_event.domain.domain_name}</code>
    % elif object_event.acme_account_id:
        <a class="label label-info" href="${admin_prefix}/acme-account/${object_event.acme_account_id}">
            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
            AcmeAccount-${object_event.acme_account_id}
        </a>
    % elif object_event.acme_account_key_id:
        <a class="label label-info" href="${admin_prefix}/acme-account-key/${object_event.acme_account_key_id}">
            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
            AcmeAccountKey-${object_event.acme_account_key_id}
        </a>
    % elif object_event.private_key_id is not None:
        <a class="label label-info" href="${admin_prefix}/private-key/${object_event.private_key_id}">
            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
            PrivateKey-${object_event.private_key_id}
        </a>
    % elif object_event.certificate_signed_id:
        <a class="label label-info" href="${admin_prefix}/certificate-signed/${object_event.certificate_signed_id}">
            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
            CertificateSigned-${object_event.certificate_signed_id}
        </a>
    % elif object_event.unique_fqdn_set_id:
        <a class="label label-info" href="${admin_prefix}/unique-fqdn-set/${object_event.unique_fqdn_set_id}">
            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
            UniqueFQDNSet-${object_event.unique_fqdn_set_id}
        </a>
    % endif
</%def>


<%def name="info_AcmeAccount()">
    <h3>Need an AcmeAccount?</h3>
    <p>PeterSSLers can help you register for an AcmeAccount, or you can import one from Certbot.</p>
    <ul class="list">
        <li>
            <a  href="${admin_prefix}/acme-account/new"
                class="btn btn-xs btn-primary"
            >
                <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                New AcmeAccount
            </a>
        </li>
        <li>
            <a  href="${admin_prefix}/acme-account/upload"
                class="btn btn-xs btn-primary"
            >
                <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
                Upload AcmeAccount
            </a>
        </li>
    </ul>

    ## <code>http://127.0.0.1:7201/.well-known/peter_sslers/acme-account/new</code>
</%def>


<%def name="info_PrivateKey()">
    <h3>Need a Private Key?</h3>
    <ul class="list">
        <li>PeterSslers will automatically generate new keys for you.</li>
        <li>Alternately:
            <ul class="list">
                <li>
                    <a  href="${admin_prefix}/private-key/new"
                        class="btn btn-xs btn-primary"
                    >
                        <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                        New Private Key
                    </a>
                </li>
                <li>
                    <a  href="${admin_prefix}/private-key/upload"
                        class="btn btn-xs btn-primary"
                    >
                        <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
                        Upload: Private Key
                    </a>
                </li>
            </ul>
        </li>
    </ul>
    <p>NOTE: you can not use your AcmeAccountKey as a PrivateKey for certificate signing</p>
    <p>You can generate a new PrivateKey locally to upload with this command:</p>
    <p>
        <code>openssl genrsa 4096 > private.key</code>
    </p>
    
</%def>


<%def name="info_CertificateCA()">
    <h3>What are CertificateCAs?</h3>
    <p>
        These are the trusted(?) certs that CertificateAuthorities use to sign your certs.
        They are used for building chains and fullchains. Trusted ones may be
        preloaded into your browser or operating system. Often one or more of these
        are 'chain.pem'.
    </p>
</%def>


<%def name="messaging_SystemConfiguration_global()">
    % if not  SystemConfiguration_global.is_configured:
    <div class="alert alert-warning">
        <span class="glyphicon glyphicon-exclamation-sign" aria-hidden="true"></span>
        The global SystemConfiguration is not configured.
        Please configure the policy to set the Global Default and Backup AcmeAccounts.
        <a  class="label label-info"
            href="${admin_prefix}/system-configuration/global"
        >
            <span class="glyphicon glyphicon-edit" aria-hidden="true"></span>
            SystemConfiguration-Global
        </a>
    </div>
    % endif
</%def>


<%def name="formgroup__acme_profile(field_name='acme_profile')">
    <div class="form-group">
        <label for="${field_name}">ACME Profile</label>
        <input
            type="text"
            class="form-control"
            name="${field_name}"
            value=""
        />
        <p class="help">
            Leave this blank for no profile.
            If you want to defer to the AcmeAccount, use the special name <code>@</code>.
        </p>
    </div>
</%def>



<%def name="formgroup__AcmeAccount_select(acmeAccounts=None, default=None, field_name='acme_account_id', allow_none=False)">
    <div class="form-group">
        <label for="${field_name}">ACME Account</label>
        <select class="form-control" name="${field_name}">
            % if allow_none:
                <option value="0"${" selected" if (not default) else ""}>
                    Not Configured
                </option>
            % endif
            % for acc in acmeAccounts:
                <option value="${acc.id}"${" selected" if (acc.id == default) else ""}>
                    ${acc.displayable}
                </option>
            % endfor
        </select>
    </div>
</%def>




<%def name="formgroup__AcmeAccount_selector__advanced(dbAcmeAccountReuse=None, support_upload=False, support_profiles=False, default_profile='', dbSystemConfiguration=None,)">
    <%
        checked = {
            "none": "",
            "account_key_reuse": "",
            "account_key_global_default": "",
        }
        if dbAcmeAccountReuse:
            checked["account_key_reuse"] = 'checked="checked"'
        elif not dbAcmeAccountReuse:
            checked["account_key_global_default"] = 'checked="checked"'
        elif not dbAcmeAccountReuse:
            checked["none"] = 'checked="checked"'
        if not dbSystemConfiguration:
            dbSystemConfiguration = SystemConfiguration_global
            
        acmeAccount_GlobalDefault = SystemConfiguration_global.acme_account__primary
    %>
    <p>Select a Primary AcmeAccount with one of the following options</p>
    <div class="form-horizontal">
        % if dbAcmeAccountReuse:
            <div class="radio">
                <label>
                    <input type="radio" name="account_key_option" id="account_key_option-account_key_reuse" value="account_key_reuse" ${checked["account_key_reuse"]|n}/>
                    <input type="hidden" name="account_key_reuse" value="${dbAcmeAccountReuse.acme_account_key.key_pem_md5}"/>
                    Select to renew with the same AcmeAccount
                </label>
                <p class="form-control-static">
                    <b>resource:</b> <a  class="label label-info"
                                         href="${admin_prefix}/acme-account/${dbAcmeAccountReuse.id}"
                                     >
                                         AcmeAccount-${dbAcmeAccountReuse.id}
                                     </a><br/>
                    <b>pem md5:</b> <code>${dbAcmeAccountReuse.acme_account_key.key_pem_md5}</code><br/>
                    <b>pem line 1:</b> <code>${dbAcmeAccountReuse.acme_account_key.key_pem_sample}</code><br/>
                    <b>known profiles:</b> <code>${dbAcmeAccountReuse.acme_server.profiles}</code><br/>
                    <a  class="label label-info"
                        href="${admin_prefix}/acme-account/${dbAcmeAccountReuse.id}"
                    >
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        AcmeAccount-${dbAcmeAccountReuse.id}
                    </a>
                </p>
            </div>
        % endif
        % if acmeAccount_GlobalDefault:
            <div class="radio">
                <label>
                    <input type="radio" name="account_key_option" id="account_key_option-account_key_global_default" value="account_key_global_default" ${checked["account_key_global_default"]|n}/>
                    The Global Default AcmeAccount.
                </label>
                <p class="form-control-static">
                    <b>resource:</b> <a  class="label label-info"
                                         href="${admin_prefix}/acme-account/${acmeAccount_GlobalDefault.id}"
                                     >
                                         AcmeAccount-${acmeAccount_GlobalDefault.id}
                                     </a><br/>
                    <b>server:</b> <a  class="label label-info"
                                         href="${admin_prefix}/acme-server/${acmeAccount_GlobalDefault.acme_server.id}"
                                     >
                                         AcmeServer-${acmeAccount_GlobalDefault.acme_server.id}
                                     </a>
                                     <span class="label label-default">${acmeAccount_GlobalDefault.acme_server.name}</span>
                                     <br/>
                    <b>pem md5:</b> <code>${acmeAccount_GlobalDefault.acme_account_key.key_pem_md5}</code><br/>
                    <b>pem line 1:</b> <code>${acmeAccount_GlobalDefault.acme_account_key.key_pem_sample}</code><br/>
                    <b>known profiles:</b> <code>${acmeAccount_GlobalDefault.acme_server.profiles}</code><br/>
                    <input type="hidden" name="account_key_global_default" value="${acmeAccount_GlobalDefault.acme_account_key.key_pem_md5}"/>
                </p>
            </div>
        % else:
            <div class="alert alert-warning">
                <span class="glyphicon glyphicon-exclamation-sign" aria-hidden="true"></span>
                There is no Global Default AcmeAccount configured.
                Any Account can be configured as the Global Default through the global SystemConfiguration
                <a  class="label label-info"
                    href="${admin_prefix}/system-configuration/global"
                >
                    <span class="glyphicon glyphicon-edit" aria-hidden="true"></span>
                    SystemConfiguration-global
                </a>
            </div>
        % endif
        <div class="radio">
            <label for="account_key_option-account_key_existing">
                <input type="radio" name="account_key_option" id="account_key_option-account_key_existing" value="account_key_existing"/>
                The PEM MD5 of an AcmeAccountKey already enrolled in the system.
            </label>
            <div class="form-control-static">
               <input class="form-control" name="account_key_existing" id="account_key_option-account_key_existing" type="text"/>
            </div>
        </div>
        <div class="radio">
            <label for="account_key_option-acme_account_id">
                <input type="radio" name="account_key_option" id="account_key_option-acme_account_id" value="acme_account_id"/>
                The internal ID of an ACME Account enrolled in the system.
            </label>
            <div class="form-control-static">
               <input class="form-control" name="acme_account_id" id="account_key_existing-acme_account_id" type="text"/>
            </div>
        </div>
        <div class="radio">
            <label for="account_key_option-acme_account_url">
                <input type="radio" name="account_key_option" id="account_key_option-acme_account_url" value="acme_account_url"/>
                The ACME Account URL (on the ACME Server).
            </label>
            <div class="form-control-static">
               <input class="form-control" name="acme_account_url" id="account_key_existing-acme_account_url" type="text"/>
            </div>
        </div>
        % if support_upload:
            <div class="radio">
                <label>
                    <input type="radio" name="account_key_option" id="account_key_option-account_key_file" value="account_key_file">
                    Upload a new AcmeAccount
                    ${formgroup__AcmeAccount_file()}
                </label>
            </div>
        % endif
        % if support_profiles:
            <label for="acme_profile__primary">
                [Optional] The name of an ACME Profile on the server
            </label>
            <p class="help">
                Leave this blank for no profile.
                If you want to defer to the AcmeAccount, use the special name <code>@</code>.
            </p>
            <div class="form-control-static">
               <input class="form-control" name="acme_profile__primary" id="acme_profile__primary" type="text" value="${default_profile or ""}"/>
            </div>
        % endif
    </div>
</%def>



<%def name="formgroup__AcmeAccount_selector__backup(dbAcmeAccountReuse=None, support_profiles=False, default_profile='', dbSystemConfiguration=None)">
    <%
        checked = {
            "none": "",
            "account_key_reuse_backup": "",
            "account_key_global_backup": "",
        }
        if dbAcmeAccountReuse:
            checked["account_key_reuse_backup"] = 'checked="checked"'
        elif AcmeAccount_GlobalBackup:
            if request.api_context.application_settings["default_backup"] == "global":
                checked["account_key_global_backup"] = 'checked="checked"'
            else:
                checked["none"] = 'checked="checked"'
        else:
            checked["none"] = 'checked="checked"'
        
        if not dbSystemConfiguration:
            dbSystemConfiguration = SystemConfiguration_global
        
        acmeAccount_GlobalBackup = SystemConfiguration_global.acme_account__backup
        
    %>
    <p>Select a Backup AcmeAccount with one of the following options</p>
    <div class="form-horizontal">
        <div class="radio">
            <label>
                <input type="radio" name="account_key_option_backup" id="account_key_option_backup-none" value="none" ${checked["none"]|n}/>
                No Backup Certificate
            </label>
        </div>
        % if dbAcmeAccountReuse:
            <div class="radio">
                <label>
                    <input type="radio" name="account_key_option_backup" id="account_key_option_backup-account_key_reuse" value="account_key_reuse" ${checked["account_key_reuse_backup"]|n}/>
                    <input type="hidden" name="account_key_reuse_backup" value="${dbAcmeAccountReuse.acme_account_key.key_pem_md5}"/>
                    Select to renew with the same AcmeAccount
                </label>
                <p class="form-control-static">
                    <b>resource:</b> <a  class="label label-info"
                                         href="${admin_prefix}/acme-account/${dbAcmeAccountReuse.id}"
                                     >
                                         AcmeAccount-${dbAcmeAccountReuse.id}
                                     </a><br/>
                    <b>pem md5:</b> <code>${dbAcmeAccountReuse.acme_account_key.key_pem_md5}</code><br/>
                    <b>pem line 1:</b> <code>${dbAcmeAccountReuse.acme_account_key.key_pem_sample}</code><br/>
                    <b>known profiles:</b> <code>${dbAcmeAccountReuse.acme_server.profiles}</code><br/>
                    <a  class="label label-info"
                        href="${admin_prefix}/acme-account/${dbAcmeAccountReuse.id}"
                    >
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        AcmeAccount-${dbAcmeAccountReuse.id}
                    </a>
                </p>
            </div>
        % endif
        % if acmeAccount_GlobalBackup:
            <div class="radio">
                <label>
                    <input type="radio" name="account_key_option_backup" id="account_key_option_backup-account_key_global_backup" value="account_key_global_backup" ${checked["account_key_global_backup"]|n}/>
                    The Global Backup AcmeAccount.
                </label>
                <p class="form-control-static">
                    <b>resource:</b> <a  class="label label-info"
                                         href="${admin_prefix}/acme-account/${acmeAccount_GlobalBackup.id}"
                                     >
                                         AcmeAccount-${acmeAccount_GlobalBackup.id}
                                     </a>
                                     <br/>
                    <b>server:</b> <a  class="label label-info"
                                         href="${admin_prefix}/acme-server/${acmeAccount_GlobalBackup.acme_server.id}"
                                     >
                                         AcmeServer-${acmeAccount_GlobalBackup.acme_server.id}
                                     </a>
                                     <span class="label label-default">${acmeAccount_GlobalBackup.acme_server.name}</span>
                                     <br/>
                    <b>pem md5:</b> <code>${acmeAccount_GlobalBackup.acme_account_key.key_pem_md5}</code><br/>
                    <b>pem line 1:</b> <code>${acmeAccount_GlobalBackup.acme_account_key.key_pem_sample}</code><br/>
                    <b>known profiles:</b> <code>${acmeAccount_GlobalBackup.acme_server.profiles}</code><br/>
                    <input type="hidden" name="account_key_global_backup" value="${acmeAccount_GlobalBackup.acme_account_key.key_pem_md5}"/>
                </p>
            </div>
        % else:
            <div class="alert alert-warning">
                <span class="glyphicon glyphicon-exclamation-sign" aria-hidden="true"></span>
                There is no Global Backup AcmeAccount configured.
                The backup can be configured through the Global SystemConfiguration
                <a  class="label label-info"
                    href="${admin_prefix}/system-configuration/global"
                >
                    <span class="glyphicon glyphicon-edit" aria-hidden="true"></span>
                    SystemConfiguration-global
                </a>
            </div>
        % endif
        <div class="radio">
            <label for="account_key_option_backup-account_key_existing">
                <input type="radio" name="account_key_option_backup" id="account_key_option_backup-account_key_existing" value="account_key_existing"/>
                The PEM MD5 of an AcmeAccountKey already enrolled in the system.
            </label>
            <div class="form-control-static">
               <input class="form-control" name="account_key_existing_backup" id="account_key_option_backup-account_key_existing" type="text"/>
            </div>
        </div>
        <div class="radio">
            <label for="account_key_option_backup-acme_account_id_backup">
                <input type="radio" name="account_key_option_backup" id="account_key_option_backup-acme_account_id_backup" value="acme_account_id_backup"/>
                The internal ID of an ACME Account enrolled in the system.
            </label>
            <div class="form-control-static">
               <input class="form-control" name="acme_account_id_backup" id="account_key_option_backup-acme_account_id_backup" type="text"/>
            </div>
        </div>
        <div class="radio">
            <label for="account_key_option_backup-acme_account_url_backup">
                <input type="radio" name="account_key_option_backup" id="account_key_option_backup-acme_account_url_backup" value="acme_account_url_backup"/>
                The ACME Account URL (on the ACME Server).
            </label>
            <div class="form-control-static">
               <input class="form-control" name="acme_account_url_backup" id="account_key_option_backup-acme_account_url_backup" type="text"/>
            </div>
        </div>
        % if support_profiles:
            <label for="acme_profile__backup">
                [Optional] The name of an ACME Profile on the server
            </label>
            <p class="help">
                Leave this blank for no profile.
                If you want to defer to the AcmeAccount, use the special name <code>@</code>.
            </p>
            <div class="form-control-static">
               <input class="form-control" name="acme_profile__backup" id="acme_profile__backup" type="text" value="${default_profile or ""}"/>
            </div>
        % endif
    </div>
</%def>



<%def name="formgroup__AcmeAccount_order_defaults()">
    <div class="form-group">
        <label for="account__order_default_private_key_technology">Orders: Default PrivateKey Technology</label>
        <select class="form-control" name="account__order_default_private_key_technology">
            <% _default = model_websafe.KeyTechnology._DEFAULT_AcmeOrder %>
            % for _option_text in model_websafe.KeyTechnology._options_AcmeAccount_order_default:
                <option value="${_option_text}"${" selected" if (_option_text == _default) else ""}>${_option_text}</option>
            % endfor
        </select>
    </div>
    <div class="form-group">
        <label for="account__order_default_private_key_cycle">Orders: Default PrivateKey Cycling</label>
        <select class="form-control" name="account__order_default_private_key_cycle">
            <% _default = model_websafe.PrivateKeyCycle._DEFAULT_AcmeAccount_order_default %>
            % for _option_text in model_websafe.PrivateKeyCycle._options_AcmeAccount_order_default:
                <option value="${_option_text}"${" selected" if (_option_text == _default) else ""}>${_option_text}</option>
            % endfor
        </select>
    </div>
    <div class="form-group">
        <label for="account__order_default_acme_profile">Orders: Default ACME Profile</label>
        <input type="text" class="form-control" name="account__order_default_acme_profile" value=""/>
    </div>
</%def>


<%def name="formgroup__AcmeAccount_file(show_header=True, show_contact=True)">
    <table class="table table-condensed">
        <thead>
            <tr><th>1) Select Account Defaults</th></tr>
        </thead>
        <tbody>
            <tr><td>
                ${formgroup__AcmeAccount_order_defaults()}
            </td></tr>
        </tbody>
        <thead>
            <tr><th>2) Complete A or B</th></tr>
        </thead>
        <thead>
            <tr><th>A) AcmeAccountKey: PEM</th></tr>
        </thead>
        <tbody>
            <tr><td>
                <p class="help-block">
                    Select your provider, and upload your LetsEncrypt registered AccountKey in PEM format.
                    This is used when requesting the ACME server sign your certificates.
                </p>
                <table class="table table-condensed table-striped">
                    <tr>
                        <th>
                            <label for="f1-acme_server_id">
                                ACME Servers
                            </label>
                        </th>
                        <td>
                            <select class="form-control" id="f1-acme_server_id" name="acme_server_id">
                                % for option in AcmeServers:
                                    <option value="${option.id}" ${'selected' if option.is_default else ''}>${option.name} (${option.url})</option>
                                % endfor
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th>
                            <label for="f1-account_key_file_pem">
                                PEM File
                            </label>
                        </th>
                        <td>
                            <input class="form-control" type="file" id="f1-account_key_file_pem" name="account_key_file_pem" />
                        </td>
                    </tr>
                    <tr>
                        <th>
                            <label for="account__contact">contact</label>
                        </th>
                        <td>
                            <div class="form-group">
                                <input class="form-control" type="text" id="f1-account__contact" name="account__contact" value=""/>
                            </div>
                        </td>
                    </tr>
                </table>
            </td></tr>
        </tbody>
        <thead>
            <tr><th>B) AcmeAccountKey: Certbot Encoding</th></tr>
        </thead>
        <tbody>
            <tr><td>
                <p class="help-block">
                    The provider will be auto-detected.
                </p>
                <table class="table table-condensed table-striped">
                    <tr>
                        <th>
                            <label for="f1-account_key_file_le_meta">LetsEncrypt meta.json</label>
                        </th>
                        <td>
                            <input class="form-control" type="file" id="f1-account_key_file_le_meta" name="account_key_file_le_meta" />
                        </td>
                    </tr>
                    <tr>
                        <th>
                            <label for="f1-account_key_file_le_pkey">LetsEncrypt private_key.json</label>
                        </th>
                        <td>
                            <input class="form-control" type="file" id="f1-account_key_file_le_pkey" name="account_key_file_le_pkey" />
                        </td>
                    </tr>
                    <tr>
                        <th>
                            <label for="f1-account_key_file_le_reg">LetsEncrypt regr.json</label>
                        </th>
                        <td>
                            <input class="form-control" type="file" id="f1-account_key_file_le_reg" name="account_key_file_le_reg" />
                        </td>
                    </tr>
                </table>
            </td></tr>
        </tbody>
    </table>
</%def>


<%def name="formgroup__CertificateCA_Chain_file(show_text=False)">
    <div class="form-group clearfix">
        <label for="f1-chain_file">Chain File</label>
        <input class="form-control" type="file" id="f1-chain_file" name="chain_file" />
        <p class="help-block">
            This should be the public cert chain of the upstream signer.
        </p>
        % if show_text:
            <label for="f1-chain">Chain File [text]</label>
            <textarea class="form-control" rows="4" name="chain" id="f1-chain"></textarea>
            <p class="help-block">
                Alternately, provide text inline.
            </p>
        % endif
    </div>
</%def>


<%def name="formgroup__CertificateCA_Cert_file(show_text=False)">
    <div class="form-group clearfix">
        <label for="f1-cert_file">Cert File</label>
        <input class="form-control" type="file" id="f1-cert_file" name="cert_file" />
        <p class="help-block">
            This should be the public cert of the upstream signer.
        </p>
        % if show_text:
            <label for="f1-cert">Cert File [text]</label>
            <textarea class="form-control" rows="4" name="cert" id="f1-cert"></textarea>
            <p class="help-block">
                Alternately, provide text inline.
            </p>
        % endif
    </div>
</%def>


<%def name="formgroup__Certificate_file(show_text=False)">
    <div class="form-group clearfix">
        <label for="f1-certificate_file">Signed Certificate</label>
        <input class="form-control" type="file" id="f1-certificate_file" name="certificate_file" />
        <p class="help-block">
            Enter a Signed Certificate above in PEM format.
            This is something that has been signed by a CA.
        </p>
        % if show_text:
            <label for="f1-certificate">Signed Certificate [text]</label>
            <textarea class="form-control" rows="4" name="certificate" id="f1-certificate"></textarea>
            <p class="help-block">
                Alternately, provide text inline.
            </p>
        % endif
    </div>
</%def>


<%def name="formgroup__domain_names(
    specify_challenge=None,
    http01_only=False,
    domain_names_http01='',
    domain_names_dns01='',
    AcmeDnsServer_GlobalDefault=None,
)">
    <div class="form-group clearfix">
        % if specify_challenge:
            <label for="f1-domain_names_http01">Domain Names - HTTP-01</label>
            <textarea class="form-control" rows="4" name="domain_names_http01" id="f1-domain_names_http01">${domain_names_http01}</textarea>
            <p class="help-block">
                A comma(,) separated list of domain names to use the default HTTP-01 challenge.
            </p>
            % if not http01_only:
                % if not AcmeDnsServer_GlobalDefault:
                    <label for="f1-domain_names_dns01">Domain Names - DNS-01</label>
                    <p class="help-block">
                        A Global ACME-DNS installation must first be configured.
                    </p>
                % else:
                    <label for="f1-domain_names_dns01">Domain Names - DNS-01</label>
                    <textarea class="form-control" rows="4" name="domain_names_dns01" id="f1-domain_names_dns01">${domain_names_dns01}</textarea>
                    <p class="help-block">
                        A comma(,) separated list of domain names to use the DNS-01 challenge.
                        These domains will be registered to the global ACME-DNS system if they are not already.
                    </p>
                % endif
            % endif
        % else:
            <label for="f1-domain_names">Domain Names</label>
            <textarea class="form-control" rows="4" name="domain_names" id="f1-domain_names"></textarea>
            <p class="help-block">
                A comma(,) separated list of domain names.
            </p>
        % endif
    </div>
</%def>


<%def name="formgroup__domain_templates(default_http01='', default_dns01='')">
    <div class="form-group">
        <p>
            Creating a "RenewalConfiguration" via "EnrollmentFactory" will only 
            require submitting a single Domain Name.  The DomainTemplates will be expanded with the following rules applied to the submitted Domain Name:
            <ul>
                <li><code>{DOMAIN}</code> will be replaced with the registered domain name.
                    <ul>
                        <li><code>`example.com` &raquo; `example.com`</code></li>                                     
                    </ul>
                </li>
                <li><code>{NIAMOD}</code> will be replaced with a modified reverse syntax domain name.
                    <ul>
                        <li><code>`example.com` &raquo; `com.example`</code></li>                                     
                        <li><code>`www.example.com` &raquo; `com.example.www`</code></li>                                     
                        <li><code>`example.co.uk` &raquo; `co.uk.example`</code></li>                                     
                        <li><code>`www.example.co.uk` &raquo; `co.uk.example.www`</code></li>                                     
                    </ul>
                </li>
            </ul>
            AT LEAST ONE of the templates MUST be submitted, and it MUST have one of the two commands above.
        </p>
        <label for="domain_template_http01">Domain Template - HTTP-01</label>
        <textarea class="form-control" rows="4" name="domain_template_http01" id="domain_template_http01">${default_http01}</textarea>
        <hr/>
        <label for="domain_template_dns01">Domain Template - DNS-01</label>
        <textarea class="form-control" rows="4" name="domain_template_dns01" id="domain_template_dns01">${default_dns01}</textarea>
    </div>
</%def>


<%def name="formgroup__is_export_filesystem(default=None, support_enrollment_factory_default=False)">
    <%
        checked = {
            "on": "",
            "off": "",
            "enrollment_factory_default": "",
        }
        if default == "on":
            checked["on"] = 'checked="checked"'
        elif default == "off":
            checked["off"] = 'checked="checked"'
        elif default =="enrollment_factory_default":
            checked["enrollment_factory_default"] = 'checked="checked"'
    
    %>
    <div class="form-group clearfix">
        <label for="is_export_filesystem">Export Filesystem</label>
        <div class="radio">
            <label>
                <input type="radio" name="is_export_filesystem" value="on" ${checked["on"]|n}/>
                On
            </label>
        </div>
        <div class="radio">
            <label>
                <input type="radio" name="is_export_filesystem" value="off" ${checked["off"]|n}/>
                Off
            </label>
        </div>
        % if support_enrollment_factory_default:
            <div class="radio">
                <label>
                    <input type="radio" name="is_export_filesystem" value="enrollment_factory_default" ${checked["enrollment_factory_default"]|n}/>
                    Off
                </label>
            </div>
        % endif
    </div>
</%def>


<%def name="formgroup__key_technology(default=None, options=None, field_name='key_technology', label='')">
    <% default = default or model_websafe.KeyTechnology._DEFAULT %>
    <% options = options or model_websafe.KeyTechnology._options_all %>
    <div class="form-group">
        <label for="${field_name}">Key Technology ${label}</label>
        <select class="form-control" name="${field_name}">
            % for _option_text in options:
                <option value="${_option_text}"${" selected" if (_option_text == default) else ""}>${_option_text}</option>
            % endfor
        </select>
    </div>
</%def>


<%def name="formgroup__label(default='', context_enrollment_factory=False)">
    <div class="form-group">
        <label for="label">Label</label>
        <input class="form-control" type="text" name="label" id="label" value="${default or ''}"/>
        <p>
            A label may only have the following characters: letters, numbers, dash, period, underscore.
            Labels are only used when exporting certificate data.
            % if context_enrollment_factory:
                If used in the context of an Enrollment Factory, it supports the <code>{DOMAIN}</code> and <code>{NIAMOD}</code> macros.
            % endif
        </p>
    </div>
</%def>


<%def name="formgroup__label_template(default='')">
    <div class="form-group">
        <label for="label_template">Label Template</label>
        <input class="form-control" type="text" name="label_template" id="label_template" value="${default or ''}"/>
        <p>
            A `label template` is used to generate the label for a RenewalConfiguration.  It can use the <code>{DOMAIN}</code> and <code>{NIAMOD}</code> macros.
        </p>
    </div>
</%def>


<%def name="formgroup__name(default='')">
    <div class="form-group">
        <label for="name">Name</label>
        <input class="form-control" type="text" name="name" id="name" value="${default or ''}"/>
    </div>
</%def>


<%def name="formgroup__note(default='')">
    <div class="form-group">
        <label for="note">Note</label>
        <textarea class="form-control" rows="4" name="note" id="note">${default or ''}</textarea>
    </div>
</%def>


<%def name="formgroup__processing_strategy()">
    <div class="form-group clearfix">
        <label for="processing_strategy">Processing Strategy</label>
        <div class="radio">
            <label>
                <input type="radio" name="processing_strategy" value="create_order" checked="checked"/>
                Create the AcmeOrder
            </label>
        </div>
        <div class="radio">
            <label>
                <input type="radio" name="processing_strategy" value="process_single" />
                Create the AcmeOrder; Attempt to Process in a single request
            </label>
        </div>
        <div class="radio">
            <label>
                <input type="radio" name="processing_strategy" value="process_multi"/>
                Create the AcmeOrder; Attempt to Process with multiple requests
            </label>
        </div>
    </div>
</%def>


<%def name="formgroup__private_key_cycle(default=None, field_name='private_key_cycle', label='')">
    <% default = default or model_websafe.PrivateKeyCycle._DEFAULT_AcmeOrder %>
    <div class="form-group">
        <label for="${field_name}">Private Key Cycle - Renewals ${label}</label>
        <select class="form-control" name="${field_name}">
            % for _option_text in model_websafe.PrivateKeyCycle._options_RenewalConfiguration_private_key_cycle:
                <option value="${_option_text}"${" selected" if (_option_text == default) else ""}>${_option_text}</option>
            % endfor
        </select>
    </div>
</%def>




<%def name="formgroup__PrivateKey_selector__advanced(show_text=None, dbPrivateKeyReuse=None, option_account_default=None, option_generate_new=None, default=None, support_upload=None, concept=None)">
    <%
        if concept not in ("primary", "backup"):
            concept = "primary"
        _checked = ' checked="checked"'
        selected = {
            "private_key_reuse": "",
            "account_default": "",
            "private_key_generate": "",
            "private_key_existing": "",
            "private_key_file_pem": "",
        }
        if default is not None:
            selected[default] = _checked
        else:
            if dbPrivateKeyReuse:
                if option_account_default:
                    selected["account_default"] = _checked
                else:
                    selected["private_key_reuse"] = _checked
            else:
                selected["account_default"] = _checked
    %>
    <p>Select a PrivateKey with one of the following options</p>
    <div class="form-horizontal">
        % if option_account_default:
            <div class="radio">
                <label for="private_key_option-account_default">
                    <input type="radio" name="private_key_option" id="private_key_option-account_default" value="account_default" ${selected["account_default"]|n}>
                    Use the AcmeAccount&#39;s Default PrivateKey Settings
                </label>
            </div>
        % endif
        % if dbPrivateKeyReuse:
            <div class="radio">
                <label>
                    <input type="radio" name="private_key_option" id="private_key_option-private_key_reuse" value="private_key_reuse"${selected["private_key_reuse"]|n}/>
                    <input type="hidden" name="private_key_reuse" value="${dbPrivateKeyReuse.key_pem_md5}"/>
                    Select to renew with the same PrivateKey
                </label>
                <p class="form-control-static">
                    <b>resource:</b> <a  class="label label-info"
                                         href="${admin_prefix}/private-key/${dbPrivateKeyReuse.id}"
                                     >
                                         PrivatetKey-${dbPrivateKeyReuse.id}
                                     </a><br/>
                    <b>pem md5:</b> <code>${dbPrivateKeyReuse.key_pem_md5}</code><br/>
                    <b>pem line 1:</b> <code>${dbPrivateKeyReuse.key_pem_sample}</code><br/>
                    <a  class="label label-info"
                        href="${admin_prefix}/private-key/${dbPrivateKeyReuse.id}"
                    >
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        PrivateKey-${dbPrivateKeyReuse.id}
                    </a>
                </p>
            </div>
        % endif        
        % if option_generate_new:
            <div class="radio">
                <label for="private_key_option-private_key_generate">
                    <input type="radio" name="private_key_option" id="private_key_option-private_key_generate" value="private_key_generate" ${selected["private_key_generate"]|n}>
                    Generate a new Private Key

                    <select class="form-control" id="private_key_option-private_key_generate-select" name="private_key_generate">
                        <% _default = model_websafe.KeyTechnology._DEFAULT_Generate %>
                        % for _option_text in model_websafe.KeyTechnology._options_Generate:
                            <option value="${_option_text}"${" selected" if (_option_text == _default) else ""}>${_option_text}</option>
                        % endfor
                    </select>
                    
                </label>
            </div>
        % endif
        <div class="radio">
            <label for="private_key_option-private_key_existing">
                <input type="radio" name="private_key_option" id="private_key_option-private_key_existing" value="private_key_existing"/>
                The PEM MD5 of a PrivateKey already enrolled in the system.
            </label>
            <div class="form-control-static">
               <input class="form-control" name="private_key_existing" id="private_key_existing-pem_md5" type="text"/>
            </div>
        </div>
        % if support_upload:
            <div class="radio">
                <label for="private_key_option-private_key_file_pem">
                    <input type="radio" name="private_key_option" id="private_key_option-private_key_file_pem" value="private_key_file_pem">
                    Upload a new PrivateKey
                        ${formgroup__PrivateKey_file()}
                </label>
            </div>
        % endif
    </div>
</%def>


<%def name="formgroup__PrivateKey_file()">
    <table class="table table-condensed">
        <thead>
            <tr><th>PrivateKey: PEM</th></tr>
        </thead>
        <tbody>
            <tr><td>
                <p class="help-block">
                    Upload a RSA PrivateKey in PEM format.
                    This will be used to sign CertificateRequests and is required for CertificateSigned deployment.
                    The key will be saved into the system.
                </p>
                <table class="table table-condensed table-striped">
                    <tr>
                        <th>
                            <label for="f1-private_key_file_pem">
                                PEM File
                            </label>
                        </th>
                        <td>
                            <input class="form-control" type="file" id="f1-private_key_file_pem" name="private_key_file_pem" />
                        </td>
                    </tr>
                </table>
            </td></tr>
        </tbody>
    </table>
</%def>


<%def name="nav_pagination(pager)">
    <% if not pager: return '' %>
    <center>
        <nav>
            <ul class="pagination">
                % if pager.start > 1:
                    <li>
                        <a href="${pager.template.format(max(pager.current-pager.range_num, 1))}" aria-label="Previous">
                            <span aria-hidden="true">&laquo;</span>
                        </a>
                    </li>
                % endif
                % for p in pager.pages:
                    <li ${'class="active"' if pager.current == p else ''|n}><a href="${pager.template.format(p)}">${p}</a></li>
                % endfor
                % if pager.end < pager.page_num:
                    <li>
                        <a href="${pager.template.format(min(pager.start+pager.range_num, pager.page_num-pager.range_num))}" aria-label="Next">
                            <span aria-hidden="true">&raquo;</span>
                        </a>
                    </li>
                % endif
            </ul>
        </nav>
    </center>
</%def>


<%def name="nav_pager(see_all_url, see_all_text='See All')">
    <nav>
      <ul class="pager">
        <li>
            <a
                href="${see_all_url}"
            >${see_all_text}</a>
        </li>
      </ul>
    </nav>
</%def>


<%def name="operations_options(enable_redis=False, enable_nginx=False, as_list=None, active=None)">
    <h4>Actions</h4>
    <ul class="nav nav-pills nav-stacked">
        <li class="${'active' if active =='/api/deactivate-expired' else ''}">
            <form action="${admin_prefix}/api/deactivate-expired" method="POST">
                <button class="btn btn-xs btn-primary" type="submit"  name="submit" value="submit">
                    <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                    Deactivate Expired CertificateSigneds
                </button>
            </form>
        </li>
        <li class="${'active' if active =='/api/update-recents' else ''}">
            <form action="${admin_prefix}/api/update-recents" method="POST">
                <button class="btn btn-xs btn-primary" type="submit"  name="submit" value="submit">
                    <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                    Update Recents
                </button>
            </form>
        </li>
        <li class="${'active' if active =='/api/update-recents.json' else ''}">
            <form action="${admin_prefix}/api/update-recents.json" method="POST">
                <button class="btn btn-xs btn-primary" type="submit"  name="submit" value="submit">
                    <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                    update-recents.json
                </button>
            </form>
        </li>
        <li class="${'active' if active =='/api/reconcile-ca' else ''}">
            <form action="${admin_prefix}/api/reconcile-cas" method="POST">
                <button class="btn btn-xs btn-primary" type="submit"  name="submit" value="submit">
                    <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                    Reconcile CAs
                </button>
            </form>
        </li>
        % if enable_redis:
            <li>
                <form action="${admin_prefix}/api/redis/prime" method="POST">
                    <button class="btn btn-xs btn-primary" type="submit"  name="submit" value="submit">
                        <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                        Prime Redis Cache
                    </button>
                </form>
            </li>
            <li>
                <form action="${admin_prefix}/api/redis/prime.json" method="POST">
                    <button class="btn btn-xs btn-primary" type="submit"  name="submit" value="submit">
                        <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                        Prime Redis Cache - JSON
                    </button>
                </form>
            </li>
        % endif
        % if enable_nginx:
            <li>
                <form action="${admin_prefix}/api/nginx/cache-flush" method="POST">
                    <button class="btn btn-xs btn-primary" type="submit"  name="submit" value="submit">
                        <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                        Flush Nginx Cache
                    </button>
                </form>
            </li>
            <li>
                <form action="${admin_prefix}/api/nginx/cache-flush.json" method="POST">
                    <button class="btn btn-xs btn-primary" type="submit"  name="submit" value="submit">
                        <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                        Flush Nginx Cache - JSON
                    </button>
                </form>
            </li>
        % endif
    </ul>
    <h4>Log</h4>
    <ul class="nav nav-pills nav-stacked">
        <li class="${'active' if active =='/operations/log' else ''}">
            <a  href="${admin_prefix}/operations/log"
            >
            <span class="glyphicon glyphicon-folder-open" aria-hidden="true"></span>
            Full Operations Log</a></li>
        % if enable_redis:
            <li class="${'active' if active =='/operations/redis' else ''}">
                <a  href="${admin_prefix}/operations/redis"
                >
                <span class="glyphicon glyphicon-folder-open" aria-hidden="true"></span>
                Operations Log: Redis</a></li>
        % endif
        % if enable_nginx:
            <li class="${'active' if active =='/operations/nginx' else ''}">
                <a  href="${admin_prefix}/operations/nginx"
                >
                <span class="glyphicon glyphicon-folder-open" aria-hidden="true"></span>
                Operations Log: Nginx</a></li>
        % endif
        <li class="${'active' if active =='/operations/object-log' else ''}">
            <a  href="${admin_prefix}/operations/object-log"
            >
            <span class="glyphicon glyphicon-folder-open" aria-hidden="true"></span>
            Object Log</a></li>
    </ul>
</%def>


<%def name="domains_section_nav()">
    <ul class="nav nav-pills nav-stacked">
      <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="${admin_prefix}/domains">All Domains</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'expiring' else ''}"><a href="${admin_prefix}/domains/expiring">Expiring Domains</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'challenged' else ''}"><a href="${admin_prefix}/domains/challenged">Challenged Domains</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'authz-potential' else ''}"><a href="${admin_prefix}/domains/authz-potential">Authorization Potentials</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'search' else ''}"><a href="${admin_prefix}/domains/search">Search Domains</a></li>
    </ul>
    <p class="pull-right">
        % if sidenav_option == 'expiring' :
            <a href="${admin_prefix}/domains/expiring.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        % elif sidenav_option == 'challenged' :
            <a href="${admin_prefix}/domains/challenged.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        % elif sidenav_option == 'authz-potential' :
            <a href="${admin_prefix}/domains/authz-potential.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        % elif sidenav_option == 'all' :
            <a href="${admin_prefix}/domains.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        % elif sidenav_option == 'search' :
            <a href="${admin_prefix}/domains/search.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        % endif
    </p>
</%def>


<%def name="acme_challenges_section_nav()">
    <ul class="nav nav-pills nav-stacked">
      <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="${admin_prefix}/acme-challenges">All AcmeChallenges</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'active' else ''}"><a href="${admin_prefix}/acme-challenges?status=active">Active AcmeChallenges</a></li>
      <li role="presentation" class="${'resolved' if sidenav_option == 'resolved' else ''}"><a href="${admin_prefix}/acme-challenges?status=resolved">Resolved AcmeChallenges</a></li>
      <li role="presentation" class="${'processing' if sidenav_option == 'processing' else ''}"><a href="${admin_prefix}/acme-challenges?status=processing">Processing AcmeChallenges</a></li>
    </ul>
    <p class="pull-right">
        % if sidenav_option == 'all' :
            <a href="${admin_prefix}/acme-challenges.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        % elif sidenav_option == 'active' :
            <a href="${admin_prefix}/acme-challenges.json?status=active" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        % elif sidenav_option == 'resolved' :
            <a href="${admin_prefix}/acme-challenges.json?status=resolved" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        % elif sidenav_option == 'processing' :
            <a href="${admin_prefix}/acme-challenges.json?status=processing" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        % endif
    </p>
</%def>


<%def name="handle_querystring_result()">
    <%
        import pprint
        result = request.params.get('result', '')
    %>
    % if result in ("success", "error"):
        % if result == 'success':
            <div class="alert alert-success">
        % elif result == 'error':
            <div class="alert alert-danger">
        % endif
            % if result == 'success':
                <p>
                    The operation `${request.params.get('operation')}` was successful.
                </p>
                % if request.params.get('message'):
                    <p>
                        Message: `${request.params.get('message')}`
                    </p>
                % endif
                % if _AriCheck:
                    ${pprint.pformat(_AriCheck)|n}
                % endif
            % elif result == 'error':
                % if request.params.get('operation'):
                    <p>
                        The operation `${request.params.get('operation')}` was not successful.
                    </p>
                % endif
                % if request.params.get('error'):
                    <p>
                        Error: `${request.params.get('error')}`
                    </p>
                % endif
                % if request.params.get('error-encoded'):
                    <p>
                        Error: `${unurlify(request.params.get('error-encoded'))}`
                    </p>
                % endif
            % endif
            % if request.params.get('message'):
                <p>
                    Message: `${request.params.get('message')}`
                </p>
            % endif
            % if request.params.get('check-ari'):
                <p>
                    Check-Ari Result: `${request.params.get('check-ari')}`
                </p>
            % endif
            % if request.params.get('check-support'):
                <p>
                    Check-Support Result: `${request.params.get('check-support')}`
                </p>
            % endif
        </div>
    % endif
</%def>



<%def name="tr_PreferredChallenges(PreferredChallenges=None)">
    <tr>
        <th>PreferredChallenges</th>
        <td>
            <em>If no ChallengeTypes are preferred, the default HTTP-01 challenge will be used.</em>
            % if PreferredChallenges:
                <table class=" table-striped table-condensed">
                    <thead>
                        <tr>
                            <th>AcmeOrder</th>
                            <th>UniquelyChallengedFQDNSet</th>
                        </tr>
                    </thead>
                    <tbody>
                        % for (dbAcmeOrder, dbUniquelyChallengedFQDNSet2Domain) in PreferredChallenges:
                            <tr>
                                <td>
                                    <a class="label label-info" href="${admin_prefix}/acme-order/${dbAcmeOrder.id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeOrder-${dbAcmeOrder.id}</a>
                                </td>
                                <td>
                                    <a class="label label-info" href="${admin_prefix}/uniquely-challenged-fqdn-set/${dbUniquelyChallengedFQDNSet2Domain.uniquely_challenged_fqdn_set_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    UniquelyChallengedFQDNSet-${dbUniquelyChallengedFQDNSet2Domain.uniquely_challenged_fqdn_set_id}</a>
                                    <code>${model_websafe.AcmeChallengeType._mapping[dbUniquelyChallengedFQDNSet2Domain.acme_challenge_type_id]}</code>
                                </td>
                            </tr>
                        % endfor
                    </tbody>
                </table>
            % endif
        </td>
    </tr>
</%def>
