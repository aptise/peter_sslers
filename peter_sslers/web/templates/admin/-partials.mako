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
    <table class="table table-striped">
        <thead>
            <tr>
                <th>id</th>
                <th><!-- active --></th>
                <th><!-- global_default --></th>
                <th>provider</th>
                <th>timestamp first seen</th>
                <th>key_pem_md5</th>
                <th>count certificate requests</th>
                <th>count certificates issued</th>
            </tr>
        </thead>
        <tbody>
            % for account in data:
                <tr>
                    <td><a class="label label-info" href="${admin_prefix}/acme-account/${account.id}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        AcmeAccount-${account.id}</a></td>
                    <td>
                        % if account.is_active:
                            <span class="label label-success">active</span>
                        % endif
                    </td>
                    <td>
                        % if account.is_global_default:
                            <span class="label label-success">global default</span>
                        % endif
                    </td>
                    <td>
                        <span class="label label-info">${account.acme_account_provider.name}</span>
                        <a class="label label-info" href="${admin_prefix}/acme-account-providers">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            AcmeAccountProvider-${account.acme_account_provider_id}</a>
                            ## <code>${account.acme_account_provider.url}</code>
                    </td>
                    <td><timestamp>${account.timestamp_created}</timestamp></td>
                    <td><code>${account.acme_account_key.key_pem_md5}</code></td>
                    <td><span class="badge">${account.count_acme_orders or ''}</span></td>
                    <td><span class="badge">${account.count_certificate_signeds or ''}</span></td>
                </tr>
            % endfor
        </tbody>
    </table>
</%def>



<%def name="table_AcmeAccountKeys(data, perspective=None)">
    <table class="table table-striped">
        <thead>
            <tr>
                <th>id</th>
                <th>acme_account_id</th>
                <th><!-- active --></th>
                <th>source</th>
                <th>provider</th>
                <th>timestamp first seen</th>
                <th>key_pem_md5</th>
            </tr>
        </thead>
        <tbody>
            % for key in data:
                <tr>
                    <td><a class="label label-info" href="${admin_prefix}/acme-account-key/${key.id}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        AcmeAccountKey-${key.id}</a></td>
                    <td><a class="label label-info" href="${admin_prefix}/acme-account/${key.acme_account_id}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        AcmeAccount-${key.acme_account_id}</a></td>
                    <td>
                        % if key.is_active:
                            <span class="label label-success">active</span>
                        % endif
                    </td>
                    <td><span class="label label-default">${key.acme_account_key_source}</span></td>
                    <td><span class="label label-info">${key.acme_account.acme_account_provider.name}</span></td>
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
    <table class="table table-striped">
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
                % if perspective != "AcmeDnsServer":
                    <th>AcmeDnsServer</th>
                % endif
                % if perspective != "Domain":
                    <th>Domain</th>
                % endif
                <th>Focus</th>
                <th>active</th>
            </tr>
        </thead>
        <tbody>
            % for a2d in AcmeDnsServerAccounts:
                <tr>
                    % if perspective != "AcmeDnsServer":
                        <td>
                            <a href="${admin_prefix}/acme-dns-server/${a2d.acme_dns_server_id}" class="label label-info">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeDnsServer-${a2d.acme_dns_server_id} | ${a2d.acme_dns_server.root_url}
                            </a>
                        </td>
                    % endif
                    % if perspective != "Domain":
                        <td>
                            <a href="${admin_prefix}/domain/${a2d.domain_id}" class="label label-info">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                Domain-${a2d.domain_id} | ${a2d.domain.domain_name} 
                            </a>
                        </td>
                    % endif
                    <td>
                        <a href="${admin_prefix}/acme-dns-server-account/${a2d.id}" class="label label-info">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            acme-dns Account Focus
                        </a>
                    </td>
                    <td>
                        <code>${a2d.is_active}</code>
                    </td>
                </tr>
            % endfor
        </tbody>
    </table>
</%def>


<%def name="table_AcmeEventLogs(acme_event_logs, perspective=None)">
    <table class="table table-striped">
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


<%def name="table_AcmeOrderlesss(acme_orderlesss, perspective=None)">
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>is active</th>
                <th>AcmeAccount</th>
                <th>timestamp_created</th>
                <th>timestamp_finalized</th>
            </tr>
        </thead>
        <tbody>
            % for order_ in acme_orderlesss:
                <tr>
                    <td>
                        <a href="${admin_prefix}/acme-orderless/${order_.id}" class="label label-info">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            AcmeOrderless-${order_.id}
                        </a>
                    </td>
                    <td>
                        % if order_.is_processing:
                            <div class="label label-success">
                                <span class="glyphicon glyphicon-ok" aria-hidden="true"></span>
                            </div>
                        % else:
                            <div class="label label-danger">
                                <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                            </div>
                        % endif
                    </td>
                    <td>
                        % if order_.acme_account_id:
                            <a href="${admin_prefix}/acme-account/${order_.acme_account_id}" class="label label-info">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeAccount-${order_.id}
                            </a>
                        % endif
                    </td>
                    <td><timestamp>${order_.timestamp_created or ''}</timestamp></td>
                    <td><timestamp>${order_.timestamp_finalized or ''}</timestamp></td>
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
                "is_auto_renew",
                "is_renewed",
                "timestamp_created",
                "timestamp_finalized",
                "acme_account_id",
                "certificate_request_id",
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
        elif perspective == 'UniqueFQDNSet':
            cols = [c for c in cols if c != "unique_fqdn_set_id"]
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
                            % elif c == 'is_auto_renew':
                                <div class="label label-${'success' if acme_order.is_auto_renew else 'warning'}">
                                    ${'AutoRenew' if acme_order.is_auto_renew else 'manual'}
                                </div>
                            % elif c == 'is_renewed':
                                <div class="label label-${'success' if acme_order.is_renewed else 'default'}">
                                    ${'Renewed' if acme_order.is_renewed else 'not-renewed-yet'}
                                </div>
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
                            % elif c == 'certificate_signed_id':
                                % if acme_order.certificate_signed_id:
                                    <a href="${admin_prefix}/certificate-signed/${acme_order.certificate_signed_id}" class="label label-info">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        CertificateSigned-${acme_order.certificate_signed_id}
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


<%def name="table_CertificateRequests(certificate_requests, perspective=None)">
    <%
        show_domains = True if perspective in ("PrivateKey", 'CertificateRequest', ) else False
        show_certificate = True if perspective in ("CertificateSigned", 'CertificateRequest', ) else False
    %>
    <%
        cols = ("id",
                "type"
                "timestamp_created",
                "certificate_request_source_id",
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
                        <td>
                            % if c == 'id':
                                <a  class="label label-info"
                                    href="${admin_prefix}/certificate-request/${certificate_request.id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    CertificateRequest-${certificate_request.id}</a>
                            % elif c == 'type':
                                <span class="label label-default">${certificate_request.certificate_request_source}</span>
                            % elif c == 'timestamp_created':
                                <timestamp>${certificate_request.timestamp_created}</timestamp>
                            % elif c == 'certificate_request_source_id':
                                <span class="label label-default">${certificate_request.certificate_request_source}</span>
                            % elif c == 'unique_fqdn_set_id':
                                <a  class="label label-info"
                                    href="${admin_prefix}/unique-fqdn-set/${certificate_request.unique_fqdn_set_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    UniqueFQDNSet-${certificate_request.unique_fqdn_set_id}</a>
                            % endif
                        </td>
                        % if show_domains:
                             <td><code>${certificate_request.domains_as_string}</code></td>
                        % endif
                    % endfor
                </tr>
            % endfor
        </tbody>
    </table>
</%def>


<%def name="table_CoverageAssuranceEvents(CoverageAssuranceEvents)">
    <table class="table table-striped">
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
                <th>Queue Certificate</th>
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
                <td>
                    % if cae.queue_certificate_id:
                        <a  class="label label-info"
                            href="${admin_prefix}/queue-certificate/${cae.queue_certificate_id}"
                        >
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            QueueCertificate-${cae.queue_certificate_id}</a>
                    % endif
                </td>
            </tr>
        % endfor
    </table>
</%def>


<%def name="table_DomainAutocerts(domain_autocerts, perspective=None)">
    <table class="table table-striped">
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
    <table class="table table-striped">
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
                <th>count certificate requests</th>
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
                <td><span class="badge">${key.count_acme_orders or ''}</span></td>
                <td><span class="badge">${key.count_certificate_signeds or ''}</span></td>
            </tr>
        % endfor
    </table>
</%def>


<%def name="table_QueueCertificates(renewal_items, perspective=None)">
    <%
        show_unique_fqdn_set = False if perspective == "UniqueFQDNSet" else True
    %>
    <table class="table table-striped table-condensed">
        <thead>
            <tr>
                <th>id</th>
                <th>active?</th>
                <th>result</th>
                % if show_unique_fqdn_set:
                    <th>UniqueFQDNSet</th>
                % endif
                <th>Source</th>
                <th>Acme Order (Generated)</th>
                <th>Server Certificate (Generated)</th>
                <th>timestamp_created</th>
                <th>operations_event_id__created</th>
                <th>timestamp_processed</th>
                <th>timestamp_process_attempt</th>
            </tr>
        </thead>
        <tbody>
        % for queue_certificate in renewal_items:
            <tr>
                <td><a href="${admin_prefix}/queue-certificate/${queue_certificate.id}" class="label label-info">
                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                    QueueCertificate-${queue_certificate.id}</a>
                </td>
                <td>
                    <span class="label label-${'success' if queue_certificate.is_active else 'warning'}">
                        ${'active' if queue_certificate.is_active else 'no'}
                    </span>
                </td>
                <td>
                    % if queue_certificate.process_result is None:
                        &nbsp;
                    % elif queue_certificate.process_result is False:
                        <span class="label label-danger"><span class="glyphicon glyphicon-remove" aria-hidden="true"></span></span>
                    % elif queue_certificate.process_result is True:
                        <span class="label label-success"><span class="glyphicon glyphicon-ok" aria-hidden="true"></span></span>
                    % endif
                </td>
                % if show_unique_fqdn_set:
                    <td>
                        <a href="${admin_prefix}/unique-fqdn-set/${queue_certificate.unique_fqdn_set_id}" class="label label-info">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            UniqueFQDNSet-${queue_certificate.unique_fqdn_set_id}</a>
                    </td>
                % endif
                <td>
                    % if queue_certificate.acme_order_id__source:
                        <a class="label label-info" href="${admin_prefix}/acme-order/${queue_certificate.acme_order_id__source}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        AcmeOrder-${queue_certificate.acme_order_id__source}</a>
                    % endif
                    % if queue_certificate.certificate_signed_id__source:
                        <a class="label label-info" href="${admin_prefix}/certificate-signed/${queue_certificate.certificate_signed_id__source}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        CertificateSigned-${queue_certificate.certificate_signed_id__source}</a>
                    % endif
                    % if queue_certificate.unique_fqdn_set_id__source:
                        <a class="label label-info" href="${admin_prefix}/unique-fqdn-set/${queue_certificate.unique_fqdn_set_id__source}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        UniqueFQDNSet-${queue_certificate.unique_fqdn_set_id__source}</a>
                    % endif
                </td>
                <td>
                    % if queue_certificate.acme_order_id__generated:
                        <a href="${admin_prefix}/acme-order/${queue_certificate.acme_order_id__generated}" class="label label-info">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            AcmeOrder-${queue_certificate.acme_order_id__generated}</a>
                    % endif
                </td>
                <td>
                    % if queue_certificate.certificate_signed_id__generated:
                        <a href="${admin_prefix}/certificate-signed/${queue_certificate.certificate_signed_id__generated}" class="label label-info">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            CertificateSigned-${queue_certificate.certificate_signed_id__generated}</a>
                    % endif
                </td>
                <td><timestamp>${queue_certificate.timestamp_created or ''}</timestamp></td>
                <td><span class="label label-info">${queue_certificate.operations_event_id__created}</span></td>
                <td><timestamp>${queue_certificate.timestamp_processed or ''}</timestamp></td>
                <td><timestamp>${queue_certificate.timestamp_process_attempt or ''}</timestamp></td>
            </tr>
        % endfor
        </tbody>
    </table>
</%def>


<%def name="table_CertificateSigneds(certificates, perspective=None, show_domains=False, show_expiring_days=False)">
    <table class="table table-striped">
        <thead>
            <tr>
                <th>id</th>
                <th>active?</th>
                <th>auto-renew?</th>
                <th>is renewed?</th>
                <th>timestamp_not_before</th>
                <th>timestamp_not_after</th>
                % if show_expiring_days:
                    <th>expiring days</th>
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
                </td>
                <td>
                    % if cert.renewals_managed_by == "AcmeOrder":
                        <div class="label label-${'success' if (cert.acme_order and cert.acme_order.is_auto_renew) else 'warning'}">
                            ${'AutoRenew' if (cert.acme_order and cert.acme_order.is_auto_renew) else 'manual'}
                            via AcmeOrder
                        </div>
                    % elif cert.renewals_managed_by == "CertificateSigned":
                        <div class="label label-warning">
                            unavailable
                            ## via CertificateSigned
                        </div>
                    % endif
                </td>
                <td>
                    <div class="label label-${'success' if (cert.acme_order and cert.acme_order.is_renewed) else 'default'}">
                        ${'Renewed' if (cert.acme_order and cert.acme_order.is_renewed) else 'not-renewed-yet'}
                    </div>
                </td>
                <td><timestamp>${cert.timestamp_not_before}</timestamp></td>
                <td><timestamp>${cert.timestamp_not_after}</timestamp></td>
                % if show_expiring_days:
                    <td>
                        <span class="label label-${cert.expiring_days_label}">
                            ${cert.expiring_days} days
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
    % elif object_event.queue_domain_id:
        <a class="label label-info" href="${admin_prefix}/queue-domain/${object_event.queue_domain_id}">
            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
            QueueDomain-${object_event.queue_domain_id}
        </a>
        <code>${object_event.queue_domain.domain_name}</code>
    % elif object_event.queue_certificate_id:
        <a class="label label-info" href="${admin_prefix}/queue-certificate/${object_event.queue_certificate_id}">
            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
            QueueCertificate-${object_event.queue_certificate_id}
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

    ## <code>http://127.0.0.1:7201/.well-known/admin/acme-account/new</code>
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
        These are the trusted(?) certs that CertificateAuthorities use to sign your certs.  They are used for building fullchains.
        Often these are called 'chain.pem'.
    </p>
</%def>


<%def name="formgroup__AcmeAccount_selector__advanced(dbAcmeAccountReuse=None, allow_no_key=False)">
    <%
        checked = {
            "none": "",
            "account_key_reuse": "",
            "account_key_global_default": "",
        }
        if dbAcmeAccountReuse:
            checked["account_key_reuse"] = 'checked="checked"'
        elif not dbAcmeAccountReuse and not allow_no_key:
            checked["account_key_global_default"] = 'checked="checked"'
        elif not dbAcmeAccountReuse and allow_no_key:
            checked["none"] = 'checked="checked"'
    %>
    <p>Select an AcmeAccount with one of the following options</p>
    <div class="form-horizontal">
        % if allow_no_key:
            <div class="radio">
                <label>
                    <input type="radio" name="account_key_option" id="account_key_option-none" value="none" ${checked["none"]}/>
                    Do not associate this Orderless with an AcmeAccount
                </label>
            </div>
        % endif
        % if dbAcmeAccountReuse:
            <div class="radio">
                <label>
                    <input type="radio" name="account_key_option" id="account_key_option-account_key_reuse" value="account_key_reuse" ${checked["account_key_reuse"]}/>
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
                    <a  class="label label-info"
                        href="${admin_prefix}/acme-account/${dbAcmeAccountReuse.id}"
                    >
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        AcmeAccount-${dbAcmeAccountReuse.id}
                    </a>
                </p>
            </div>
        % endif
        % if AcmeAccount_GlobalDefault:
            <div class="radio">
                <label>
                    <input type="radio" name="account_key_option" id="account_key_option-account_key_global_default" value="account_key_global_default" ${checked["account_key_global_default"]}/>
                    The Global Default AcmeAccount.
                </label>
                <p class="form-control-static">
                    <b>resource:</b> <a  class="label label-info"
                                         href="${admin_prefix}/acme-account/${AcmeAccount_GlobalDefault.id}"
                                     >
                                         AcmeAccount-${AcmeAccount_GlobalDefault.id}
                                     </a><br/>
                    <b>server:</b> <code>${AcmeAccount_GlobalDefault.acme_account_provider.server}</code><br/>
                    <b>pem md5:</b> <code>${AcmeAccount_GlobalDefault.acme_account_key.key_pem_md5}</code><br/>
                    <b>pem line 1:</b> <code>${AcmeAccount_GlobalDefault.acme_account_key.key_pem_sample}</code>
                    <input type="hidden" name="account_key_global_default" value="${AcmeAccount_GlobalDefault.acme_account_key.key_pem_md5}"/>
                </p>
            </div>
        % else:
            <div class="alert alert-warning">
                <span class="glyphicon glyphicon-exclamation-sign" aria-hidden="true"></span>
                There is no Global Default AcmeAccount configured. Any key can be configured as the Global Default.
                Browse keys at
                <a  class="label label-info"
                    href="${admin_prefix}/acme-accounts"
                >
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    AcmeAccounts
                </a>
            </div>
        % endif
        <div class="radio">
            <label for="account_key_option-account_key_existing">
                <input type="radio" name="account_key_option" id="account_key_option-account_key_existing" value="account_key_existing"/>
                The PEM MD5 of an AcmeAccountKey already enrolled in the system.
            </label>
            <div class="form-control-static">
               <input class="form-control" name="account_key_existing" id="account_key_existing-pem_md5" type="text"/>
            </div>
        </div>
        <div class="radio">
            <label>
                <input type="radio" name="account_key_option" id="account_key_option-account_key_file" value="account_key_file">
                Upload a new AcmeAccount
                ${formgroup__AcmeAccount_file()}
            </label>
        </div>
    </div>
</%def>


<%def name="formgroup__AcmeAccount_file(show_header=True, show_contact=True)">
    <table class="table table-condensed">
        <thead>
            <tr><th>Private Key Cycling (*required)</th></tr>
        </thead>
        <tbody>
            <tr><td>
                <div class="form-group">
                    <select class="form-control" name="account__private_key_cycle">
                        <% _default = model_websafe.PrivateKeyCycle._DEFAULT_AcmeAccount %>
                        % for _option_text in model_websafe.PrivateKeyCycle._options_AcmeAccount_private_key_cycle:
                            <option value="${_option_text}"${" selected" if (_option_text == _default) else ""}>${_option_text}</option>
                        % endfor
                    </select>
                </div>
            </td></tr>
        </tbody>
        <thead>
            <tr><th>Complete A or B</th></tr>
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
                            <label for="f1-acme_account_provider_id">
                                ACME Provider
                            </label>
                        </th>
                        <td>
                            <select class="form-control" id="f1-acme_account_provider_id" name="acme_account_provider_id">
                                % for option in AcmeAccountProviders:
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
                            <label for="contact">contact</label>
                        </th>
                        <td>
                            <div class="form-group">
                                <input class="form-control" type="text" name="account__contact" value=""/>
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


<%def name="formgroup__domain_names(specify_challenge=None, http01_only=False)">
    <div class="form-group clearfix">
        % if specify_challenge:
            <label for="f1-domain_names_http01">Domain Names - HTTP-01</label>
            <textarea class="form-control" rows="4" name="domain_names_http01" id="f1-domain_names_http01"></textarea>
            <p class="help-block">
                A comma(,) separated list of domain names to use the default HTTP-01 challenge.
            </p>
            % if not http01_only:
                <label for="f1-domain_names_dns01">Domain Names - DNS-01</label>
                <textarea class="form-control" rows="4" name="domain_names_dns01" id="f1-domain_names_dns01"></textarea>
                <p class="help-block">
                    A comma(,) separated list of domain names to use the DNS-01 challenge. These domains must be registered with an ACME-DNS system known to this installation.
                </p>
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


<%def name="formgroup__private_key_cycle__renewal(default=None)">
    <% default = default or model_websafe.PrivateKeyCycle._DEFAULT_AcmeOrder %>
    <div class="form-group">
        <label for="private_key_cycle__renewal">Private Key Cycle - Renewals</label>
        <select class="form-control" name="private_key_cycle__renewal">
            % for _option_text in model_websafe.PrivateKeyCycle._options_AcmeOrder_private_key_cycle:
                <option value="${_option_text}"${" selected" if (_option_text == default) else ""}>${_option_text}</option>
            % endfor
        </select>
    </div>
</%def>


<%def name="formgroup__PrivateKey_selector__advanced(show_text=None, dbPrivateKeyReuse=None, option_account_key_default=None, option_generate_new=None, default=None)">
    <%
        _checked = ' checked="checked"'
        selected = {
            "private_key_reuse": "",
            "private_key_for_account_key": "",
            "private_key_generate": "",
            "private_key_existing": "",
            "private_key_file_pem": "",
        }
        if default is not None:
            selected[default] = _checked
        else:
            if dbPrivateKeyReuse:
                if option_account_key_default:
                    selected["private_key_for_account_key"] = _checked
                else:
                    selected["private_key_reuse"] = _checked
            else:
                selected["private_key_for_account_key"] = _checked
    %>
    <p>Select a PrivateKey with one of the following options</p>
    <div class="form-horizontal">
        % if option_account_key_default:
            <div class="radio">
                <label for="private_key_option-private_key_for_account_key">
                    <input type="radio" name="private_key_option" id="private_key_option-private_key_for_account_key" value="private_key_for_account_key" ${selected["private_key_for_account_key"]}>
                    Use the AcmeAccount&#39;s Default PrivateKey or Strategy
                </label>
            </div>
        % endif
        % if dbPrivateKeyReuse:
            <div class="radio">
                <label>
                    <input type="radio" name="private_key_option" id="private_key_option-private_key_reuse" value="private_key_reuse"${selected["private_key_reuse"]}/>
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
                    <input type="radio" name="private_key_option" id="private_key_option-private_key_generate" value="private_key_generate" ${selected["private_key_generate"]}>
                    Generate a new PrivateKey with 4096 bits.
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
        <div class="radio">
            <label for="private_key_option-private_key_file_pem">
                <input type="radio" name="private_key_option" id="private_key_option-private_key_file_pem" value="private_key_file_pem">
                Upload a new PrivateKey
                    ${formgroup__PrivateKey_file()}
            </label>
        </div>
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
            <a  href="${admin_prefix}/api/deactivate-expired"
            >
             <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
             Deactivate Expired CertificateSigneds</a></li>
        <li class="${'active' if active =='/api/update-recents' else ''}">
            <a  href="${admin_prefix}/api/update-recents"
            >
             <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
             Update Recents</a></li>
        % if enable_redis:
            <li>
                <a  href="${admin_prefix}/api/redis/prime"
                >
                    <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                    Prime Redis Cache
                </a>
            </li>
            <li>
                <a  href="${admin_prefix}/api/redis/prime.json"
                >
                    <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                    Prime Redis Cache - JSON
                </a>
            </li>
        % endif
        % if enable_nginx:
            <li>
                <a  href="${admin_prefix}/api/nginx/cache-flush"
                >
                    <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                    Flush Nginx Cache
                </a>
            </li>
            <li>
                <a  href="${admin_prefix}/api/nginx/cache-flush.json"
                >
                    <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                    Flush Nginx Cache - JSON
                </a>
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
        <li class="${'active' if active =='/operations/certificate-ca-downloads' else ''}">
            <a  href="${admin_prefix}/operations/certificate-ca-downloads"
            >
            <span class="glyphicon glyphicon-folder-open" aria-hidden="true"></span>
            Operations Log: CertificateCA Downloads</a></li>
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
    <% result =  request.params.get('result', '') %>
    % if result == 'success':
        <div class="alert alert-success">
            <p>
                The operation `${request.params.get('operation')}` was successful.
            </p>
            % if request.params.get('message'):
                <p>
                    Message: `${request.params.get('message')}`
                </p>
            % endif
        </div>
    % elif result == 'error':
        <div class="alert alert-danger">
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
            % if request.params.get('message'):
                <p>
                    Message: `${request.params.get('message')}`
                </p>
            % endif
        </div>
    % endif
</%def>
