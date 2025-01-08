<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-authorizations">ACME Authorization</a></li>
        <li class="active">Focus [${AcmeAuthorization.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>ACME Authorization - Focus</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-authorization/${AcmeAuthorization.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    ${admin_partials.handle_querystring_result()}
    
    <div class="row">
        <div class="col-sm-12">
            <table class="table">
                <thead>
                    <tr>
                        <th colspan="2">
                            ACME Server Operations
                        </th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <th>Sync</th>
                        <td>
                            <% _btn_class = '' if AcmeAuthorization.is_can_acme_server_sync else 'disabled' %>
                            <form method="POST"
                                action="${admin_prefix}/acme-authorization/${AcmeAuthorization.id}/acme-server/sync"
                                id="form-acme_server-sync"
                            >
                                <button class="btn btn-xs btn-info ${_btn_class}" id="btn-acme_authorization-sync">
                                    <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                    Sync AcmeAuthorization Against ACME Server 
                                </button>
                            </form>

                            <% _btn_class = '' if AcmeAuthorization.is_can_acme_server_deactivate else 'disabled' %>
                            <form method="POST"
                                action="${admin_prefix}/acme-authorization/${AcmeAuthorization.id}/acme-server/deactivate"
                                id="form-acme_server-deactivate"
                            >
                                <button class="btn btn-xs btn-info ${_btn_class}" id="btn-acme_authorization-deactivate">
                                    <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                    Deactivate Against ACME Server
                                </button>
                            </form>
                        </td>
                    </tr>
                </tbody>
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
                                ${AcmeAuthorization.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>authorization_url</th>
                        <td><code>${AcmeAuthorization.authorization_url or ''}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>timestamp_created</th>
                        <td><timestamp>${AcmeAuthorization.timestamp_created or ''}</timestamp>
                        </td>
                    </tr>
                    <tr>
                        <th>domain</th>
                        <td>
                            % if AcmeAuthorization.domain_id:
                                <a class="label label-info" href="${admin_prefix}/domain/${AcmeAuthorization.domain_id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                Domain-${AcmeAuthorization.domain_id}</a>
                                <code>${AcmeAuthorization.domain.domain_name}</code>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>timestamp_expires</th>
                        <td><timestamp>${AcmeAuthorization.timestamp_expires or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>pending</th>
                        <td>
                            % if AcmeAuthorization.is_acme_server_pending:
                                <span class="label label-success"><span class="glyphicon glyphicon-ok" aria-hidden="true"></span></span>
                            % else:
                                <span class="label label-default"><span class="glyphicon glyphicon-remove" aria-hidden="true"></span></span>
                            % endif
                        </td>
                    </tr>

                    <tr>
                        <th>status</th>
                        <td><code>${AcmeAuthorization.acme_status_authorization or ''}</code></td>
                    </tr>
                    <tr>
                        <th>timestamp_updated</th>
                        <td><timestamp>${AcmeAuthorization.timestamp_updated or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>timestamp_deactivated</th>
                        <td><timestamp>${AcmeAuthorization.timestamp_deactivated or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>wildcard</th>
                        <td><code>${AcmeAuthorization.wildcard or ''}</code></td>
                    </tr>
                    % if False:
                        <tr>
                            <th>AcmeChallenge - http01</th>
                            <td>
                                % if AcmeAuthorization.acme_challenge_http_01:
                                    <a class="label label-info" href="${admin_prefix}/acme-challenge/${AcmeAuthorization.acme_challenge_http_01.id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeChallenge-${AcmeAuthorization.acme_challenge_http_01.id}</a>
                                % endif
                            </td>
                        </tr>
                    % endif
                    <tr>
                        <th>AcmeOrder - authz first created</th>
                        <td>
                            <em>An AcmeAuthorization may be associated with more than one AcmeOrder.</em>
                            <a class="label label-info" href="${admin_prefix}/acme-order/${AcmeAuthorization.acme_order_id__created}">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            AcmeOrder-${AcmeAuthorization.acme_order_id__created}</a>
                        </td>
                    </tr>
                    <tr>
                        <th>UniquelyChallengedFQDNSet2Domain</th>
                        <td>
                            <em>If no ChallengeTypes are preferred, the default HTTP-01 challenge will be used.</em>
                            ## TODO: Show Orders
                            <table class=" table-striped table-condensed">
                                <thead>
                                    <tr>
                                        <th>UniquelyChallengedFQDNSet</th>
                                        <th>Preferred Challenge Type</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    % for item in UniquelyChallengedFQDNSet2Domain:
                                        <tr>
                                            <td>
                                                <a class="label label-info" href="${admin_prefix}/uniquely-challenged-fqdn-set/${item.uniquely_challenged_fqdn_set_id}">
                                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                UniquelyChallengedFQDNSet-${item.uniquely_challenged_fqdn_set_id}</a>
                                            </td>
                                            <td>
                                                <code>${model_websafe.AcmeChallengeType._mapping[item.acme_challenge_type_id]}</code>
                                            </td>
                                        </tr>
                                    % endfor
                                </tbody>
                            </table>

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
                        <th>AcmeChallenges(s)</th>
                        <td>
                            % if AcmeAuthorization.acme_challenges__5:
                                ${admin_partials.table_AcmeChallenges(AcmeAuthorization.acme_challenges__5, perspective="AcmeAuthorization")}
                                ${admin_partials.nav_pager("%s/acme-authorization/%s/acme-challenges" % (admin_prefix, AcmeAuthorization.id))}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeOrder(s)</th>
                        <td>
                            % if AcmeAuthorization.acme_orders__5:
                                ${admin_partials.table_AcmeOrders(AcmeAuthorization.acme_orders__5, perspective="AcmeAuthorization")}
                                ${admin_partials.nav_pager("%s/acme-authorization/%s/acme-orders" % (admin_prefix, AcmeAuthorization.id))}
                            % endif
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</%block>
