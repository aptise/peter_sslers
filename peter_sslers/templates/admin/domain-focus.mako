<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/domains">Domains</a></li>
        <li class="active">Focus [${SslDomain.id}]</li>
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
    <a  class="btn btn-info"
        href="${admin_prefix}/domain/${SslDomain.id}/calendar"
        target="_blank"
    >
        Calendar
    </a>
</%block>



<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <table class="table">
                <tr>
                    <th>id</th>
                    <td>
                        <span class="label label-default">
                            ${SslDomain.id}
                        </span>
                    </td>
                </tr>
                <tr>
                    <th>domain_name</th>
                    <td><code>${SslDomain.domain_name}</code></td>
                </tr>
                <tr>
                    <th>timestamp_first_seen</th>
                    <td><timestamp>${SslDomain.timestamp_first_seen}</timestamp></td>
                </tr>
                <tr>
                    <th>is_active</th>
                    <td>
                        <span class="label label-${'success' if SslDomain.is_active else 'warning'}">
                            ${'Active' if SslDomain.is_active else 'inactive'}
                        </span>

                        % if SslDomain.is_active:
                            &nbsp;
                            <a  class="label label-warning"
                                href="${admin_prefix}/domain/${SslDomain.id}/mark?action=inactive"
                            >
                                <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                inactive
                            </a>
                        % else:
                            &nbsp;
                            <a  class="label label-success"
                                href="${admin_prefix}/domain/${SslDomain.id}/mark?action=active"
                            >
                                <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                active
                            </a>
                        % endif

                    </td>
                </tr>
                <tr>
                    <th>json_config</th>
                    <td>
                        <a  class="btn btn-xs btn-info"
                            href="${admin_prefix}/domain/${SslDomain.id}/config.json"
                        >
                            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                            config.json</a>
                    </td>
                </tr>
                % if request.registry.settings['enable_nginx']:
                    <tr>
                        <th>nginx cache</th>
                        <td>
                            <a  class="btn btn-xs btn-primary"
                                href="${admin_prefix}/domain/${SslDomain.id}/nginx-cache-expire"
                            >
                                <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                nginx-cache-expire</a>
                            <a  class="btn btn-xs btn-primary"
                                href="${admin_prefix}/domain/${SslDomain.id}/nginx-cache-expire.json"
                                target="_blank"
                            >
                                <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                nginx-cache-expire.json</a>
                        </td>
                    </tr>
                % endif
                <tr>
                    <th>certificates recent</th>
                    <td>
                        <table class="table">
                            <tr>
                                <th>latest_single</th>
                                <td>
                                    % if SslDomain.ssl_server_certificate_id__latest_single:
                                        ${admin_partials.table_certificates__list([SslDomain.server_certificate__latest_single,], show_domains=True, show_expiring_days=True)}
                                    % endif
                                </td>
                            </tr>
                            <tr>
                                <th>latest_multi</th>
                                <td>
                                    % if SslDomain.ssl_server_certificate_id__latest_multi:
                                        ${admin_partials.table_certificates__list([SslDomain.server_certificate__latest_multi,], show_domains=True, show_expiring_days=True)}
                                    % endif
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
                <tr>
                    <th>certificates history</th>
                    <td>
                        ${admin_partials.table_certificates__list(SslDomain.server_certificates__5, show_domains=True, show_expiring_days=True)}
                        % if SslDomain.server_certificates__5:
                            ${admin_partials.nav_pager("%s/domain/%s/certificates" % (admin_prefix, SslDomain.id))}
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>certificate requests</th>
                    <td>
                        ${admin_partials.table_to_certificate_requests(SslDomain.to_certificate_requests__5)}
                        % if SslDomain.to_certificate_requests__5:
                            ${admin_partials.nav_pager("%s/domain/%s/certificate-requests" % (admin_prefix, SslDomain.id))}
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>unique FQDN Sets</th>
                    <td>
                        ${admin_partials.table_SslUniqueFQDNSets([i.unique_fqdn_set for i in SslDomain.to_unique_fqdn_sets__5])}
                        % if SslDomain.to_unique_fqdn_sets__5:
                            ${admin_partials.nav_pager("%s/domain/%s/unique-fqdn-sets" % (admin_prefix, SslDomain.id))}
                        % endif
                    </td>
                </tr>
            </table>
        </div>
    </div>
</%block>
