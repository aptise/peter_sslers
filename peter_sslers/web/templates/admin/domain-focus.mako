<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/domains">Domains</a></li>
        <li class="active">Focus [${Domain.id}]</li>
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
            <table class="table">
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
                    <th>timestamp_first_seen</th>
                    <td><timestamp>${Domain.timestamp_first_seen}</timestamp></td>
                </tr>
                <tr>
                    <th>is_active</th>
                    <td>
                        <span class="label label-${'success' if Domain.is_active else 'warning'}">
                            ${'Active' if Domain.is_active else 'inactive'}
                        </span>

                        % if Domain.is_active:
                            &nbsp;
                            <form action="${admin_prefix}/domain/${Domain.id}/mark" method="POST" style="display:inline;">
                                <input type="hidden" name="action" value="inactive"/>
                                <button class="btn btn-xs btn-warning" type="submit">
                                    <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                    inactive
                                </button>
                            </form>
                        % else:
                            &nbsp;
                            <form action="${admin_prefix}/domain/${Domain.id}/mark" method="POST" style="display:inline;">
                                <input type="hidden" name="action" value="active"/>
                                <button class="btn btn-xs btn-success" type="submit">
                                    <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                    active
                                </button>
                            </form>
                        % endif

                    </td>
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
                % if request.registry.settings['enable_nginx']:
                    <tr>
                        <th>Nginx cache</th>
                        <td>
                            <span class="btn-group">
                                <a  class="btn btn-xs btn-primary"
                                    href="${admin_prefix}/domain/${Domain.id}/nginx-cache-expire"
                                >
                                    <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                    nginx-cache-expire</a>
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
                    <th>Certificates Recent</th>
                    <td>
                        <table class="table">
                            <tr>
                                <th>latest_single</th>
                                <td>
                                    % if Domain.server_certificate_id__latest_single:
                                        ${admin_partials.table_certificates__list([Domain.server_certificate__latest_single,], show_domains=True, show_expiring_days=True)}
                                    % endif
                                </td>
                            </tr>
                            <tr>
                                <th>latest_multi</th>
                                <td>
                                    % if Domain.server_certificate_id__latest_multi:
                                        ${admin_partials.table_certificates__list([Domain.server_certificate__latest_multi,], show_domains=True, show_expiring_days=True)}
                                    % endif
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
                <tr>
                    <th>Certificates</th>
                    <td>
                        ${admin_partials.table_certificates__list(Domain.server_certificates__5, show_domains=True, show_expiring_days=True)}
                        % if Domain.server_certificates__5:
                            ${admin_partials.nav_pager("%s/domain/%s/certificates" % (admin_prefix, Domain.id))}
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
                    <th>UniqueFQDNSets</th>
                    <td>
                        ${admin_partials.table_UniqueFQDNSets([i.unique_fqdn_set for i in Domain.to_unique_fqdn_sets__5], perspective="Domain")}
                        % if Domain.to_unique_fqdn_sets__5:
                            ${admin_partials.nav_pager("%s/domain/%s/unique-fqdn-sets" % (admin_prefix, Domain.id))}
                        % endif
                    </td>
                </tr>
            </table>
        </div>
    </div>
</%block>
