<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Domains</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Domains</h2>
    These domains are known to the system.
</%block>


<%block name="page_header_nav">
    ${admin_partials.domains_section_nav()}
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if expiring_days:
                <p>Domains that will be expiring within `${expiring_days}` days.
                </p>
            % endif
            % if Domains:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>domain name</th>
                            <th>is active</th>
                            <th>server_certificate__latest_multi</th>
                            <th>server_certificate__latest_single</th>
                        </tr>
                        <tr>
                            <th></th>
                            <th></th>
                            <th></th>
                            <th>id, expiring, days</th>
                            <th>id, expiring, days</th>
                        </tr>
                    </thead>
                    % for d in Domains:
                        <tr>
                            <td>
                                <a  class="label label-info"
                                    href="${admin_prefix}/domain/${d.id}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    domain-${d.id}</a>
                            </td>
                            <td><code>${d.domain_name}</code></td>
                            <td>
                                <span class="label label-${'success' if d.is_active else 'warning'}">
                                    ${'Active' if d.is_active else 'inactive'}
                                </span>
                            </td>
                            <td>
                                % if d.server_certificate_id__latest_multi:
                                    <a  class="label label-info"
                                        href="${admin_prefix}/certificate/${d.server_certificate_id__latest_multi}"
                                    >
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        cert-${d.server_certificate_id__latest_multi}</a>
                                    <timestamp>${d.server_certificate__latest_multi.timestamp_expires}</timestamp>
                                    <span class="label label-${d.server_certificate__latest_multi.expiring_days_label}">${d.server_certificate__latest_multi.expiring_days} days</span>
                                % endif
                            </td>
                            <td>
                                % if d.server_certificate_id__latest_single:
                                    <a  class="label label-info"
                                        href="${admin_prefix}/certificate/${d.server_certificate_id__latest_single}"
                                    >
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        cert-${d.server_certificate_id__latest_single}</a>
                                    <timestamp>${d.server_certificate__latest_single.timestamp_expires}</timestamp>
                                    <span class="label label-${d.server_certificate__latest_single.expiring_days_label}">${d.server_certificate__latest_single.expiring_days} days</span>
                                % endif
                            </td>
                        </tr>
                    % endfor
                </table>
            % else:
                <em>
                    No Domains
                </em>
            % endif
            </div>
        </div>
    </div>
</%block>
