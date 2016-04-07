<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Domains</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Domains</h2>
    These domains are known to the system.
</%block>


<%block name="content_main">
    <div class="col-sm-9">
        % if expiring_days:
            <p>Domains that will be expiring within `${expiring_days}` days.
            </p>
        % endif
        % if LetsencryptDomains:
            ${admin_partials.nav_pagination(pager)}
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>id</th>
                        <th>domain name</th>
                        <th>is active</th>
                        <th>latest_certificate_multi</th>
                        <th>latest_certificate_single</th>
                    </tr>
                    <tr>
                        <th></th>
                        <th></th>
                        <th></th>
                        <th>id, expiring, days</th>
                        <th>id, expiring, days</th>
                    </tr>
                </thead>
                % for d in LetsencryptDomains:
                    <tr>
                        <td>
                            <a  class="label label-info"
                                href="${admin_prefix}/domain/${d.id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ${d.id}</a>
                        </td>
                        <td><code>${d.domain_name}</code></td>
                        <td>
                            <span class="label label-${'success' if d.is_active else 'warning'}">
                                ${'Active' if d.is_active else 'inactive'}
                            </span>
                        </td>
                        <td>
                            % if d.letsencrypt_server_certificate_id__latest_multi:
                                <a  class="label label-info"
                                    href="${admin_prefix}/certificate/${d.letsencrypt_server_certificate_id__latest_multi}"
                                    >
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        ${d.letsencrypt_server_certificate_id__latest_multi}</a>
                                <timestamp>${d.latest_certificate_multi.timestamp_expires}</timestamp>
                                <span class="label label-${d.latest_certificate_multi.expiring_days_label}">${d.latest_certificate_multi.expiring_days} days</span>
                            % endif
                        </td>
                        <td>
                            % if d.letsencrypt_server_certificate_id__latest_single:
                                <a  class="label label-info"
                                    href="${admin_prefix}/certificate/${d.letsencrypt_server_certificate_id__latest_single}"
                                    >
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        ${d.letsencrypt_server_certificate_id__latest_single}</a>
                                <timestamp>${d.latest_certificate_single.timestamp_expires}</timestamp>
                                <span class="label label-${d.latest_certificate_single.expiring_days_label}">${d.latest_certificate_single.expiring_days} days</span>
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
        <div class="col-sm-3">
            <ul class="nav nav-pills nav-stacked">
              <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="${admin_prefix}/domains">All Domains</a></li>
              <li role="presentation" class="${'active' if sidenav_option == 'expiring' else ''}"><a href="${admin_prefix}/domains/expiring">Expiring Domains</a></li>
            </ul>
        </div>
    </div>
</%block>
