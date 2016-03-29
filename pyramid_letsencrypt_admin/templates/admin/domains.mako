<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li class="active">Domains</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Domains</h2>
    These domains are known to the system.
</%block>
    

<%block name="content_main">
    % if LetsencryptDomains:
        ${admin_partials.nav_pagination(pager)}
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>id</th>
                    <th>domain name</th>
                    <th>latest_certificate_multi</th>
                    <th>latest_certificate_single</th>
                </tr>
                <tr>
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
                            href="/.well-known/admin/domain/${d.id}">&gt; ${d.id}</a>
                    </td>
                    <td>${d.domain_name}</td>
                    <td>
                        % if d.letsencrypt_server_certificate_id__latest_multi:
                            <a  class="label label-info"
                                href="/.well-known/admin/certificate/${d.letsencrypt_server_certificate_id__latest_multi}"
                                >&gt; ${d.letsencrypt_server_certificate_id__latest_multi}</a>
                            <timestamp>${d.latest_certificate_multi.timestamp_expires}</timestamp>
                            <span class="label label-${d.latest_certificate_multi.expiring_days_label}">${d.latest_certificate_multi.expiring_days}</span>
                        % endif
                    </td>
                    <td>
                        % if d.letsencrypt_server_certificate_id__latest_single:
                            <a  class="label label-info"
                                href="/.well-known/admin/certificate/${d.letsencrypt_server_certificate_id__latest_single}"
                                >&gt; ${d.letsencrypt_server_certificate_id__latest_single}</a>
                            <timestamp>${d.latest_certificate_single.timestamp_expires}</timestamp>
                            <span class="label label-${d.latest_certificate_single.expiring_days_label}">${d.latest_certificate_single.expiring_days}</span>
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
</%block>
