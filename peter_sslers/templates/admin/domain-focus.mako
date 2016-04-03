<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li><a href="/.well-known/admin/domains">Domains</a></li>
        <li class="active">Focus [${LetsencryptDomain.id}]</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Domain Focus</h2>
</%block>

    
<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">

    <table class="table">
        <tr>
            <th>id</th>
            <td>
                <span class="label label-default">
                    ${LetsencryptDomain.id}
                </span>
            </td>
        </tr>
        <tr>
            <th>domain_name</th>
            <td>${LetsencryptDomain.domain_name}</td>
        </tr>
        <tr>
            <th>json_config</th>
            <td>
                <a  class="btn btn-xs btn-info"
                    href="/.well-known/admin/domain/${LetsencryptDomain.id}/config.json"
                >config.json</a>
            </td>
        </tr>
        % if request.registry.settings['enable_nginx']:
            <tr>
                <th>nginx cache</th>
                <td>
                    <a  class="btn btn-xs btn-primary"
                        href="/.well-known/admin/domain/${LetsencryptDomain.id}/nginx_cache_expire"
                    >nginx_cache_expire</a>
                    <a  class="btn btn-xs btn-primary"
                        href="/.well-known/admin/domain/${LetsencryptDomain.id}/nginx_cache_expire.json"
                    >nginx_cache_expire.json</a>
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
                            % if LetsencryptDomain.letsencrypt_server_certificate_id__latest_single:
                                ${admin_partials.table_certificates__list([LetsencryptDomain.latest_certificate_single,], show_domains=True, show_expiring_days=True)}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>latest_multi</th>
                        <td>
                            % if LetsencryptDomain.letsencrypt_server_certificate_id__latest_multi:
                                ${admin_partials.table_certificates__list([LetsencryptDomain.latest_certificate_multi,], show_domains=True, show_expiring_days=True)}
                            % endif
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr>
            <th>certificates history</th>
            <td>
                ${admin_partials.table_to_certificates(LetsencryptDomain.domain_to_certificates_5, show_domains=True, show_expiring_days=True)}
                % if LetsencryptDomain.domain_to_certificates_5:
                    ${admin_partials.nav_pager("/.well-known/admin/domain/%s/certificates" % LetsencryptDomain.id)}
                % endif
            </td>
        </tr>
        <tr>
            <th>certificate requests</th>
            <td>
                ${admin_partials.table_to_certificate_requests(LetsencryptDomain.domain_to_certificate_requests_5)}
                % if LetsencryptDomain.domain_to_certificate_requests_5:
                    ${admin_partials.nav_pager("/.well-known/admin/domain/%s/certificate_requests" % LetsencryptDomain.id)}
                % endif
            </td>
        </tr>
        <tr>
            <th>unique FQDN Sets</th>
            <td>
                ${admin_partials.nav_pager("/.well-known/admin/domain/%s/unique_fqdn_sets" % LetsencryptDomain.id)}
            </td>
        </tr>
    </table>
    
        </div>
        <div class="col-sm-3">
            <a  class="btn btn-info"
                href="/.well-known/admin/domain/${LetsencryptDomain.id}/calendar"
            >
                Calendar
            </a>
        </div>
    </div>

</%block>
