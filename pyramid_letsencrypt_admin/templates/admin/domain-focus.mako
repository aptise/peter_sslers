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
            <th>certificates recent</th>
            <td>
                <table class="table">
                    <tr>
                        <th>latest_single</th>
                        <td>
                            % if LetsencryptDomain.letsencrypt_server_certificate_id__latest_single:
                                ${admin_partials.table_certificates__list([LetsencryptDomain.latest_certificate_single,], show_domains=True)}
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>latest_multi</th>
                        <td>
                            % if LetsencryptDomain.letsencrypt_server_certificate_id__latest_multi:
                                ${admin_partials.table_certificates__list([LetsencryptDomain.latest_certificate_multi,], show_domains=True)}
                            % endif
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr>
            <th>certificates history</th>
            <td>
                ${admin_partials.table_to_certificates(LetsencryptDomain.domain_to_certificates, show_domains=True)}
                % if LetsencryptDomain.domain_to_certificates:
                    <nav>
                      <ul class="pager">
                        <li>
                            <a 
                                href="/.well-known/admin/domain/${LetsencryptDomain.id}/certificates"
                            >See All</a>
                        </li>
                      </ul>
                    </nav>
                % endif
            </td>
        </tr>
        <tr>
            <th>certificate requests</th>
            <td>
                ${admin_partials.table_to_certificate_requests(LetsencryptDomain.domain_to_certificate_requests)}
                % if LetsencryptDomain.domain_to_certificate_requests:
                    <nav>
                      <ul class="pager">
                        <li>
                            <a 
                                href="/.well-known/admin/domain/${LetsencryptDomainLetsencryptDomain.id}/certificate_requests"
                            >See All</a>
                        </li>
                      </ul>
                    </nav>
                % endif
            </td>
        </tr>
    </table>

</%block>
