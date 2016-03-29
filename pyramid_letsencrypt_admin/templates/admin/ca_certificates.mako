<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li class="active">CA Certificates</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>CA Certificate</h2>
    <p>${request.text_library.info_CACertificates[1]}</p>
</%block>
    

<%block name="content_main">
    % if LetsencryptCACertificates:
        ${admin_partials.nav_pagination(pager)}
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>id</th>
                    <th>count_active_certificates</th>
                    <th>timestamp_first_seen</th>
                    <th>cert_pem_md5</th>
                </tr>
            </thead>
            % for cert in LetsencryptCACertificates:
                <tr>
                    <td><a class="label label-info" href="/.well-known/admin/ca_certificate/${cert.id}">&gt; ${cert.id}</a></td>
                    <td><span class="badge">${cert.count_active_certificates or ''}</span></td>
                    <td><timestamp>${cert.timestamp_first_seen}</timestamp></td>
                    <td><code>${cert.cert_pem_md5}</code></td>
                </tr>
            % endfor
        </table>
    % else:
        <em>
            No Certificate Authority Certificates
        </em>
    % endif
</%block>
