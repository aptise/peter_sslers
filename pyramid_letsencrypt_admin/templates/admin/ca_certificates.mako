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
        ${admin_partials.nav_pager(pager)}
        <table class="table table-striped">
            <thead>
                <tr>
                    <td>id</td>
                    <td>timestamp_first_seen</td>
                    <td>cert_pem_md5</td>
                </tr>
            </thead>
            % for cert in LetsencryptCACertificates:
                <tr>
                    <td><a class="label label-default" href="/.well-known/admin/ca_certificate/${cert.id}">&gt; ${cert.id}</a></td>
                    <td>${cert.timestamp_first_seen}</td>
                    <td><code>${cert.cert_pem_md5}</code></td>
                </tr>
            % endfor
        </table>
    % else:
        <em>
            No CA certificates
        </em>
    % endif
</%block>
