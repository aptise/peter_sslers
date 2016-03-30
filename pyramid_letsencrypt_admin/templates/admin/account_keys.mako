<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li class="active">Account Keys</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Account Keys</h2>
    <p>${request.text_library.info_AccountKeys[1]}</p>
</%block>
    

<%block name="content_main">
    % if LetsencryptAccountKeys:
        ${admin_partials.nav_pagination(pager)}
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>id</th>
                    <th>timestamp_first_seen</th>
                    <th>key_pem_md5</th>
                    <th>count_certificate_requests</th>
                    <th>count_certificates_issued</th>
                </tr>
            </thead>
            <tbody>
            % for key in LetsencryptAccountKeys:
                <tr>
                    <td><a class="label label-info" href="/.well-known/admin/account_key/${key.id}">&gt; ${key.id}</a></td>
                    <td><timestamp>${key.timestamp_first_seen}<timestamp></td>
                    <td><code>${key.key_pem_md5}</code></td>
                    <td><span class="badge">${key.count_certificate_requests or ''}</span></td>
                    <td><span class="badge">${key.count_certificates_issued or ''}</span></td>
                </tr>
            % endfor
            </tbody>
        </table>
    % else:
        <em>
            No Account Keys
        </em>
    % endif
</%block>
