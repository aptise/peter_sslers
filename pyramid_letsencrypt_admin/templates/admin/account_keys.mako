<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li class="active">Account Keys</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Account Key</h2>
    <p>${request.text_library.info_AccountKeys[1]}</p>
</%block>
    

<%block name="content_main">
    % if LetsencryptAccountKeys:
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>id</th>
                    <th>timestamp_first_seen</th>
                    <th>key_pem_md5</th>
                </tr>
            </thead>
            <tbody>
            % for cert in LetsencryptAccountKeys:
                <tr>
                    <td><a class="label label-default" href="/.well-known/admin/account_key/${cert.id}">&gt; ${cert.id}</a></td>
                    <td>${cert.timestamp_first_seen}</td>
                    <td><code>${cert.key_pem_md5}</code></td>
                </tr>
            % endfor
            </tbody>
        </table>
    % else:
        <em>
            No Account certificates
        </em>
    % endif
</%block>
