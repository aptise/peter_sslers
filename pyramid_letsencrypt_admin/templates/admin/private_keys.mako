<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li class="active">Private Keys</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Private Keys</h2>
    <p>${request.text_library.info_PrivateKeys[1]}</p>
</%block>
    

<%block name="content_main">
    % if LetsencryptPrivateKeys:
        ${admin_partials.nav_pagination(pager)}
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>id</th>
                    <th>count_active_certificates</th>
                    <th>timestamp_first_seen</th>
                    <th>key_pem_md5</th>
                </tr>
            </thead>
            % for key in LetsencryptPrivateKeys:
                <tr>
                    <td><a class="label label-info" href="/.well-known/admin/private_key/${key.id}">&gt; ${key.id}</a></td>
                    <td><span class="badge">${key.count_active_certificates or ''}</span></td>
                    <td><timestamp>${key.timestamp_first_seen}</timestamp></td>
                    <td><code>${key.key_pem_md5}</code></td>
                </tr>
            % endfor
        </table>
    % else:
        <em>
            No Private Keys
        </em>
    % endif
</%block>
