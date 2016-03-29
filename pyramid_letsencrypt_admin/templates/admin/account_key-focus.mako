<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li><a href="/.well-known/admin/account_keys">Account Keys</a></li>
        <li class="active">Focus [${LetsencryptAccountKey.id}]</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Account Keys - Focus</h2>
    <p>${request.text_library.info_AccountKeys[1]}</p>
</%block>
    

<%block name="content_main">

    <table class="table">
        <tr>
            <th>id</th>
            <td>
                <span class="label label-default">
                    ${LetsencryptAccountKey.id}
                </span>
            </td>
        </tr>
        <tr>
            <th>timestamp_first_seen</th>
            <td><timestamp>${LetsencryptAccountKey.timestamp_first_seen  or ''}</timestamp></td>
        </tr>
        <tr>
            <th>key_pem_md5</th>
            <td><code>${LetsencryptAccountKey.key_pem_md5}</code></td>
        </tr>
        <tr>
            <th>key_pem_modulus_md5</th>
            <td><code>${LetsencryptAccountKey.key_pem_modulus_md5}</code></td>
        </tr>
        <tr>
            <th>key_pem</th>
            <td>
                ## ${'tracked' if LetsencryptAccountKey.key_pem else 'untracked'}
                ## <textarea class="form-control">${LetsencryptAccountKey.key_pem}</textarea>
                <a class="btn btn-xs btn-info" href="/.well-known/admin/account_key/${LetsencryptAccountKey.id}/key.pem">key.pem</a>
                <a class="btn btn-xs btn-info" href="/.well-known/admin/account_key/${LetsencryptAccountKey.id}/key.pem.txt">key.pem.txt</a>
                <a class="btn btn-xs btn-info" href="/.well-known/admin/account_key/${LetsencryptAccountKey.id}/key.key">key.key (der)</a>
            </td>
        </tr>
        <tr>
            <th>certificates</th>
            <td>
                ${admin_partials.table_certificates__list(LetsencryptAccountKey.signed_certificates_5, show_domains=True, show_expiring_days=True)}
                % if LetsencryptAccountKey.signed_certificates_5:
                    ${admin_partials.nav_pager("/.well-known/admin/account_key/%s/certificates" % LetsencryptAccountKey.id)}
                % endif
            </td>
        </tr>
        <tr>
            <th>certificate_requests</th>
            <td>
                ${admin_partials.table_certificate_requests__list(LetsencryptAccountKey.certificate_requests_5, show_domains=True)}
                % if LetsencryptAccountKey.certificate_requests_5:
                    ${admin_partials.nav_pager("/.well-known/admin/account_key/%s/certificate_requests" % LetsencryptAccountKey.id)}
                % endif
            </td>
        </tr>
    </table>


    
</%block>
