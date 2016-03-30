<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li><a href="/.well-known/admin/private_keys">Private Keys</a></li>
        <li class="active">Focus [${LetsencryptPrivateKey.id}]</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Private Key - Focus</h2>
    <p>${request.text_library.info_PrivateKeys[1]}</p>
</%block>
    

<%block name="content_main">

    <table class="table">
        <tr>
            <th>id</th>
            <td>
                <span class="label label-default">
                    ${LetsencryptPrivateKey.id}
                </span>
            </td>
        </tr>
        <tr>
            <th>timestamp_first_seen</th>
            <td><timestamp>${LetsencryptPrivateKey.timestamp_first_seen  or ''}</timestamp></td>
        </tr>
        <tr>
            <th>count_active_certificates</th>
            <td><span class="badge">${LetsencryptPrivateKey.count_active_certificates  or ''}</span></td>
        </tr>
        <tr>
            <th>count_certificate_requests</th>
            <td><span class="badge">${LetsencryptPrivateKey.count_certificate_requests or ''}</span></td>
        </tr>
        <tr>
            <th>count_certificates_issued</th>
            <td><span class="badge">${LetsencryptPrivateKey.count_certificates_issued or ''}</span></td>
        </tr>
        <tr>
            <th>key_pem_md5</th>
            <td><code>${LetsencryptPrivateKey.key_pem_md5}</code></td>
        </tr>
        <tr>
            <th>key_pem_modulus_md5</th>
            <td><code>${LetsencryptPrivateKey.key_pem_modulus_md5}</code></td>
        </tr>
        <tr>
            <th>key_pem</th>
            <td>
                ## ${'tracked' if LetsencryptPrivateKey.key_pem else 'untracked'}
                ## <textarea class="form-control">${LetsencryptPrivateKey.key_pem}</textarea>
                <a class="btn btn-xs btn-info" href="/.well-known/admin/private_key/${LetsencryptPrivateKey.id}/key.pem">key.pem</a>
                <a class="btn btn-xs btn-info" href="/.well-known/admin/private_key/${LetsencryptPrivateKey.id}/key.pem.txt">key.pem.txt</a>
                <a class="btn btn-xs btn-info" href="/.well-known/admin/private_key/${LetsencryptPrivateKey.id}/key.key">key.key (der)</a>
            </td>
        </tr>
        <tr>
            <th>certificates</th>
            <td>
                ${admin_partials.table_certificates__list(LetsencryptPrivateKey.signed_certificates_5, show_domains=True, show_expiring_days=True)}
                % if LetsencryptPrivateKey.signed_certificates_5:
                    ${admin_partials.nav_pager("/.well-known/admin/private_key/%s/certificates" % LetsencryptPrivateKey.id)}
                % endif
            </td>
        </tr>
        <tr>
            <th>certificate_requests</th>
            <td>
                ${admin_partials.table_certificate_requests__list(LetsencryptPrivateKey.certificate_requests_5, show_domains=True)}
                % if LetsencryptPrivateKey.certificate_requests_5:
                    ${admin_partials.nav_pager("/.well-known/admin/private_key/%s/certificate_requests" % LetsencryptPrivateKey.id)}
                % endif
            </td>
        </tr>
    </table>


    
</%block>
