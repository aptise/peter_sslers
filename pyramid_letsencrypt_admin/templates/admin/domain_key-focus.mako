<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li><a href="/.well-known/admin/domain_keys">Domain Keys</a></li>
        <li class="active">Focus [${LetsencryptDomainKey.id}]</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Domain Key - Focus</h2>
    <p>${request.text_library.info_DomainKeys[1]}</p>
</%block>
    

<%block name="content_main">

    <table class="table">
        <tr>
            <th>id</th>
            <td>
                <span class="label label-default">
                    ${LetsencryptDomainKey.id}
                </span>
            </td>
        </tr>
        <tr>
            <th>timestamp_first_seen</th>
            <td>${LetsencryptDomainKey.timestamp_first_seen  or ''}</td>
        </tr>
        <tr>
            <th>key_pem_md5</th>
            <td><code>${LetsencryptDomainKey.key_pem_md5}</code></td>
        </tr>
        <tr>
            <th>key_pem_modulus_md5</th>
            <td><code>${LetsencryptDomainKey.key_pem_modulus_md5}</code></td>
        </tr>
        <tr>
            <th>key_pem</th>
            <td>
                ## ${'tracked' if LetsencryptDomainKey.key_pem else 'untracked'}
                ## <textarea class="form-control">${LetsencryptDomainKey.key_pem}</textarea>
                <a class="btn btn-xs btn-info" href="/.well-known/admin/domain_key/${LetsencryptDomainKey.id}/key.pem">key.pem</a>
                <a class="btn btn-xs btn-info" href="/.well-known/admin/domain_key/${LetsencryptDomainKey.id}/key.pem.txt">key.pem.txt</a>
                <a class="btn btn-xs btn-info" href="/.well-known/admin/domain_key/${LetsencryptDomainKey.id}/key.key">key.key (der)</a>
            </td>
        </tr>
        <tr>
            <th>certificate_requests</th>
            <td>
                ${admin_partials.table_certificate_requests__list(LetsencryptDomainKey.certificate_requests, show_domains=True)}
            </td>
        </tr>
    </table>


    
</%block>
