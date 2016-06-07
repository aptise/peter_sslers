<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/private-keys">Private Keys</a></li>
        <li class="active">Focus [${SslPrivateKey.id}]</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Private Key - Focus</h2>
    <p>${request.text_library.info_PrivateKeys[1]}</p>

    ${admin_partials.standard_error_display()}
</%block>


<%block name="content_main">

    <table class="table">
        <tr>
            <th>id</th>
            <td>
                <span class="label label-default">
                    ${SslPrivateKey.id}
                </span>
            </td>
        </tr>
        <tr>
            <th>is_active</th>
            <td>
                <span class="label label-${'success' if SslPrivateKey.is_active else 'warning'}">
                    ${'active' if SslPrivateKey.is_active else 'inactive'}
                </span>
                % if SslPrivateKey.is_compromised:
                    &nbsp;
                    <span class="label label-danger">
                        <span class="glyphicon glyphicon-warning-sign" aria-hidden="true"></span>
                        Compromised
                    </span>
                % endif
                % if not SslPrivateKey.is_active and not SslPrivateKey.is_compromised:
                    &nbsp;
                    <a  href="${admin_prefix}/private-key/${SslPrivateKey.id}/mark?action=active"
                        class="label label-info"
                    >
                        <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                        activate
                    </a>
                % elif SslPrivateKey.is_active and not SslPrivateKey.is_compromised:
                    &nbsp;
                    <a  href="${admin_prefix}/private-key/${SslPrivateKey.id}/mark?action=inactive"
                        class="label label-danger"
                    >
                        <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                        deactivate
                    </a>
                    &nbsp;
                    <a  href="${admin_prefix}/private-key/${SslPrivateKey.id}/mark?action=compromised"
                        class="label label-danger"
                    >
                        <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                        mark compromised
                    </a>
                % endif
            </td>
        </tr>
        <tr>
            <th>is_autogenerated_key?</th>
            <td>
                % if SslPrivateKey.is_autogenerated_key:
                    <span class="label label-success">
                        Autogenerated
                    </span>
                    &nbsp;
                    <code>
                        ${SslPrivateKey.autogenerated_key_year_week}
                    </code>
                % endif
            </td>
        </tr>
        <tr>
            <th>is_compromised?</th>
            <td>
                % if SslPrivateKey.is_compromised:
                    <span class="label label-dander">
                        COMPROMISED
                    </span>
                % endif
            </td>
        </tr>

        <tr>
            <th>timestamp_first_seen</th>
            <td><timestamp>${SslPrivateKey.timestamp_first_seen  or ''}</timestamp></td>
        </tr>
        <tr>
            <th>timestamp_last_certificate_request</th>
            <td><timestamp>${SslPrivateKey.timestamp_last_certificate_request  or ''}</timestamp></td>
        </tr>
        <tr>
            <th>timestamp_last_certificate_issue</th>
            <td><timestamp>${SslPrivateKey.timestamp_last_certificate_issue  or ''}</timestamp></td>
        </tr>
        <tr>
            <th>count_active_certificates</th>
            <td><span class="badge">${SslPrivateKey.count_active_certificates  or ''}</span></td>
        </tr>
        <tr>
            <th>count_certificate_requests</th>
            <td><span class="badge">${SslPrivateKey.count_certificate_requests or ''}</span></td>
        </tr>
        <tr>
            <th>count_certificates_issued</th>
            <td><span class="badge">${SslPrivateKey.count_certificates_issued or ''}</span></td>
        </tr>
        <tr>
            <th>key_pem_md5</th>
            <td><code>${SslPrivateKey.key_pem_md5}</code></td>
        </tr>
        <tr>
            <th>key_pem_modulus_md5</th>
            <td>
                <code>${SslPrivateKey.key_pem_modulus_md5}</code>
                <a
                    class="btn btn-xs btn-info"
                    href="${admin_prefix}/search?${SslPrivateKey.key_pem_modulus_search}"
                >
                    <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                </a>
            </td>
        </tr>
        ${admin_partials.table_tr_event_created(SslPrivateKey.ssl_operations_event_id__created)}
        <tr>
            <th>key_pem</th>
            <td>
                ## ${'tracked' if SslPrivateKey.key_pem else 'untracked'}
                ## <textarea class="form-control">${SslPrivateKey.key_pem}</textarea>
                <a class="btn btn-xs btn-info" href="${admin_prefix}/private-key/${SslPrivateKey.id}/key.pem">key.pem</a>
                <a class="btn btn-xs btn-info" href="${admin_prefix}/private-key/${SslPrivateKey.id}/key.pem.txt">key.pem.txt</a>
                <a class="btn btn-xs btn-info" href="${admin_prefix}/private-key/${SslPrivateKey.id}/key.key">key.key (der)</a>
            </td>
        </tr>
        <tr>
            <th>certificates</th>
            <td>
                ${admin_partials.table_certificates__list(SslPrivateKey.server_certificates__5, show_domains=True, show_expiring_days=True)}
                % if SslPrivateKey.server_certificates__5:
                    ${admin_partials.nav_pager("%s/private-key/%s/certificates" % (admin_prefix, SslPrivateKey.id))}
                % endif
            </td>
        </tr>
        <tr>
            <th>certificate_requests</th>
            <td>
                ${admin_partials.table_certificate_requests__list(SslPrivateKey.certificate_requests__5, show_domains=True)}
                % if SslPrivateKey.certificate_requests__5:
                    ${admin_partials.nav_pager("%s/private-key/%s/certificate-requests" % (admin_prefix, SslPrivateKey.id))}
                % endif
            </td>
        </tr>
    </table>



</%block>
