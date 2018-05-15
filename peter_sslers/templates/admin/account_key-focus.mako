<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/account-keys">Account Keys</a></li>
        <li class="active">Focus [${SslLetsEncryptAccountKey.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Account Keys - Focus</h2>
    <p>${request.text_library.info_AccountKeys[1]}</p>

    ${admin_partials.standard_error_display()}
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <table class="table">
                <tr>
                    <th>id</th>
                    <td>
                        <span class="label label-default">
                            ${SslLetsEncryptAccountKey.id}
                        </span>
                    </td>
                </tr>
                <tr>
                    <th>timestamp_last_authenticated</th>
                    <td><timestamp>${SslLetsEncryptAccountKey.timestamp_last_authenticated  or ''}</timestamp>
                        % if not SslLetsEncryptAccountKey.timestamp_last_authenticated:
                            <a  href="${admin_prefix}/account-key/${SslLetsEncryptAccountKey.id}/authenticate"
                                class="btn btn-xs btn-primary"
                            >
                                authenticate against LetsEncrypt
                            </a>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>is_active</th>
                    <td>
                        <span class="label label-${'success' if SslLetsEncryptAccountKey.is_active else 'warning'}">
                            ${'active' if SslLetsEncryptAccountKey.is_active else 'inactive'}
                        </span>
                        &nbsp;
                        % if not SslLetsEncryptAccountKey.is_active:
                            <a  href="${admin_prefix}/account-key/${SslLetsEncryptAccountKey.id}/mark?action=active"
                                class="label label-info"
                            >
                                <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                active
                            </a>
                        % else:
                            % if not SslLetsEncryptAccountKey.is_default:
                                <a  href="${admin_prefix}/account-key/${SslLetsEncryptAccountKey.id}/mark?action=inactive"
                                    class="label label-danger disabled"
                                >
                                    <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                    inactive
                                </a>
                            % else:
                                <span
                                    class="label label-warning"
                                >
                                    <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                    select another default key to deactivate this one
                                </span>
                            % endif
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>is_default</th>
                    <td>
                        % if SslLetsEncryptAccountKey.is_default:
                            <span class="label label-success">
                                default
                            </span>
                        % else:
                            <span class="label label-default">
                                no
                            </span>
                        % endif
                        &nbsp;
                        % if not SslLetsEncryptAccountKey.is_default:
                            <a  href="${admin_prefix}/account-key/${SslLetsEncryptAccountKey.id}/mark?action=default"
                                class="label label-info"
                            >
                                <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                make default
                            </a>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>timestamp_first_seen</th>
                    <td><timestamp>${SslLetsEncryptAccountKey.timestamp_first_seen  or ''}</timestamp></td>
                </tr>
                <tr>
                    <th>timestamp_last_certificate_request</th>
                    <td><timestamp>${SslLetsEncryptAccountKey.timestamp_last_certificate_request  or ''}</timestamp></td>
                </tr>
                <tr>
                    <th>timestamp_last_certificate_issue</th>
                    <td><timestamp>${SslLetsEncryptAccountKey.timestamp_last_certificate_issue  or ''}</timestamp></td>
                </tr>
                <tr>
                    <th>count_certificate_requests</th>
                    <td><span class="badge">${SslLetsEncryptAccountKey.count_certificate_requests or ''}</span></td>
                </tr>
                <tr>
                    <th>count_certificates_issued</th>
                    <td><span class="badge">${SslLetsEncryptAccountKey.count_certificates_issued or ''}</span></td>
                </tr>
                <tr>
                    <th>key_pem_md5</th>
                    <td><code>${SslLetsEncryptAccountKey.key_pem_md5}</code></td>
                </tr>
                <tr>
                    <th>key_pem_modulus_md5</th>
                    <td>
                        <code>${SslLetsEncryptAccountKey.key_pem_modulus_md5}</code>
                        <a
                            class="btn btn-xs btn-info"
                            href="${admin_prefix}/search?${SslLetsEncryptAccountKey.key_pem_modulus_search}"
                        >
                            <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                        </a>
                    </td>
                </tr>
                <tr>
                    <th>key_pem</th>
                    <td>
                        ## ${'tracked' if SslLetsEncryptAccountKey.key_pem else 'untracked'}
                        ## <textarea class="form-control">${SslLetsEncryptAccountKey.key_pem}</textarea>
                        <a class="btn btn-xs btn-info" href="${admin_prefix}/account-key/${SslLetsEncryptAccountKey.id}/key.pem">key.pem</a>
                        <a class="btn btn-xs btn-info" href="${admin_prefix}/account-key/${SslLetsEncryptAccountKey.id}/key.pem.txt">key.pem.txt</a>
                        <a class="btn btn-xs btn-info" href="${admin_prefix}/account-key/${SslLetsEncryptAccountKey.id}/key.key">key.key (der)</a>
                    </td>
                </tr>
                ${admin_partials.table_tr_event_created(SslLetsEncryptAccountKey)}
                <tr>
                    <th>certificates</th>
                    <td>
                        ${admin_partials.table_certificates__list(SslLetsEncryptAccountKey.server_certificates__5, show_domains=True, show_expiring_days=True)}
                        % if SslLetsEncryptAccountKey.server_certificates__5:
                            ${admin_partials.nav_pager("%s/account-key/%s/certificates" % (admin_prefix, SslLetsEncryptAccountKey.id))}
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>certificate_requests</th>
                    <td>
                        ${admin_partials.table_certificate_requests__list(SslLetsEncryptAccountKey.certificate_requests__5, show_domains=True)}
                        % if SslLetsEncryptAccountKey.certificate_requests__5:
                            ${admin_partials.nav_pager("%s/account-key/%s/certificate-requests" % (admin_prefix, SslLetsEncryptAccountKey.id))}
                        % endif
                    </td>
                </tr>
            </table>
        </div>
    </div>
</%block>
