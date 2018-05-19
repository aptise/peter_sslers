<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/account-keys">Account Keys</a></li>
        <li class="active">Focus [${SslAcmeAccountKey.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Account Keys - Focus</h2>
    <p>${request.text_library.info_AccountKeys[1]}</p>

    ${admin_partials.standard_error_display()}
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/account-key/${SslAcmeAccountKey.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <table class="table">
                <tr>
                    <th>id</th>
                    <td>
                        <span class="label label-default">
                            ${SslAcmeAccountKey.id}
                        </span>
                    </td>
                </tr>
                <tr>
                    <th>timestamp_last_authenticated</th>
                    <td><timestamp>${SslAcmeAccountKey.timestamp_last_authenticated  or ''}</timestamp>
                        % if not SslAcmeAccountKey.timestamp_last_authenticated:
                            <a  href="${admin_prefix}/account-key/${SslAcmeAccountKey.id}/authenticate"
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
                        <span class="label label-${'success' if SslAcmeAccountKey.is_active else 'warning'}">
                            ${'active' if SslAcmeAccountKey.is_active else 'inactive'}
                        </span>
                        &nbsp;
                        % if not SslAcmeAccountKey.is_active:
                            <a  href="${admin_prefix}/account-key/${SslAcmeAccountKey.id}/mark?action=active"
                                class="label label-info"
                            >
                                <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                active
                            </a>
                        % else:
                            % if not SslAcmeAccountKey.is_default:
                                <a  href="${admin_prefix}/account-key/${SslAcmeAccountKey.id}/mark?action=inactive"
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
                        % if SslAcmeAccountKey.is_default:
                            <span class="label label-success">
                                default
                            </span>
                        % else:
                            <span class="label label-default">
                                no
                            </span>
                        % endif
                        &nbsp;
                        % if not SslAcmeAccountKey.is_default:
                            <a  href="${admin_prefix}/account-key/${SslAcmeAccountKey.id}/mark?action=default"
                                class="label label-primary"
                            >
                                <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                make default
                            </a>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>acme_account_provider_id</th>
                    <td>
                        ${SslAcmeAccountKey.acme_account_provider_id}
                        ${SslAcmeAccountKey.acme_account_provider}
                    </td>
                </tr>
                <tr>
                    <th>timestamp_first_seen</th>
                    <td><timestamp>${SslAcmeAccountKey.timestamp_first_seen  or ''}</timestamp></td>
                </tr>
                <tr>
                    <th>timestamp_last_certificate_request</th>
                    <td><timestamp>${SslAcmeAccountKey.timestamp_last_certificate_request  or ''}</timestamp></td>
                </tr>
                <tr>
                    <th>timestamp_last_certificate_issue</th>
                    <td><timestamp>${SslAcmeAccountKey.timestamp_last_certificate_issue  or ''}</timestamp></td>
                </tr>
                <tr>
                    <th>count_certificate_requests</th>
                    <td><span class="badge">${SslAcmeAccountKey.count_certificate_requests or ''}</span></td>
                </tr>
                <tr>
                    <th>count_certificates_issued</th>
                    <td><span class="badge">${SslAcmeAccountKey.count_certificates_issued or ''}</span></td>
                </tr>
                <tr>
                    <th>key_pem_md5</th>
                    <td><code>${SslAcmeAccountKey.key_pem_md5}</code></td>
                </tr>
                <tr>
                    <th>key_pem_modulus_md5</th>
                    <td>
                        <code>${SslAcmeAccountKey.key_pem_modulus_md5}</code>
                        <a
                            class="btn btn-xs btn-info"
                            href="${admin_prefix}/search?${SslAcmeAccountKey.key_pem_modulus_search}"
                        >
                            <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
                        </a>
                    </td>
                </tr>
                <tr>
                    <th>key_pem</th>
                    <td>
                        ## ${'tracked' if SslAcmeAccountKey.key_pem else 'untracked'}
                        ## <textarea class="form-control">${SslAcmeAccountKey.key_pem}</textarea>
                        <a class="btn btn-xs btn-info" href="${admin_prefix}/account-key/${SslAcmeAccountKey.id}/key.pem">key.pem</a>
                        <a class="btn btn-xs btn-info" href="${admin_prefix}/account-key/${SslAcmeAccountKey.id}/key.pem.txt">key.pem.txt</a>
                        <a class="btn btn-xs btn-info" href="${admin_prefix}/account-key/${SslAcmeAccountKey.id}/key.key">key.key (der)</a>
                    </td>
                </tr>
                <tr>
                    <th>letsencrypt_data</th>
                    <td>
                        % if SslAcmeAccountKey.letsencrypt_data:
                            ${SslAcmeAccountKey.letsencrypt_data}
                        % endif
                    </td>
                </tr>
                ${admin_partials.table_tr_event_created(SslAcmeAccountKey)}
                <tr>
                    <th>certificates</th>
                    <td>
                        ${admin_partials.table_certificates__list(SslAcmeAccountKey.server_certificates__5, show_domains=True, show_expiring_days=True)}
                        % if SslAcmeAccountKey.server_certificates__5:
                            ${admin_partials.nav_pager("%s/account-key/%s/certificates" % (admin_prefix, SslAcmeAccountKey.id))}
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>certificate_requests</th>
                    <td>
                        ${admin_partials.table_certificate_requests__list(SslAcmeAccountKey.certificate_requests__5, show_domains=True)}
                        % if SslAcmeAccountKey.certificate_requests__5:
                            ${admin_partials.nav_pager("%s/account-key/%s/certificate-requests" % (admin_prefix, SslAcmeAccountKey.id))}
                        % endif
                    </td>
                </tr>
            </table>
        </div>
    </div>
</%block>
