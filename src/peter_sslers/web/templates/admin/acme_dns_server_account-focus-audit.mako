<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-dns-server-accounts">AcmeDnsServerAccounts</a></li>
        <li><a href="${admin_prefix}/acme-dns-server-account/${AcmeDnsServerAccount.id}">Focus [${AcmeDnsServerAccount.id}]</a></li>
        <li class="active">Audit</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>AcmeDnsServerAccount Focus ${AcmeDnsServerAccount.id} - Audit</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-dns-server-account/${AcmeDnsServerAccount.id}/audit.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">

            <h4>Integration Status</h4>
            <table class="table table-striped table-condensed">
                <tr>
                    <th>errors?</th>
                    <td>
                        % if AuditResults["errors"]:
                            <ul>
                                % for err in AuditResults["errors"]:
                                    <li><code>${err}</code></li>
                                % endfor
                            </ul>
                        % endif
                    </td>
                </tr>
            </table>

            <h4>Generic DNS Status</h4>
            <table class="table table-striped table-condensed">
                <tr>
                    <th></th>
                    <th>type</th>
                    <th>dns entry</th>
                    <th>expected</th>
                    <th>actual</th>
                </tr>
                <tr>
                    <th>
                        % if AuditResults["server_global"]["chained"]["TXT"]:
                            % if AcmeDnsServerAccount.cname_target == AuditResults["server_global"]["chained"]["TXT"]:
                                <span class="label label-success"><span class="glyphicon glyphicon-ok" aria-hidden="true"></span></span>
                            % elif AcmeDnsServerAccount.cname_target in AuditResults["server_global"]["chained"]["TXT"]:
                                <span class="label label-warning"><span class="glyphicon glyphicon-ok" aria-hidden="true"></span></span>
                            % else:
                                <span class="label label-danger"><span class="glyphicon glyphicon-remove" aria-hidden="true"></span></span>
                            % endif
                        % else:
                            <span class="label label-danger"><span class="glyphicon glyphicon-remove" aria-hidden="true"></span></span>
                        % endif
                    </th>
                    <td>TXT</td>
                    <td><code>${AcmeDnsServerAccount.cname_source}</code></td>
                    <td><code>${AcmeDnsServerAccount.cname_target}</code></td>
                    <td><code>${AuditResults["server_global"]["chained"]["TXT"] or ''}</code></td>
                </tr>
            </table>


            <h4>Authoritative DNS Status</h4>
            <p>
                A correct configuration will have a CNAME - not TXT - record that
                points to the acme-dns server.
            </p>
            <table class="table table-striped table-condensed">
                <tr>
                    <th></th>
                    <th>type</th>
                    <th>dns entry</th>
                    <th>dns type</th>
                    <th>expected</th>
                    <th>actual</th>
                </tr>
                <tr>
                    <th>
                        % if AuditResults["server_global"]["source"]["CNAME"]:
                            % if AcmeDnsServerAccount.cname_target == AuditResults["server_global"]["source"]["CNAME"]:
                                <span class="label label-success"><span class="glyphicon glyphicon-ok" aria-hidden="true"></span></span>
                            % elif AcmeDnsServerAccount.cname_target in AuditResults["server_global"]["source"]["CNAME"]:
                                <span class="label label-warning"><span class="glyphicon glyphicon-ok" aria-hidden="true"></span></span>
                            % else:
                                <span class="label label-danger"><span class="glyphicon glyphicon-remove" aria-hidden="true"></span></span>
                            % endif
                        % else:
                            <span class="label label-danger"><span class="glyphicon glyphicon-remove" aria-hidden="true"></span></span>
                        % endif
                    </th>
                    <th>source</th>
                    <td><code>${AcmeDnsServerAccount.cname_source}</code></td>
                    <th>CNAME</th>
                    <td><code>${AcmeDnsServerAccount.cname_target}</code></td>
                    <td><code>${AuditResults["server_global"]["source"]["CNAME"] or ''}</code></td>
                </tr>
                <tr>
                    <th>
                        % if not AuditResults["server_global"]["source"]["TXT"]:
                            <span class="label label-success"><span class="glyphicon glyphicon-ok" aria-hidden="true"></span></span>
                        % else:
                            <span class="label label-danger"><span class="glyphicon glyphicon-remove" aria-hidden="true"></span></span>
                        % endif
                    </th>
                    <th>source</th>
                    <td><code>${AcmeDnsServerAccount.cname_source}</code></td>
                    <th>TXT</th>
                    <td><code></code></td>
                    <td><code>${AuditResults["server_global"]["source"]["TXT"] or ''}</code></td>
                </tr>
                <tr>
                    <th>
                        % if not AuditResults["server_global"]["target"]["TXT"]:
                            <span class="label label-success"><span class="glyphicon glyphicon-ok" aria-hidden="true"></span></span>
                        % else:
                            <span class="label label-danger"><span class="glyphicon glyphicon-remove" aria-hidden="true"></span></span>
                        % endif
                    </th>
                    <th>target</th>
                    <td><code>${AcmeDnsServerAccount.cname_target}</code></td>
                    <th>TXT</th>
                    <td><code></code></td>
                    <td><code>${AuditResults["server_global"]["target"]["TXT"] or ''}</code></td>
                </tr>
            </table>


            <h4>ACME-DNS Server Status</h4>
            <table class="table table-striped table-condensed">
                <tr>
                    <th>acme-dns credentials work?</th>
                    <td>
                        ${AuditResults["server_acme_dns"]["credentials_work"] or ''}
                    </td>
                </tr>
                <tr>
                    <th>acme-dns credentials reset?</th>
                    <td>
                        ${AuditResults["server_acme_dns"]["credentials_reset"] or ''}
                    </td>
                </tr>
                <tr>
                    <th>TXT Records (pre)</th>
                    <td>
                        <code>${AuditResults["server_acme_dns"]["TXT"]["pre"] or ''}</code>
                    </td>
                </tr>
                <tr>
                    <th>TXT Records (reset)</th>
                    <td>
                        <code>${AuditResults["server_acme_dns"]["TXT"]["reset"] or ''}</code>
                    </td>
                </tr>
            </table>

            ## ${AuditResults}
            
        </div>
    </div>
</%block>
