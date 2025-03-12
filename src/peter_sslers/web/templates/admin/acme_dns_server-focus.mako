<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-dns-servers">acme-dns Servers</a></li>
        <li class="active">Focus ${AcmeDnsServer.id}</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>acme-dns Server: Focus</h2>
    ${admin_partials.handle_querystring_result()}
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-dns-server/${AcmeDnsServer.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">

            <table class="table table-striped table-condensed">
                <tr>
                    <th>id</th>
                    <td>
                        <span class="label label-info">
                            ${AcmeDnsServer.id}
                        </span>
                    </td>
                </tr>
                <tr>
                    <th>timestamp_created</th>
                    <td>
                        <timestamp>${AcmeDnsServer.timestamp_created}</timestamp>
                    </td>
                </tr>
                <tr>
                    <th>api_url</th>
                    <td>
                        <code>${AcmeDnsServer.api_url}</code>

                        <form action="${admin_prefix}/acme-dns-server/${AcmeDnsServer.id}/check" method="POST" style="display:inline;" id="form-check">
                            <input type="hidden" name="action" value="active"/>
                            <button class="btn btn-xs btn-primary" type="submit">
                                <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                                Check
                            </button>
                        </form>

                    </td>
                </tr>
                <tr>
                    <th>domain</th>
                    <td>
                        <code>${AcmeDnsServer.domain}</code>
                    </td>
                </tr>
                <tr>
                    <th>active?</th>
                    <td>
                        <code>${AcmeDnsServer.is_active}</code>
                        % if not AcmeDnsServer.is_active:
                            <form action="${admin_prefix}/acme-dns-server/${AcmeDnsServer.id}/mark" method="POST" style="display:inline;" id="form-mark-active">
                                <input type="hidden" name="action" value="active"/>
                                <button class="btn btn-xs btn-success" type="submit">
                                    <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                    Activate
                                </button>
                            </form>
                        % else:
                            <form action="${admin_prefix}/acme-dns-server/${AcmeDnsServer.id}/mark" method="POST" style="display:inline;" id="form-mark-inactive">
                                <input type="hidden" name="action" value="inactive"/>
                                <button class="btn btn-xs btn-danger" type="submit">
                                    <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                    Deactivate
                                </button>
                            </form>
                        % endif
                    </td>
                </tr>
                <tr>
                    <th>global default?</th>
                    <td>
                        <code>${AcmeDnsServer.is_global_default}</code>
                        % if not AcmeDnsServer.is_global_default and AcmeDnsServer.is_active:
                            <form action="${admin_prefix}/acme-dns-server/${AcmeDnsServer.id}/mark" method="POST" style="display:inline;" id="form-mark-global_default">
                                <input type="hidden" name="action" value="global_default"/>
                                <button class="btn btn-xs btn-success" type="submit">
                                    <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                    set Global Default
                                </button>
                            </form>
                        % endif
                    </td>
                </tr>

                <tr>
                    <th>AcmeDNS Server Accounts</th>
                    <td>
                        ${admin_partials.table_AcmeDnsServerAccounts(AcmeDnsServer.acme_dns_server_accounts__5, perspective="AcmeDnsServer")}
                        % if AcmeDnsServer.acme_dns_server_accounts__5:
                            ${admin_partials.nav_pager("%s/acme-dns-server/%s/acme-dns-server-accounts" % (admin_prefix, AcmeDnsServer.id))}
                        % endif
                    </td>
                </tr>

            </table>
            
            <a href="${admin_prefix}/acme-dns-server/${AcmeDnsServer.id}/edit"
               class="btn btn-primary"
            >
                <span class="glyphicon glyphicon-pencil" aria-hidden="true"></span>
                Edit
            </a>

            <a href="${admin_prefix}/acme-dns-server/${AcmeDnsServer.id}/ensure-domains"
               class="btn btn-primary"
            >
                <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                Ensure Domains
            </a>

            <a href="${admin_prefix}/acme-dns-server/${AcmeDnsServer.id}/import-domain"
               class="btn btn-primary"
            >
                <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                Import Domain
            </a>

        </div>
    </div>
</%block>
