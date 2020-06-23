<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/queue-certificates">Queue Certificate</a></li>
        <li class="active">New</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Queue Certificate - New</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/queue-certificate/new/structured.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    ${admin_partials.handle_querystring_result()}
    <div class="row">
        <div class="col-sm-9">

            <h4>Queue a Renewal?</h4>
            
            <p>Upon submission, the following combination will be added to the processing queue for AcmeOrders.</p>
            
            <form
                action="${admin_prefix}/queue-certificate/new/structured"
                method="POST"
                enctype="multipart/form-data"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}
                <table class="table table-striped table-condensed">
                    <tbody>
                        <tr>
                            <th>Object</th>
                            <td>
                                % if AcmeOrder:
                                    <a 
                                        href="${admin_prefix}/acme-order/${AcmeOrder.id}"
                                        class="label label-info">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        AcmeOrder-${AcmeOrder.id}
                                    </a>
                                    <input type="hidden" name="queue_source" value="AcmeOrder"/>
                                    <input type="hidden" name="acme_order" value="${AcmeOrder.id}"/>
                                % elif ServerCertificate:
                                    <a 
                                        href="${admin_prefix}/server-certificate/${ServerCertificate.id}"
                                        class="label label-info">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        ServerCertificate-${ServerCertificate.id}
                                    </a>
                                    <input type="hidden" name="queue_source" value="ServerCertificate"/>
                                    <input type="hidden" name="server_certificate" value="${ServerCertificate.id}"/>
                                % elif UniqueFQDNSet:
                                    <a 
                                        href="${admin_prefix}/acme-order/${UniqueFQDNSet.id}"
                                        class="label label-info">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        UniqueFQDNSet-${UniqueFQDNSet.id}
                                    </a>
                                    <input type="hidden" name="queue_source" value="UniqueFQDNSet"/>
                                    <input type="hidden" name="unique_fqdn_set" value="${UniqueFQDNSet.id}"/>
                                % endif
                            </td>
                            <td></td>
                        </tr>
                        <tr>
                            <th>UniqueFQDNSet</th>
                            <td>
                                <%
                                    unique_fqdn_set = None
                                    if AcmeOrder:
                                        unique_fqdn_set = AcmeOrder.unique_fqdn_set
                                    elif ServerCertificate:
                                        unique_fqdn_set = ServerCertificate.unique_fqdn_set
                                    elif UniqueFQDNSet:
                                        unique_fqdn_set = UniqueFQDNSet
                                %>
                                <a
                                    class="label label-info"
                                    href="${admin_prefix}/unique-fqdn-set/${unique_fqdn_set.id}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    UniqueFQDNSet-${unique_fqdn_set.id}
                                </a>
                            </td>
                            <td>
                                <code>${', '.join(unique_fqdn_set.domains_as_list)}</code>
                            </td>
                        </tr>
                        <tr>
                            <th>AcmeAccount</th>
                            <td>
                                % if AcmeOrder:
                                    <a
                                        class="label label-info"
                                        href="${admin_prefix}/acme-account/${AcmeOrder.acme_account_id}"
                                    >
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        AcmeAccount-${AcmeOrder.acme_account_id}
                                    </a>
                                % endif
                            </td>
                            <td>
                                ${admin_partials.formgroup__AcmeAccount_selector__advanced(dbAcmeAccountReuse=AcmeAccount_reuse)}
                            </td>
                        </tr>
                        <tr>
                            <th>PrivateKey</th>
                            <td>
                                % if AcmeOrder:
                                    <a
                                        class="label label-info"
                                        href="${admin_prefix}/private-key/${AcmeOrder.private_key_id}"
                                    >
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        PrivateKey-${AcmeOrder.private_key_id}
                                    </a>
                                % endif
                            </td>
                            <td>
                                ${admin_partials.formgroup__PrivateKey_selector__advanced(dbPrivateKeyReuse=PrivateKey_reuse, option_account_key_default=True, option_generate_new=True)}
                            </td>
                        </tr>
                        <tr>
                            <th>Private Key Cycling: Renewals</th>
                            <td></td>
                            <td>
                                ${admin_partials.formgroup__private_key_cycle__renewal()}
                            </td>
                        </tr>
                        <tr>
                            <th></th>
                            <td colspan="2">
                                <button class="btn btn-xs btn-primary" type="submit">
                                    <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                    Queue the Server Certificate!
                                </button>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </form>
        </div>
        <div class="col-sm-3">
            <p>This route supports JSON and is self-documenting on GET requests.</p>
            ## ${admin_partials.info_AcmeAccount()}
            ## ${admin_partials.info_PrivateKey()}
        </div>
    </div>
</%block>
