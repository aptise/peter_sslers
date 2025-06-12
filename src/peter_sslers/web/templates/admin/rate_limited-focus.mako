<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/rate-limiteds/all">Rate Limiteds</a></li>
        <li class="active">Focus: ${RateLimited.id}</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Rate Limiteds | Focus: ${RateLimited.id}</h2>
    
    ${admin_partials.handle_querystring_result()}
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/rate-limited/${RateLimited.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-file-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-6">

            <table class="table table-striped table-condensed">
                <thead>
                    <tr>
                        <th colspan="2">
                            Core Details
                        </th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <th>id</th>
                        <td>
                            <span class="label label-default">
                                ${RateLimited.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>timestamp_created</th>
                        <td><timestamp>${RateLimited.timestamp_created or ''}</timestamp></td>
                    </tr>
                    <tr>
                        <th>acme_account</th>
                        <td>
                            <a  class="label label-info"
                                href="${admin_prefix}/acme-account/${RateLimited.acme_account_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeAccount-${RateLimited.acme_account_id}
                            </a>
                        </td>
                    </tr>
                    <tr>
                        <th>acme_server</th>
                        <td>
                            <a  class="label label-info"
                                href="${admin_prefix}/acme-server/${RateLimited.acme_server_id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeServer-${RateLimited.acme_server_id}
                            </a>
                        </td>
                    </tr>
                    <tr>
                        <th>acme_order</th>
                        <td>
                            % if RateLimited.acme_order_id:
                                <a  class="label label-info"
                                    href="${admin_prefix}/acme-order/${RateLimited.acme_order_id}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeOrder-${RateLimited.acme_order_id}
                                </a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>unique fqdn set</th>
                        <td>
                            % if RateLimited.unique_fqdn_set_id:
                                <a  class="label label-info"
                                    href="${admin_prefix}/unique-fqdn-set/${RateLimited.unique_fqdn_set_id}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    UniqueFQDNSet-${RateLimited.unique_fqdn_set_id}
                                </a>
                                <code>${RateLimited.unique_fqdn_set.domains_as_string}</code>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>server_resposne_body</th>
                        <td>
                            <code>${RateLimited.server_resposne_body}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>server_resposne_headers</th>
                        <td>
                            <code>${RateLimited.server_resposne_headers}</code>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</%block>
