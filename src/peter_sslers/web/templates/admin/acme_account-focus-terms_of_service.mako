<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-accounts">AcmeAccounts</a></li>
        <li><a href="${admin_prefix}/acme-account/${AcmeAccount.id}">Focus [${AcmeAccount.id}]</a></li>
        <li class="active">Terms Of Service</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>AcmeAccount - Focus | Terms Of Service</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            ${admin_partials.nav_pagination(pager)}
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>id</th>
                        <th>is_active</th>
                        <th>timestamp_created_isoformat</th>
                        <th>terms_of_service</th>
                    </tr>
                </thead>
                <tbody>
                    % for tos in TermsOfService:
                        <tr>
                            <td>${tos.id}</td>
                            <td>${tos.is_active or ""}</td>
                            <td><timestamp>${tos.timestamp_created_isoformat}</timestamp></td>
                            <td><code>${tos.terms_of_service}</code></td>
                        </tr>
                    % endfor
                </tbody>
            </table>
            ${admin_partials.nav_pagination(pager)}
        </div>
    </div>
</%block>
