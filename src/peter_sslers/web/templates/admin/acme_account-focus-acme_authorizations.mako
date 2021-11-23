<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-accounts">AcmeAccounts</a></li>
        <li><a href="${admin_prefix}/acme-account/${AcmeAccount.id}">Focus [${AcmeAccount.id}]</a></li>
        <li class="active">AcmeAuthorizations</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>AcmeAccount - Focus | AcmeAuthorizations</h2>
</%block>


<%block name="page_header_nav">
    <%
        _status = request.params.get("status")
        sidenav_option = 'all'
        if _status in ('active', 'active-expired'):
            sidenav_option = _status
    %>
    <ul class="nav nav-pills nav-stacked">
      <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="${admin_prefix}/acme-account/${AcmeAccount.id}/acme-authorizations">All Authorizations</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'active' else ''}"><a href="${admin_prefix}/acme-account/${AcmeAccount.id}/acme-authorizations?status=active">Pending Authorizations</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'active-expired' else ''}"><a href="${admin_prefix}/acme-account/${AcmeAccount.id}/acme-authorizations?status=active-expired">Pending + Expired Authorizations</a></li>
    </ul>
    <p class="pull-right">
        <a href="${admin_prefix}/acme-account/${AcmeAccount.id}/acme-authorizations.json${'?status=%s' % _status if sidenav_option != 'all' else ''}" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if AcmeAuthorizations:
                ${admin_partials.nav_pagination(pager)}
                <form method="POST" action="${admin_prefix}/acme-account/${AcmeAccount.id}/acme-server/deactivate-pending-authorizations">
                    ${admin_partials.table_AcmeAuthorizations(AcmeAuthorizations, perspective='AcmeAccount', is_form_enabled=True)}
                
                    <button class="btn btn-xs btn-danger" type="submit"  name="submit" value="submit">
                        <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                        Deactivate Selected Pending Authorizations
                    </button>
                </form>
            % else:
                No known AcmeAuthorizations.
            % endif
        </div>
    </div>
</%block>
