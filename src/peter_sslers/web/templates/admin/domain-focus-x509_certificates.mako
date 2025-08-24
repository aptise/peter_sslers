<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/domains">Domains</a></li>
        <li><a href="${admin_prefix}/domain/${Domain.id}">Focus [${Domain.id}-${Domain.domain_name}]</a></li>
        <li class="active">X509Certificates</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Domain Focus - X509Certificates</h2>
</%block>



<%block name="page_header_nav">
    <ul class="nav nav-pills nav-stacked">
      <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="${admin_prefix}/domain/${Domain.id}/x509-certificates/all">All X509Certificates</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'single' else ''}"><a href="${admin_prefix}/domain/${Domain.id}/x509-certificates/single">Single X509Certificates</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'multi' else ''}"><a href="${admin_prefix}/domain/${Domain.id}/x509-certificates/multi">Multi X509Certificates</a></li>
    </ul>

    <p class="pull-right">
        <a href="${admin_prefix}/domain/${Domain.id}/x509-certificates/${sidenav_option}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>

<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            % if X509Certificates:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_X509Certificates(X509Certificates, show_domains=True, show_days_to_expiry=True)}
            % else:
                No known X509Certificates.
            % endif
        </div>
    </div>
</%block>
