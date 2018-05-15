<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Unique FQDN Sets</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Unique FQDN Sets</h2>
    <p>${request.text_library.info_UniqueFQDNs[1]}</p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            % if SslUniqueFQDNSets:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_SslUniqueFQDNSets(SslUniqueFQDNSets)}
            % else:
                <em>
                    No Unique FQDN Sets
                </em>
            % endif
        </div>
        <div class="col-sm-3">
        </div>
    </div>
</%block>
