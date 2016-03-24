<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li class="active">Domains</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Domains</h2>
    These domains are known to the system.
</%block>
    

<%block name="content_main">
    % if LetsencryptManagedDomains:
        ${admin_partials.nav_pager(pager)}
        <ul>
            % for d in LetsencryptManagedDomains:
                <li><a href="/.well-known/admin/domain/${d.id}">${d.domain_name}</a></li>
            % endfor
        </ul>
        
    % else:
        <em>
            No Domains
        </em>
    % endif
</%block>
