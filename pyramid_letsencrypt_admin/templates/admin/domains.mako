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
    % if LetsencryptDomains:
        ${admin_partials.nav_pager(pager)}
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>id</th>
                    <th>domain name</th>
                </tr>
            </thead>
            % for d in LetsencryptDomains:
                <tr>
                    <td>
                        <a  class="label label-default"
                            href="/.well-known/admin/domain/${d.id}">&gt; ${d.id}</a>
                    </td>
                    <td>${d.domain_name}</td>
                </tr>
            % endfor
        </table>
        
    % else:
        <em>
            No Domains
        </em>
    % endif
</%block>
