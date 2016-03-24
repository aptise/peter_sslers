<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li class="active">Domain Keys</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Domain Keys</h2>
    <p>${request.text_library.info_DomainKeys[1]}</p>
</%block>
    

<%block name="content_main">
    % if LetsencryptDomainKeys:
        ${admin_partials.nav_pager(pager)}
        <table class="table table-striped">
            <thead>
                <tr>
                    <td>id</td>
                    <td>timestamp_first_seen</td>
                    <td>key_pem_md5</td>
                </tr>
            </thead>
            % for cert in LetsencryptDomainKeys:
                <tr>
                    <td><a class="label label-default" href="/.well-known/admin/domain_key/${cert.id}">&gt; ${cert.id}</a></td>
                    <td><timestamp>${cert.timestamp_first_seen}</timestamp></td>
                    <td><code>${cert.key_pem_md5}</code></td>
                </tr>
            % endfor
        </table>
    % else:
        <em>
            No Domain certificates
        </em>
    % endif
</%block>
