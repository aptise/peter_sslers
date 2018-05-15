<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Settings</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Configuration Settings</h2>
</%block>


<%block name="content_main">
    <p>
        These settings can be edited with your <code>environment.ini</code> file.
    </p>
    <div class="row">
        <div class="col-sm-6">

<table class="table table-striped table-condensed">
    <tr>
        <th colspan="2">
            Enabled Options
        </th>
    </tr>
    % for option in ('enable_nginx', 'enable_redis', 'enable_views_admin', 'enable_views_public'):
        <tr>
            <td>${option}</td>
            <td>${request.registry.settings.get(option)}</td>
        </tr>
    % endfor

    <tr>
        <th colspan="2">
            Views Configuration
        </th>
    </tr>
    % for option in ('enable_views_admin', 'enable_views_public', 'admin_prefix', ):
        <tr>
            <td>${option}</td>
            <td>${request.registry.settings.get(option)}</td>
        </tr>
    % endfor


    <tr>
        <th colspan="2">
            Certifcate Configuration
        </th>
    </tr>
    % for option in ('certificate_authority', 'expiring_days', 'openssl_path', 'openssl_path_conf', ):
        <tr>
            <td>${option}</td>
            <td>${request.registry.settings.get(option)}</td>
        </tr>
    % endfor

    <tr>
        <th colspan="2">
            NGINX Configuration
        </th>
    </tr>
    % for option in ('nginx.reset_path', 'nginx.servers_pool', 'nginx.servers_pool_allow_invalid', 'nginx.status_path', 'nginx.timeout', 'nginx.userpass', ):
        <tr>
            <td>${option}</td>
            <td>${request.registry.settings.get(option)}</td>
        </tr>
    % endfor

    <tr>
        <th colspan="2">
            Redis Configuration
        </th>
    </tr>
    % for option in ('redis.prime_style', 'redis.url', ):
        <tr>
            <td>${option}</td>
            <td>${request.registry.settings.get(option)}</td>
        </tr>
    % endfor


    <tr>
        <th colspan="2">
            SqlAlchemy Configuration
        </th>
    </tr>
    % for option in ('sqlalchemy.url', ):
        <tr>
            <td>${option}</td>
            <td>${request.registry.settings.get(option)}</td>
        </tr>
    % endfor
</table>
        

        </div>
    </div>
</%block>
