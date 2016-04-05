<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li class="active">Renewal Queue</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Renewal Queue</h2>
</%block>
    

<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            % if LetsencryptRenewalQueues:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>certificate_id</th>
                            <th>unique fqdn</th>
                            <th>timestamp_entered</th>
                            <th>timestamp_processed</th>
                            <th>process_result</th>
                        </tr>
                    </thead>
                    % for q in LetsencryptRenewalQueues:
                        <tr>
                            <td><a class="label label-info" href="/.well-known/admin/renewal-queue/item/${q.id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ${q.id}</a></td>
                            <td><a class="label label-info" href="/.well-known/admin/certificate/${q.letsencrypt_server_certificate_id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ${q.letsencrypt_server_certificate_id}</a></td>
                            <td><a class="label label-info" href="/.well-known/admin/unique-fqdn-set/${q.letsencrypt_unique_fqdn_set_id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ${q.letsencrypt_unique_fqdn_set_id}</a></td>
                            <td><timestamp>${q.timestamp_entered}</timestamp></td>
                            <td><timestamp>${q.timestamp_processed}</timestamp></td>
                            <td>${q.process_result or ''}</td>
                        </tr>
                    % endfor
                </table>
            % else:
                <em>
                    No Queue Items
                </em>
            % endif
        </div>
        <div class="col-sm-3">
            <ul class="nav nav-pills nav-stacked">
              <li role="presentation" class="${'active' if sidenav_option == 'unprocessed' else ''}"><a href="/.well-known/admin/renewal-queue">Unprocessed Items</a></li>
              <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="/.well-known/admin/renewal-queue/all">All Items</a></li>
            </ul>
        </div>
    </div>
</%block>
