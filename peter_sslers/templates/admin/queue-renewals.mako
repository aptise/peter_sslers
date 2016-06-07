<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Queue: Renewals</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Queue: Renewals</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            % if SslQueueRenewals:
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
                    % for q in SslQueueRenewals:
                        <tr>
                            <td><a class="label label-info" href="${admin_prefix}/queue-renewal/${q.id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ${q.id}</a></td>
                            <td><a class="label label-info" href="${admin_prefix}/certificate/${q.ssl_server_certificate_id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ${q.ssl_server_certificate_id}</a></td>
                            <td><a class="label label-info" href="${admin_prefix}/unique-fqdn-set/${q.ssl_unique_fqdn_set_id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ${q.ssl_unique_fqdn_set_id}</a></td>
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
              <li role="presentation" class="${'active' if sidenav_option == 'unprocessed' else ''}"><a href="${admin_prefix}/queue-renewals">Unprocessed Items</a></li>
              <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="${admin_prefix}/queue-renewals/all">All Items</a></li>
              <li role="presentation" class="">
                <a href="${admin_prefix}/queue-renewals/update">
                <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                Update Queue (30 days or less)</a>
              </li>
            </ul>
        </div>
    </div>
</%block>
