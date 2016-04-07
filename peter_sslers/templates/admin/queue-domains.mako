<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Domains Queue</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Domains Queue</h2>

    ${admin_partials.standard_error_display()}
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            % if LetsencryptQueueDomains:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>domain_name</th>
                            <th>timestamp_entered</th>
                            <th>timestamp_processed</th>
                        </tr>
                    </thead>
                    % for q in LetsencryptQueueDomains:
                        <tr>
                            <td><a class="label label-info" href="${admin_prefix}/queue-domain/${q.id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ${q.id}</a></td>
                            <td><code>${q.domain_name}</code></td>
                            <td><timestamp>${q.timestamp_entered}</timestamp></td>
                            <td><timestamp>${q.timestamp_processed or ''}</timestamp></td>
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
              <li role="presentation" class="${'active' if sidenav_option == 'unprocessed' else ''}"><a href="${admin_prefix}/queue-domains">Unprocessed Items</a></li>
              <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="${admin_prefix}/queue-domains/all">All Items</a></li>
              <li role="presentation" class="">
                <a href="${admin_prefix}/queue-domains/add">
                <span class="glyphicon glyphicon-plus-sign" aria-hidden="true"></span>
                Add Domain</a>
              </li>
              <li role="presentation" class="">
                <a href="${admin_prefix}/queue-domains/process">
                <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
                Process Queue</a>
              </li>
            </ul>
        </div>
    </div>
</%block>
