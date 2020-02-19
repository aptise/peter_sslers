<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Queue: Renewals</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Queue: Renewals</h2>
</%block>


<%block name="page_header_nav">
    <ul class="nav nav-pills nav-stacked">
      <li role="presentation" class="${'active' if sidenav_option == 'unprocessed' else ''}"><a href="${admin_prefix}/queue-renewals">Unprocessed Items</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'active-failures' else ''}"><a href="${admin_prefix}/queue-renewals/active-failures">Unprocessed Failures</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="${admin_prefix}/queue-renewals/all">All Items</a></li>
      <li role="presentation" class="">
        <a href="${admin_prefix}/api/queue-renewals/update">
        <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
        Update Queue (30 days or less)</a>
      </li>
      % if QueueRenewals:
          <li role="presentation" class="">
            <a href="${admin_prefix}/api/queue-renewals/process">
            <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
            Process Queue Items</a>
          </li>
          <li role="presentation" class="">
            <a href="${admin_prefix}/api/queue-renewals/process.json">
            <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
            Process Queue Items - JSON</a>
          </li>
        % endif
    </ul>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <%
                results = request.params.get('results')
            %>
            % if results:
                <h4>Results</h4>
                <textarea class="form-control">${results}</textarea>
                <hr/>
            % endif

            ## set via controller
            % if continue_processing:
                <meta http-equiv="refresh" content="1; url=${admin_prefix}/api/queue-renewals/process">
                <div class="alert alert-info">
                    Queue Still Populated, automatically continuing...
                </div>
            % endif

            % if QueueRenewals:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>certificate_id</th>
                            <th>unique fqdn</th>
                            <th>timestamp_entered</th>
                            <th>timestamp_process_attempt</th>
                            <th>timestamp_processed</th>
                            <th>process_result</th>
                        </tr>
                    </thead>
                    % for q in QueueRenewals:
                        <tr>
                            <td><a class="label label-info" href="${admin_prefix}/queue-renewal/${q.id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ${q.id}</a></td>
                            <td>
                                % if q.server_certificate_id:
                                    <a class="label label-info" href="${admin_prefix}/server-certificate/${q.server_certificate_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    cert-${q.server_certificate_id}</a></td>
                                % endif
                            <td><a class="label label-info" href="${admin_prefix}/unique-fqdn-set/${q.unique_fqdn_set_id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                UniqueFQDNSet-${q.unique_fqdn_set_id}</a></td>
                            <td><timestamp>${q.timestamp_entered}</timestamp></td>
                            <td><timestamp>${q.timestamp_process_attempt or ''}</timestamp></td>
                            <td><timestamp>${q.timestamp_processed or ''}</timestamp></td>
                            <td>
                                % if q.process_result is True:
                                    <span class="label label-success"><span class="glyphicon glyphicon-plus" aria-hidden="true"></span></span>
                                % elif q.process_result is False:
                                    <span class="label label-danger"><span class="glyphicon glyphicon-remove" aria-hidden="true"></span></span>
                                % endif
                            </td>
                        </tr>
                    % endfor
                </table>
            % else:
                <em>
                    No Queue Items
                </em>
            % endif
        </div>
    </div>
</%block>
