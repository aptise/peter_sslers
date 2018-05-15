<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Queue: Domains</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Queue: Domains</h2>

    ${admin_partials.standard_error_display()}
</%block>


<%block name="page_header_nav">
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
            
            <p>
                The domain queue is designed to allow for domains to be "queued in" for later batch processing.
            </p>

            % if SslQueueDomains:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>domain_name</th>
                            <th>timestamp_entered</th>
                            <th>timestamp_processed</th>
                            <th>active?</th>
                            <th>domain</th>
                        </tr>
                    </thead>
                    % for q in SslQueueDomains:
                        <tr>
                            <td><a class="label label-info" href="${admin_prefix}/queue-domain/${q.id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ${q.id}</a></td>
                            <td><code>${q.domain_name}</code></td>
                            <td><timestamp>${q.timestamp_entered}</timestamp></td>
                            <td><timestamp>${q.timestamp_processed or ''}</timestamp></td>
                            <td>
                                % if q.is_active:
                                    <span class="label label-success">y</span>
                                % else:
                                    <span class="label label-default">x</span>
                                % endif
                            </td>
                            <td>
                                % if q.ssl_domain_id:
                                    <a class="label label-info" href="${admin_prefix}/domain/${q.ssl_domain_id}">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        ${q.ssl_domain_id}
                                    </a>
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
