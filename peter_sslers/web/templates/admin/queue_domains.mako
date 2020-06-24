<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Queue: Domains</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Queue: Domains</h2>
</%block>


<%block name="page_header_nav">
    ${admin_partials.handle_querystring_result()}
    <div class="clearfix">
        <p class="pull-right">
            <a href="${admin_prefix}/queue-domains.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
                .json
            </a>
        </p>
    </div>
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
                result = request.params.get('result')
                operation = request.params.get('operation')
                error = request.params.get('error')
                
                # only for `add`
                results = request.params.get('results')

                # only for `processed`
                acme_order_id = request.params.get('acme-order-id')
            %>
            % if result:
                <h3>Result: ${operation or ''}</h3>
                Your request resulted in: ${result}
            % endif
            % if error:
                <h4>Error</h4>
                ${error}
            % endif
            % if results:
                <h4>Results</h4>
                <textarea class="form-control">${results}</textarea>
                <hr/>
            % endif
            % if acme_order_id:
                <h4>AcmeOrder</h4>
                    The following item was created:
                    <a class="label label-info" href="${admin_prefix}/acme-order/${acme_order_id}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        AcmeOrder-${acme_order_id}
                    </a>
                <hr/>
            % endif

            <p>
                The domain queue is designed to allow for domains to be "queued in" for later batch processing.  A domain can have multiple entries, but only one "active" entry. 
            </p>

            % if QueueDomains:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>domain_name</th>
                            <th>timestamp_created</th>
                            <th>timestamp_processed</th>
                            <th>active?</th>
                            <th>domain</th>
                        </tr>
                    </thead>
                    % for q in QueueDomains:
                        <tr>
                            <td><a class="label label-info" href="${admin_prefix}/queue-domain/${q.id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ${q.id}</a></td>
                            <td><code>${q.domain_name}</code></td>
                            <td><timestamp>${q.timestamp_created}</timestamp></td>
                            <td><timestamp>${q.timestamp_processed or ''}</timestamp></td>
                            <td>
                                % if q.is_active:
                                    <span class="label label-success">y</span>
                                % else:
                                    <span class="label label-default">x</span>
                                % endif
                            </td>
                            <td>
                                % if q.domain_id:
                                    <a class="label label-info" href="${admin_prefix}/domain/${q.domain_id}">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        Domain-${q.domain_id}
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
