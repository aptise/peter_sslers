<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Queue: Certificates</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Queue: Certificates</h2>
    <p>Most QueueCertificates can be created from a link on an exisiting object&apos;s "Focus" page to the <code>/new/structured</code> form.
        <ul>
            <li>AcmeOrder</li>
            <li>ServerCertificate</li>
            <li>UniqueFQDNSet</li>
        </ul>
    </p>
    <p>
        If you do not have an existing UniqueFQDNSet, you can use the <code>/new/freeform</code> form:
            <a href="${admin_prefix}/queue-certificate/new/freeform"
               class="btn btn-primary btn-xs"
            >
                <span class="glyphicon glyphicon-plus"></span>
                QueueCertificate    
            </a>
    </p>
</%block>


<%block name="page_header_nav">
    <div class="clearfix">
        <p class="pull-right">
            <a href="${admin_prefix}/queue-certificates/${sidenav_option}.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
                .json
            </a>
        </p>
    </div>
    <ul class="nav nav-pills nav-stacked">
      <li role="presentation" class="${'active' if sidenav_option == 'all' else ''}"><a href="${admin_prefix}/queue-certificates/all">All Items</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'failures' else ''}"><a href="${admin_prefix}/queue-certificates/failures">Failures</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'successes' else ''}"><a href="${admin_prefix}/queue-certificates/successes">Successes</a></li>
      <li role="presentation" class="${'active' if sidenav_option == 'unprocessed' else ''}"><a href="${admin_prefix}/queue-certificates/unprocessed">Unprocessed Items</a></li>
      <li role="presentation" class="">
        <a href="${admin_prefix}/api/queue-certificates/update">
        <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
        Update Queue (30 days or less)</a>
      </li>
      % if QueueCertificates:
          <li role="presentation" class="">
            <a href="${admin_prefix}/api/queue-certificates/process">
            <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
            Process Queue Items</a>
          </li>
          <li role="presentation" class="">
            <a href="${admin_prefix}/api/queue-certificates/process.json">
            <span class="glyphicon glyphicon-refresh" aria-hidden="true"></span>
            Process Queue Items - JSON</a>
          </li>
        % endif
    </ul>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            ${admin_partials.handle_querystring_result()}
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
                <meta http-equiv="refresh" content="1; url=${admin_prefix}/api/queue-certificates/process">
                <div class="alert alert-info">
                    Queue Still Populated, automatically continuing...
                </div>
            % endif

            % if QueueCertificates:
                ${admin_partials.nav_pagination(pager)}
                ${admin_partials.table_QueueCertificates(QueueCertificates)}
            % else:
                <em>
                    No Queue Items
                </em>
            % endif
        </div>
    </div>
</%block>
