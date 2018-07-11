<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/domains">Domains</a></li>
        <li class="active">Search</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Domains: Search</h2>
</%block>


<%block name="page_header_nav">
    ${admin_partials.domains_section_nav()}
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <p>
            This will seach registered and queued domains to determine if they are enrolled.
            </p>
            <form action="${admin_prefix}/domains/search" method="POST">
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}
                <div class="form-group">
                    <label for="domain">Domain Name</label>
                    <input type="text" name="domain" class="form-control" />
                </div>
                <button class="btn btn-primary" type="submit">Submit</button>
            </form>
            % if search_results:
                <hr/>
                <h4>Query</h4>
                <code>${search_results['query']}</code>
                
                <h4>Results - SslDomain</h4>
                % if search_results['SslDomain']:
                    <table class="table table-striped table-condensed">
                        <thead>
                            <tr>
                                <th colspan="2">SslDomain</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <th>domain_name</th>
                                <td><code>${search_results['SslDomain'].domain_name}</code></td>
                            </tr>
                            <tr>
                                <th>record</th>
                                <td><a href="${admin_prefix}/domain/${search_results['SslDomain'].id}"
                                       class="label label-info"
                                    >
                                    domain-${search_results['SslDomain'].id}
                                    </a>
                                </td>
                            </tr>
                            <tr>
                                <th>is_active</th>
                                <td>${search_results['SslDomain'].is_active}</td>
                            </tr>
                        </tbody>
                    </table>
                % else:
                    <em>No SslDomain</em>
                % endif 

                <h4>Results - SslQueueDomain Active</h4>
                % if search_results['SslQueueDomainActive']:
                    <table class="table table-striped table-condensed">
                        <thead>
                            <tr>
                                <th colspan="2">SslQueueDomain</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <th>domain_name</th>
                                <td><code>${search_results['SslQueueDomainActive'].domain_name}</code></td>
                            </tr>
                            <tr>
                                <th>record</th>
                                <td><a href="${admin_prefix}/queue-domain/${search_results['SslQueueDomainActive'].id}"
                                       class="label label-info"
                                    >
                                    queue-domain-${search_results['SslQueueDomainActive'].id}
                                    </a>
                                </td>
                            </tr>
                            <tr>
                                <th>is_active</th>
                                <td>${search_results['SslQueueDomainActive'].is_active}</td>
                            </tr>
                        </tbody>
                    </table>
                % else:
                    <em>No SslQueueDomain - Active</em>
                % endif 

                <h4>Results - SslQueueDomains - Inactive</h4>
                % if search_results['SslQueueDomainsInactive']:
                    <table class="table table-striped table-condensed">
                        <thead>
                            <tr>
                                <th colspan="2">SslQueueDomainsInactive</th>
                            </tr>
                        </thead>
                        <tbody>
                            % for q in search_results['SslQueueDomainsInactive']:
                                <tr>
                                    <th>domain_name</th>
                                    <td><code>${q.domain_name}</code></td>
                                </tr>
                                <tr>
                                    <th>record</th>
                                    <td><a href="${admin_prefix}/queue-domain/${q.id}"
                                           class="label label-info"
                                        >
                                        queue-domain-${q.id}
                                        </a>
                                    </td>
                                </tr>
                                <tr>
                                    <th>is_active</th>
                                    <td>${q.is_active}</td>
                                </tr>
                                <tr>
                                    <td colspan="2"><hr/></td>
                                </tr>
                            % endfor
                        </tbody>
                    </table>
                % else:
                    <em>No SslQueueDomain - Active</em>
                % endif 
            % endif 
            
        </div>
    </div>
</%block>
