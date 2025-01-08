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
            This will seach registered domains to determine if they are enrolled.
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
                
                <h4>Results - Domain</h4>
                % if search_results['Domain']:
                    <table class="table table-striped table-condensed">
                        <thead>
                            <tr>
                                <th colspan="2">Domain</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <th>domain_name</th>
                                <td><code>${search_results['Domain'].domain_name}</code></td>
                            </tr>
                            <tr>
                                <th>record</th>
                                <td><a href="${admin_prefix}/domain/${search_results['Domain'].id}"
                                       class="label label-info"
                                    >
                                    Domain-${search_results['Domain'].id}
                                    </a>
                                </td>
                            </tr>
                            <tr>
                                <th>is_active</th>
                                <td>${search_results['Domain'].is_active}</td>
                            </tr>
                        </tbody>
                    </table>
                % else:
                    <em>No Domain</em>
                % endif 
            % endif 
            
        </div>
    </div>
</%block>
