<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificate-signeds">Certificate Signeds</a></li>
        <li class="active">Search</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Certificate Signeds: Search</h2>
</%block>


<%block name="page_header_nav">
    <a  class="btn btn-xs btn-info"
        href="${admin_prefix}/certificate-signeds/search.json"
    >
        <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
        .json</a>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <p>
                Search certificates by a field
            </p>
            <form action="${admin_prefix}/certificate-signeds/search" id="form-certificate_signeds-search" method="POST">
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}
                <div class="form-group">
                    <label for="ari_identifier">ARI Identifier</label>
                    <input type="text" name="ari_identifier" class="form-control" />
                </div>
                <div class="form-group">
                    <label for="serial">Serial</label>
                    <input type="text" name="serial" class="form-control" />
                </div>
                <button class="btn btn-primary" type="submit">Submit</button>
            </form>
            % if search_query:
                <hr/>
                <h4>Query</h4>
                <code>${search_query}</code>
                
                <h4>Results - Certificate</h4>
                % if search_results['CertificateSigned']:
                    <table class="table table-striped table-condensed">
                        <thead>
                            <tr>
                                <th colspan="2">CertificateSigned</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <th>id</th>
                                <td><code>${search_results['CertificateSigned'].id}</code></td>
                            </tr>
                            <tr>
                                <th>record</th>
                                <td><a href="${admin_prefix}/certificate-signed/${search_results['CertificateSigned'].id}"
                                       class="label label-info"
                                    >
                                    CertificateSigned-${search_results['CertificateSigned'].id}
                                    </a>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                % else:
                    <em>No CertificateSigned</em>
                % endif 
            % endif 
            
        </div>
    </div>
</%block>
