<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/queue-domains">Queue Domains</a></li>
        <li class="active">Process</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Queue Domains - Process</h2>
</%block>


<%block name="page_header_nav">
    <div class="clearfix">
        <p class="pull-right">
            <a href="${admin_prefix}/queue-domains/process.json" class="btn btn-xs btn-info">
                <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
                .json
            </a>
        </p>
    </div>
</%block>


<%block name="content_main">
    ${admin_partials.standard_error_display()}
    ${admin_partials.handle_querystring_result()}
    <div class="row">
        <div class="col-sm-12">

            <h4>Process the existing Domains Queue into Certificates</h4>
            
            <p>Upon submission, the following combination will be used by the processing queue:</p>

            <p><b>There are ${QueueDomain_Count} domains in the queue</b></p>

            % if QueueDomain_Count:
                <p><b>The next max-100 domains in the queue are</b></p>
                <ul>
                    % for QueueDomain in QueueDomain_100:
                        <li><code>${QueueDomain.domain_name}</code></li>
                    % endfor
                </ul>
            % endif
            
            <form
                action="${admin_prefix}/queue-domains/process"
                method="POST"
                enctype="multipart/form-data"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}
                <table class="table table-striped table-condensed">
                    <tbody>
                        <tr>
                            <th>AcmeAccount</th>
                            <td>
                                ${admin_partials.formgroup__AcmeAccount_selector__advanced()}
                            </td>
                        </tr>
                        <tr>
                            <th>PrivateKey</th>
                            <td>
                                ${admin_partials.formgroup__PrivateKey_selector__advanced(option_account_key_default=True, option_generate_new=True)}
                            </td>
                        </tr>
                        <tr>
                            <th>Max Domains per Certificate</th>
                            <td>
                                <input type="text" name="max_domains_per_certificate" value="50" />
                            </td>
                        </tr>

                        <tr>
                            <th>Private Key Cycling: Renewals</th>
                            <td>
                                ${admin_partials.formgroup__private_key_cycle__renewal()}
                            </td>
                        </tr>
                        <tr>
                            <th>Processing Strategy</th>
                            <td>
                                ${admin_partials.formgroup__processing_strategy()}
                            </td>
                        </tr>
                        <tr>
                            <th></th>
                            <td>
                                <button class="btn btn-xs btn-primary" type="submit">
                                    <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
                                    Process the Queue!
                                </button>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </form>
        </div>
    </div>
</%block>
