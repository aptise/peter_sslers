<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">API: Domain: Certificate if Needed</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>API: Domain: Certificate if Needed</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/api/domain/certificate-if-needed.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <p>
                The `certificate-if-needed` endpoint allows `nginx` to automatically provision a certificate as needed.  It is similar to the `autocert` endpoint, but allows for more control over the account options.  Autocert will only accept a domain and use the default Account and Key policies, while Certificate-if-Needed will allow for overrides.
            </p>
            <p>
                The endpoint ONLY responds to json requests.  <code>GET</code> will document, <code>POST</code> will submit.
            </p>
            
            % if not SystemConfiguration_cin.is_configured:
                <div class="alert alert-danger">
                    <p>There `certificate-if-needed` SystemConfiguration is NOT configured.</p>
                </div>
            % endif

            <table class="table table-striped table-condensed">
                <thead>
                    <tr>
                        <th>SystemConfiguration</th>
                        <th>Link</th>
                        <th>Configured?</th>
                    <tr>
                </thead>
                <tbody>
                    <tr>
                        <th>Certificate If Needed</th>
                        <td>
                            <a href="${admin_prefix}/system-configuration/${SystemConfiguration_cin.slug}" class="label label-info">
                                SystemConfiguration-${SystemConfiguration_cin.slug}
                            </a>
                        </td>
                        <td>
                            % if SystemConfiguration_cin.is_configured:
                                <span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span>
                            % else:
                                <span class="label label-danger"><span class="glyphicon glyphicon-remove" aria-hidden="true"></span></span>
                            % endif
                        </td>
                    </tr>
                </tbody>
            </table>

            
            <p>
            The .json API is self documenting; an HTML version is below:
            </p>
            <table class="table table-striped table-condensed">
            
                <tr>
                    <th colspan="2">Core</th>
                </tr>
                <tr>
                    <th><code>domain_name</code></th>
                    <td><code>string</code></td>
                </tr>
                <tr>
                    <th><code>processing_strategy</code></th>
                    <td><code>${Form_API_Domain_certificate_if_needed.fields["processing_strategy"].list}</code></td>
                </tr>
                <tr>
                    <th><code>note</code></th>
                    <td><code>string</code></td>
                </tr>
                <tr>
                    <th colspan="2">Primary Cert</th>
                </tr>
                <tr>
                    <th><code>account_key_option__primary</code></th>
                    <td><code>${Form_API_Domain_certificate_if_needed.fields["account_key_option__primary"].list}</code></td>
                </tr>
                <tr>
                    <th><code>account_key_existing__primary</code></th>
                    <td>
                        <code>string</code>
                        <p class="help">Only/Required if <code>account_key_option__primary==account_key_existing</code></p>
                    </td>
                </tr>
                <tr>
                    <th><code>private_key_cycle__primary</code></th>
                    <td><code>${Form_API_Domain_certificate_if_needed.fields["private_key_cycle__primary"].list}</code></td>
                </tr>
                <tr>
                    <th><code>private_key_option__primary</code></th>
                    <td><code>${Form_API_Domain_certificate_if_needed.fields["private_key_option__primary"].list}</code></td>
                </tr>
                <tr>
                    <th><code>private_key_existing__primary</code></th>
                    <td>
                        <code>string</code>
                        <p class="help">Only/Required if <code>private_key_option__primary=="private_key_existing"</code></p>
                    </td>
                </tr>
                <tr>
                    <th><code>private_key_technology__primary</code></th>
                    <td>
                        <code>${Form_API_Domain_certificate_if_needed.fields["private_key_technology__primary"].list}</code>
                        <p class="help">Only/Required if <code>private_key_option__primary=="private_key_generate"</code></p>
                    </td>
                </tr>
                <tr>
                    <th><code>acme_profile__primary</code></th>
                    <td><code>string</code></td>
                </tr>
                
                <tr>
                    <th colspan="2">Backup Cert</th>
                </tr>
                <tr>
                    <th><code>account_key_option__backup</code></th>
                    <td><code>${Form_API_Domain_certificate_if_needed.fields["account_key_option__backup"].list}</code></td>
                </tr>
                <tr>
                    <th><code>account_key_existing__backup</code></th>
                    <td>
                        <code>string</code>
                        <p class="help">Only/Required if <code>account_key_existing__backup=="account_key_existing"</code></p>
                    </td>
                </tr>
                <tr>
                    <th><code>private_key_cycle__backup</code></th>
                    <td><code>${Form_API_Domain_certificate_if_needed.fields["private_key_cycle__backup"].list}</code></td>
                </tr>
                <tr>
                    <th><code>private_key_option__backup</code></th>
                    <td><code>${Form_API_Domain_certificate_if_needed.fields["private_key_option__backup"].list}</code></td>
                </tr>
                <tr>
                    <th><code>private_key_existing__backup</code></th>
                    <td>
                        <code>string</code>
                        <p class="help">Only/Required if <code>private_key_option__backup=="private_key_existing"</code></p>
                    </td>
                </tr>
                <tr>
                    <th><code>private_key_technology__backup</code></th>
                    <td>
                        <code>${Form_API_Domain_certificate_if_needed.fields["private_key_technology__backup"].list}</code>
                        <p class="help">Only/Required if <code>private_key_option__backup=="private_key_generate"</code></p>
                    </td>
                </tr>
                <tr>
                    <th><code>acme_profile__backup</code></th>
                    <td><code>string</code></td>
                </tr>
            </table>
            
        </div>
    </div>
</%block>
