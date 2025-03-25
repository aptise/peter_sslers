<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/renewal-configurations">RenewalConfiguration</a></li>
        <li class="active">New Enrollment</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>RenewalConfiguration - New Enrollment</h2>
</%block>

<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/renewal-configuration/new-enrollment.json?enrollment_factory_id=${EnrollmentFactory.id}" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">

    <div class="row">
        <div class="col-sm-6">

            <form
                action="${admin_prefix}/renewal-configuration/new-enrollment"
                method="POST"
                enctype="multipart/form-data"
                id="form-renewal_configuration-new_enrollment"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}




                <table class="table table-striped table-condenesed">
                    <tr>
                        <th>Enrollment Factory</th>
                        <td>
                            <a class="label label-info" href="${admin_prefix}/enrollment-factory/${EnrollmentFactory.id}">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            EnrollmentFactory-${EnrollmentFactory.id}</a>
                            <span class="label label-default">${EnrollmentFactory.name}</span>
                            <input type="hidden" name="enrollment_factory_id" value="${EnrollmentFactory.id}"/>
                        </td>
                    </tr>
                    <tr>
                        <th colspan="2">Shared</th>
                    </tr>
                    <tr>
                        <th>EnrollmentFactory note</th>
                        <td>${EnrollmentFactory.note}</td>
                    </tr>
                    <tr>
                        <th>RenewalConfiguration note</th>
                        <td>${admin_partials.formgroup__note()}</td>
                    </tr>
                    <tr>
                        <th>Domain Templates - http01</th>
                        <td><code>${EnrollmentFactory.domain_template_http01}</code></td>
                    </tr>
                    <tr>
                        <th>Domain Templates - dns01</th>
                        <td><code>${EnrollmentFactory.domain_template_dns01}</code></td>
                    </tr>
                    <tr>
                        <th>Label</th>
                        <td>
${admin_partials.formgroup__label(default=EnrollmentFactory.label_template, context_enrollment_factory=True)}
                        </td>
                    </tr>
                    <tr>
                        <th>is_export_filesystem</th>
                       <td>
                           <code>${model_websafe.OptionsOnOff.as_string(model_websafe.OptionsOnOff.ENROLLMENT_FACTORY_DEFAULT)}</code>
                           </td>
                    </tr>
                    <tr>
                        <th>Domain Name</th>
                        <td>
                        
                            <label for="domain_name">Domain Name</label>
                            <input class="form-control" name="domain_name" id="form-domain_name" value=""/>
                            <p class="help-block">
                               A single domain name, which will be expaneded into the EnrollmentFactory template(s) above.
                            </p>                        
                        </td>
                    </tr>
                    <tr>
                        <th colspan="2">Primary Certificate</th>
                    </tr>
                    <tr>
                        <th>AcmeAccount</th>
                        <td>
                            <a class="label label-info" href="${admin_prefix}/acme-account/${EnrollmentFactory.acme_account_id__primary}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeAccount-${EnrollmentFactory.acme_account_id__primary}
                            </a>
                            % if EnrollmentFactory.acme_account__primary.name:
                                <span class="label label-default">${EnrollmentFactory.acme_account__primary.name}</span>
                            % endif
                            on
                            <a class="label label-info" href="${admin_prefix}/acme-server/${EnrollmentFactory.acme_account__primary.acme_server_id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeServer-${EnrollmentFactory.acme_account__primary.acme_server_id}
                            <span class="label label-default">${EnrollmentFactory.acme_account__primary.acme_server.name}</span>
                        </td>
                    </tr>
                    <tr>
                        <th>ACME Profile</th>
                        <td>
<code>${EnrollmentFactory.acme_profile__primary or ""}</code> &raquo;
<code>${EnrollmentFactory.acme_profile__primary__effective}</code>
                        </td>
                        </td>
                    </tr>
                    <tr>
                        <th>Private Key Technology</th>
                        <td>
<code>${EnrollmentFactory.private_key_technology__primary}</code> &raquo;
<code>${EnrollmentFactory.private_key_technology__primary__effective}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>Private Key Cycle</th>
                        <td>
<code>${EnrollmentFactory.private_key_cycle__primary}</code> &raquo;
<code>${EnrollmentFactory.private_key_cycle__primary__effective}</code>
                        </td>
                    </tr>
                    % if not EnrollmentFactory.acme_account__backup:
                        <tr>
                            <th colspan="2">NO Backup Certificate</th>
                        </tr>
                    % else:
                        <tr>
                            <th colspan="2">Backup Certificate</th>
                        </tr>
                        <tr>
                            <th>AcmeAccount</th>
                            <td>
                            <a class="label label-info" href="${admin_prefix}/acme-account/${EnrollmentFactory.acme_account_id__backup}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeAccount-${EnrollmentFactory.acme_account_id__backup}
                            </a>
                            % if EnrollmentFactory.acme_account__backup.name:
                                <span class="label label-default">${EnrollmentFactory.acme_account__backup.name}</span>
                            % endif
                            on
                            <a class="label label-info" href="${admin_prefix}/acme-server/${EnrollmentFactory.acme_account__backup.acme_server_id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                AcmeServer-${EnrollmentFactory.acme_account__backup.acme_server_id}
                            <span class="label label-default">${EnrollmentFactory.acme_account__backup.acme_server.name}</span>
                            </td>
                        </tr>
                        <tr>
                            <th>ACME Profile</th>
                            <td>
    <code>${EnrollmentFactory.acme_profile__backup or ""}</code> &raquo;
    <code>${EnrollmentFactory.acme_profile__backup__effective}</code>
                            </td>
                            </td>
                        </tr>
                        <tr>
                            <th>Private Key Technology</th>
                            <td>
    <code>${EnrollmentFactory.private_key_technology__backup}</code> &raquo;
    <code>${EnrollmentFactory.private_key_technology__backup__effective}</code>
                            </td>
                        </tr>
                        <tr>
                            <th>Private Key Cycle</th>
                            <td>
    <code>${EnrollmentFactory.private_key_cycle__backup}</code> &raquo;
    <code>${EnrollmentFactory.private_key_cycle__backup__effective}</code>
                            </td>
                    % endif
                </table>

                <hr/>

                <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>
            </form>
        </div>
        <div class="col-sm-6">
            <p>This route supports JSON and is self-documenting on GET requests.</p>

            <p>A Factory Enrollment only accepts a DOMAIN and a Note.</p>


        </div>
    </div>
</%block>

