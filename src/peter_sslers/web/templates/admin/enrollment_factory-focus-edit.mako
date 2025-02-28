<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/enrollment-factorys">EnrollmentFactorys</a></li>
        <li><a href="${admin_prefix}/enrollment-factory/${EnrollmentFactory.id}">EnrollmentFactory ${EnrollmentFactory.id}-`${EnrollmentFactory.name}`</a></li>
        <li class="active">Edit</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>EnrollmentFactory - Focus - [${EnrollmentFactory.id}-`${EnrollmentFactory.name}`] - Edit</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/enrollment-factory/${EnrollmentFactory.id}/edit.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    ${admin_partials.handle_querystring_result()}

    <div class="row">
        <div class="col-sm-12">


            <form action="${admin_prefix}/enrollment-factory/${EnrollmentFactory.id}/edit"
                  method="POST"
                  id="form-system_configuration-edit"
                  >

            <% form = request.pyramid_formencode_classic.get_form() %>
            ${form.html_error_main_fillable()|n}

            <table class="table table-striped table-condensed">
                <thead>
                    <tr>
                        <th colspan="2">
                            Core Details
                        </th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <th>id</th>
                        <td>
                            <span class="label label-default">
                                ${EnrollmentFactory.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>name</th>
                        <td>
                            ${admin_partials.formgroup__name(default=EnrollmentFactory.name)}
                        </td>
                    </tr>
                    <tr>
                        <th>note</th>
                        <td>
                            ${admin_partials.formgroup__note(default=EnrollmentFactory.note)}
                        </td>
                    </tr>
                    <tr>
                        <th>domain templates</th>
                        <td>
                            ${admin_partials.formgroup__domain_templates(
                                default_http01=EnrollmentFactory.domain_template_http01,
                                default_dns01=EnrollmentFactory.domain_template_dns01,
                            )}
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeAccount</th>
                        <td>
                           ${admin_partials.formgroup__AcmeAccount_select(
                               acmeAccounts=AcmeAccounts,
                               default=EnrollmentFactory.acme_account_id__primary,
                               field_name="acme_account_id__primary",
                               allow_none=False,
                            )}
                            <p>
                                Create or Upload additional
                                <a href="${admin_prefix}/acme-accounts" class="btn btn-xs btn-info">
                                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                                    AcmeAccounts
                                </a>
                                ?
                            </p>
                        </td>
                    </tr>
                        <tr>
                            <th>acme_profile__primary</th>
                            <td>
                                <input
                                    type="text"
                                    class="form-control"
                                    name="acme_profile__primary"
                                    value="${EnrollmentFactory.acme_profile__primary or ''}"
                                />
                                <p class="help">
                                    Leave this blank for no profile.
                                    If you want to defer to the AcmeAccount, use the special name <code>@</code>.
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th>private_key_technology__primary</th>
                            <td>
                               ${admin_partials.formgroup__key_technology(
                                   default=EnrollmentFactory.private_key_technology__primary,
                                   field_name="private_key_technology__primary",
                                )}
                            </td>
                        </tr>
                        <tr>
                            <th>private_key_cycle__primary</th>
                            <td>
                               ${admin_partials.formgroup__private_key_cycle(
                                   field_name="private_key_cycle__primary",
                                   default=EnrollmentFactory.private_key_cycle__primary,
                                )}
                            </td>
                        </tr>

                    <tr>
                        <th>AcmeAccount [Backup]</th>
                        <td>
                           ${admin_partials.formgroup__AcmeAccount_select(
                               acmeAccounts=AcmeAccounts,
                               default=EnrollmentFactory.acme_account_id__backup,
                               field_name="acme_account_id__backup",
                               allow_none=True,
                            )}
                            <p>
                                Create or Upload additional
                                <a href="${admin_prefix}/acme-accounts" class="btn btn-xs btn-info">
                                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                                    AcmeAccounts
                                </a>
                                ?
                            </p>
                        </td>
                    </tr>
                    % if EnrollmentFactory.name == "global":
                        <tr>
                            <th>acme_profile__backup</th>
                            <td>
                                <code>${EnrollmentFactory.acme_profile__backup}</code>
                                <input
                                    type="hidden"
                                    name="acme_profile__backup"
                                    value="${EnrollmentFactory.acme_profile__backup}"
                                />
                            </td>
                        </tr>
                        <tr>
                            <th>private_key_technology__backup</th>
                            <td>
                                <code>${EnrollmentFactory.private_key_technology__backup}</code>
                                <input
                                    type="hidden"
                                    name="private_key_technology__backup"
                                    value="${EnrollmentFactory.private_key_technology__backup}"
                                />
                            </td>
                        </tr>
                        <tr>
                            <th>private_key_cycle__backup</th>
                            <td>
                                <code>${EnrollmentFactory.private_key_cycle__backup}</code>
                                <input
                                    type="hidden"
                                    name="private_key_cycle__backup"
                                    value="${EnrollmentFactory.private_key_cycle__backup}"
                                />
                            </td>
                        </tr>
                    % else:                    
                        <tr>
                            <th>acme_profile__backup</th>
                            <td>
                                <input
                                    type="text"
                                    class="form-control"
                                    name="acme_profile__backup"
                                    value="${EnrollmentFactory.acme_profile__backup or ''}"
                                />
                                <p class="help">
                                    Leave this blank for no profile.
                                    If you want to defer to the AcmeAccount, use the special name <code>@</code>.
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th>private_key_technology__backup</th>
                            <td>
                               ${admin_partials.formgroup__key_technology(
                                   default=EnrollmentFactory.private_key_technology__backup,
                                   field_name="private_key_technology__backup",
                                )}
                            </td>
                        </tr>
                        <tr>
                            <th>private_key_cycle__backup</th>
                            <td>
                               ${admin_partials.formgroup__private_key_cycle(
                                   field_name="private_key_cycle__backup",
                                   default=EnrollmentFactory.private_key_cycle__backup,
                                )}
                            </td>
                        </tr>
                    % endif
                </tbody>
            </table>
            <button class="btn btn-primary" type="submit" name="submit" value="submit">
                <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
                Edit
            </button>

            </form>
        </div>
    </div>
</%block>
