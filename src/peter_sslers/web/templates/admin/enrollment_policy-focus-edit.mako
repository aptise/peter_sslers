<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/enrollment-policys">Enrollment Policys</a></li>
        <li><a href="${admin_prefix}/enrollment-policy/${EnrollmentPolicy.id}">Enrollment Policy ${EnrollmentPolicy.id}-`${EnrollmentPolicy.name}`</a></li>
        <li class="active">Edit</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>EnrollmentPolicy - Focus - [${EnrollmentPolicy.id}-`${EnrollmentPolicy.name}`] - Edit</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/enrollment-policy/${EnrollmentPolicy.id}/edit.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    ${admin_partials.handle_querystring_result()}

    <div class="row">
        <div class="col-sm-12">


            <form action="${admin_prefix}/enrollment-policy/${EnrollmentPolicy.id}/edit"
                  method="POST"
                  id="form-enrollment_policy-edit"
                  >


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
                                ${EnrollmentPolicy.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>name</th>
                        <td>
                            <span class="label label-default">
                                ${EnrollmentPolicy.name}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>is_system</th>
                        <td>
                            % if EnrollmentPolicy.is_system:
                                <span class="label label-info">
                                    System Policy
                                </span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeAccount</th>
                        <td>
                           ${admin_partials.formgroup__AcmeAccount_select(
                               acmeAccounts=AcmeAccounts,
                               default=EnrollmentPolicy.acme_account_id__primary,
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
                    % if EnrollmentPolicy.name == "global":
                        <tr>
                            <th>acme_profile__primary</th>
                            <td>
                                <code>${EnrollmentPolicy.acme_profile__primary}</code>
                                <input
                                    type="hidden"
                                    name="acme_profile__primary"
                                    value="${EnrollmentPolicy.acme_profile__primary}"
                                />
                            </td>
                        </tr>
                        <tr>
                            <th>private_key_technology__primary</th>
                            <td>
                                <code>${EnrollmentPolicy.private_key_technology__primary}</code>
                                <input
                                    type="hidden"
                                    name="private_key_technology__primary"
                                    value="${EnrollmentPolicy.private_key_technology__primary}"
                                />
                            </td>
                        </tr>
                        <tr>
                            <th>private_key_cycle__primary</th>
                            <td>
                                <code>${EnrollmentPolicy.private_key_cycle__primary}</code>
                                <input
                                    type="hidden"
                                    name="private_key_cycle__primary"
                                    value="${EnrollmentPolicy.private_key_cycle__primary}"
                                />
                            </td>
                        </tr>
                    % else:
                        <tr>
                            <th>acme_profile__primary</th>
                            <td>
                                <input
                                    type="text"
                                    class="form-control"
                                    name="acme_profile__primary"
                                    value="${EnrollmentPolicy.acme_profile__primary or ''}"
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
                                   default=EnrollmentPolicy.private_key_technology__primary,
                                   field_name="private_key_technology__primary",
                                )}
                            </td>
                        </tr>
                        <tr>
                            <th>private_key_cycle__primary</th>
                            <td>
                               ${admin_partials.formgroup__private_key_cycle(
                                   field_name="private_key_cycle__primary",
                                   default=EnrollmentPolicy.private_key_cycle__primary,
                                )}
                            </td>
                        </tr>
                    % endif
                    <tr>
                        <th>AcmeAccount [Backup]</th>
                        <td>
                           ${admin_partials.formgroup__AcmeAccount_select(
                               acmeAccounts=AcmeAccounts,
                               default=EnrollmentPolicy.acme_account_id__backup,
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
                    % if EnrollmentPolicy.name == "global":
                        <tr>
                            <th>acme_profile__backup</th>
                            <td>
                                <code>${EnrollmentPolicy.acme_profile__backup}</code>
                                <input
                                    type="hidden"
                                    name="acme_profile__backup"
                                    value="${EnrollmentPolicy.acme_profile__backup}"
                                />
                            </td>
                        </tr>
                        <tr>
                            <th>private_key_technology__backup</th>
                            <td>
                                <code>${EnrollmentPolicy.private_key_technology__backup}</code>
                                <input
                                    type="hidden"
                                    name="private_key_technology__backup"
                                    value="${EnrollmentPolicy.private_key_technology__backup}"
                                />
                            </td>
                        </tr>
                        <tr>
                            <th>private_key_cycle__backup</th>
                            <td>
                                <code>${EnrollmentPolicy.private_key_cycle__backup}</code>
                                <input
                                    type="hidden"
                                    name="private_key_cycle__backup"
                                    value="${EnrollmentPolicy.private_key_cycle__backup}"
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
                                    value="${EnrollmentPolicy.acme_profile__backup or ''}"
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
                                   default=EnrollmentPolicy.private_key_technology__backup,
                                   field_name="private_key_technology__backup",
                                )}
                            </td>
                        </tr>
                        <tr>
                            <th>private_key_cycle__backup</th>
                            <td>
                               ${admin_partials.formgroup__private_key_cycle(
                                   field_name="private_key_cycle__backup",
                                   default=EnrollmentPolicy.private_key_cycle__backup,
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
