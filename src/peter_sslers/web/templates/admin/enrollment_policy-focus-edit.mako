<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/enrollment-policys">Enrollment Policys</a></li>
        <li><a href="${admin_prefix}/enrollment-policy/${EnrollmentPolicy.id}">Enrollment Policy ${EnrollmentPolicy.id}</a></li>
        <li class="active">Edit</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>EnrollmentPolicy - Edit</h2>
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
                        <th>AcmeAccount</th>
                        <td>
                           ${admin_partials.formgroup__AcmeAccount_select(
                               acmeAccounts=AcmeAccounts,
                               default=EnrollmentPolicy.acme_account_id,
                               field_name="acme_account_id",
                            )}
                        </td>
                    </tr>
                    <tr>
                        <th>acme_profile</th>
                        <td>
                            <input
                                type="text"
                                class="form-control"
                                name="acme_profile"
                                value="${EnrollmentPolicy.acme_profile or ''}"
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>key_technology</th>
                        <td>
                           ${admin_partials.formgroup__key_technology(
                               default=EnrollmentPolicy.key_technology,
                               field_name="key_technology",
                            )}
                        </td>
                    </tr>
                    <tr>
                        <th>private_key_cycle</th>
                        <td>
                           ${admin_partials.formgroup__private_key_cycle(
                               default=EnrollmentPolicy.private_key_cycle,
                               field_name="private_key_cycle",
                            )}
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeAccount [Backup]</th>
                        <td>
                           ${admin_partials.formgroup__AcmeAccount_select(
                               acmeAccounts=AcmeAccounts,
                               default=EnrollmentPolicy.acme_account_id__backup,
                               field_name="acme_account_id__backup",
                            )}
                        </td>
                    </tr>
                    <tr>
                        <th>acme_profile__backup</th>
                        <td>
                            <input
                                type="text"
                                class="form-control"
                                name="acme_profile__backup"
                                value="${EnrollmentPolicy.acme_profile__backup or ''}"
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>key_technology__backup</th>
                        <td>
                           ${admin_partials.formgroup__key_technology(
                               default=EnrollmentPolicy.key_technology__backup,
                               field_name="key_technology__backup",
                            )}
                        </td>
                    </tr>
                    <tr>
                        <th>private_key_cycle__backup</th>
                        <td>
                           ${admin_partials.formgroup__private_key_cycle(
                               default=EnrollmentPolicy.private_key_cycle__backup,
                               field_name="private_key_cycle__backup",
                            )}
                        </td>
                    </tr>
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
