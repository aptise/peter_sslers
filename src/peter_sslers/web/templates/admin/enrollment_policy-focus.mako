<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/enrollment-policys">Enrollment Policys</a></li>
        <li class="active">Focus [${EnrollmentPolicy.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>EnrollmentPolicy - Focus - [${EnrollmentPolicy.id}]</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/enrollment-policy/${EnrollmentPolicy.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
        <a href="${admin_prefix}/enrollment-policy/${EnrollmentPolicy.id}/edit" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-pencil" aria-hidden="true"></span>
            Edit
        </a>
    </p>
</%block>


<%block name="content_main">
    ${admin_partials.handle_querystring_result()}

    <div class="row">
        <div class="col-sm-12">
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
                            <span class="label label-default">
                                ${EnrollmentPolicy.acme_account_id}
                            </span>
                            % if EnrollmentPolicy.acme_account_id:
                                <a class="label label-info" href="${admin_prefix}/acme-account/${EnrollmentPolicy.acme_account_id}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeAccount-${EnrollmentPolicy.acme_account_id}
                                    |
                                    ${EnrollmentPolicy.acme_account.displayable}
                                </a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>acme_profile</th>
                        <td>
                            <span class="label label-default">
                                ${EnrollmentPolicy.acme_profile or ""}
                            </span>
                            <span class="label label-info">
                                ${EnrollmentPolicy.acme_profile__effective or ""}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>key_technology</th>
                        <td>
                            <span class="label label-default">
                                ${EnrollmentPolicy.key_technology}
                            </span>
                            <span class="label label-info">
                                ${EnrollmentPolicy.key_technology__effective}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>private_key_cycle</th>
                        <td>
                            <span class="label label-default">
                                ${EnrollmentPolicy.private_key_cycle}
                            </span>
                            <span class="label label-info">
                                ${EnrollmentPolicy.private_key_cycle__effective}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeAccount [Backup]</th>
                        <td>
                            <span class="label label-default">
                                ${EnrollmentPolicy.acme_account_id__backup}
                            </span>
                            % if EnrollmentPolicy.acme_account_id:
                                <a class="label label-info" href="${admin_prefix}/acme-account/${EnrollmentPolicy.acme_account_id__backup}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeAccount-${EnrollmentPolicy.acme_account_id__backup}
                                    |
                                    ${EnrollmentPolicy.acme_account__backup.displayable}
                                </a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>acme_profile__backup</th>
                        <td>
                            <span class="label label-default">
                                ${EnrollmentPolicy.acme_profile__backup or ""}
                            </span>
                            <span class="label label-info">
                                ${EnrollmentPolicy.acme_profile__backup__effective or ""}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>key_technology__backup</th>
                        <td>
                            <span class="label label-default">
                                ${EnrollmentPolicy.key_technology__backup}
                            </span>
                            <span class="label label-info">
                                ${EnrollmentPolicy.key_technology__backup__effective}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>private_key_cycle__backup</th>
                        <td>
                            <span class="label label-default">
                                ${EnrollmentPolicy.private_key_cycle__backup}
                            </span>
                            <span class="label label-info">
                                ${EnrollmentPolicy.private_key_cycle__backup__effective}
                            </span>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</%block>
