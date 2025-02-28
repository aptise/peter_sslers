<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/enrollment-factorys">EnrollmentFactorys</a></li>
        <li class="active">Focus [${EnrollmentFactory.id}-`${EnrollmentFactory.name}`]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>EnrollmentFactory - Focus - [${EnrollmentFactory.id}-`${EnrollmentFactory.name}`]</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/enrollment-factory/${EnrollmentFactory.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
        <a href="${admin_prefix}/enrollment-factory/${EnrollmentFactory.id}/edit" class="btn btn-xs btn-info">
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
                                ${EnrollmentFactory.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>name</th>
                        <td>
                            <span class="label label-default">
                                ${EnrollmentFactory.name}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>note</th>
                        <td>
                            <code>${EnrollmentFactory.note}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>domain templates</th>
                        <td>
                            <p>
                                <b>HTTP-01</b>
                                <code>${EnrollmentFactory.domain_template_http01}</code>
                            </p>
                            <p>
                                <b>DNS-01</b>
                                <code>${EnrollmentFactory.domain_template_dns01}</code>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeAccount Primary</th>
                        <td>
                            <span class="label label-default">
                                ${EnrollmentFactory.acme_account_id__primary}
                            </span>
                            % if EnrollmentFactory.acme_account_id__primary:
                                <a class="label label-info" href="${admin_prefix}/acme-account/${EnrollmentFactory.acme_account_id__primary}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeAccount-${EnrollmentFactory.acme_account_id__primary}
                                    |
                                    ${EnrollmentFactory.acme_account__primary.displayable}
                                </a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>acme_profile__primary</th>
                        <td>
                            <span class="label label-default">
                                ${EnrollmentFactory.acme_profile__primary or ""}
                            </span>
                            <span class="label label-info">
                                ${EnrollmentFactory.acme_profile__primary__effective or ""}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>private_key_technology__primary</th>
                        <td>
                            <span class="label label-default">
                                ${EnrollmentFactory.private_key_technology__primary}
                            </span>
                            <span class="label label-info">
                                ${EnrollmentFactory.private_key_technology__primary__effective}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>private_key_cycle__primary</th>
                        <td>
                            <span class="label label-default">
                                ${EnrollmentFactory.private_key_cycle__primary}
                            </span>
                            <span class="label label-info">
                                ${EnrollmentFactory.private_key_cycle__primary__effective}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeAccount [Backup]</th>
                        <td>
                            <span class="label label-default">
                                ${EnrollmentFactory.acme_account_id__backup}
                            </span>
                            % if EnrollmentFactory.acme_account_id__backup:
                                <a class="label label-info" href="${admin_prefix}/acme-account/${EnrollmentFactory.acme_account_id__backup}">
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    AcmeAccount-${EnrollmentFactory.acme_account_id__backup}
                                    |
                                    ${EnrollmentFactory.acme_account__backup.displayable}
                                </a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>acme_profile__backup</th>
                        <td>
                            <span class="label label-default">
                                ${EnrollmentFactory.acme_profile__backup or ""}
                            </span>
                            <span class="label label-info">
                                ${EnrollmentFactory.acme_profile__backup__effective or ""}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>private_key_technology__backup</th>
                        <td>
                            <span class="label label-default">
                                ${EnrollmentFactory.private_key_technology__backup}
                            </span>
                            <span class="label label-info">
                                ${EnrollmentFactory.private_key_technology__backup__effective}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>private_key_cycle__backup</th>
                        <td>
                            <span class="label label-default">
                                ${EnrollmentFactory.private_key_cycle__backup}
                            </span>
                            <span class="label label-info">
                                ${EnrollmentFactory.private_key_cycle__backup__effective}
                            </span>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</%block>
