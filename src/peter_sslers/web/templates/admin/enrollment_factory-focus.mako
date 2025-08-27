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
        <a href="${admin_prefix}/enrollment-factory/${EnrollmentFactory.id}/query" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
            Query
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
                        <th>is_export_filesystem</th>
                        <td>
                            % if EnrollmentFactory.is_export_filesystem_id == model_websafe.OptionsOnOff.ON:
                                <span class="label label-success">
                                    on
                                </span>
                            % else:
                                <span class="label label-danger">
                                    off
                                </span>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>label_template</th>
                        <td>
                            <code>${EnrollmentFactory.label_template}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>onboard</th>
                        <td>
                            <a href="${admin_prefix}/enrollment-factory/${EnrollmentFactory.id}/onboard" class="btn btn-xs btn-primary">
                                <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                                Onboard
                            </a>
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
                    <thead>
                        <tr>
                            <th colspan="2">
                                Primary Certificate
                            </th>
                        </tr>
                    </thead>
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
                                </a>
                                <span class="label label-default">
                                    ${EnrollmentFactory.acme_account__primary.displayable}
                                </span>
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
                    <thead>
                        <tr>
                            <th colspan="2">
                                BACKUP Certficate
                            </th>
                        </tr>
                    </thead>
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
                                </a>
                                <span class="label label-default">
                                    ${EnrollmentFactory.acme_account__backup.displayable}
                                </span>
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
                <thead>
                    <tr>
                        <th colspan="2">
                            RELATIONS
                        </th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <th>Domains</th>
                        <td>
                            ${admin_partials.table_Domains(EnrollmentFactory.domains__5, perspective='EnrollmentFactory')}
                            ${admin_partials.nav_pager("%s/enrollment-factory/%s/domains" % (admin_prefix, EnrollmentFactory.id))}
                        </td>
                    </tr>
                    <tr>
                        <th>X509Certificates</th>
                        <td>
                            ${admin_partials.table_X509Certificates(EnrollmentFactory.x509_certificates__5, perspective='EnrollmentFactory')}
                            ${admin_partials.nav_pager("%s/enrollment-factory/%s/x509-certificates" % (admin_prefix, EnrollmentFactory.id))}
                        </td>
                    </tr>
                    <tr>
                        <th>RenewalConfigurations</th>
                        <td>
                            ${admin_partials.table_RenewalConfigurations(EnrollmentFactory.renewal_configurations__5, perspective='EnrollmentFactory')}
                            ${admin_partials.nav_pager("%s/enrollment-factory/%s/renewal-configurations" % (admin_prefix, EnrollmentFactory.id))}
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</%block>
