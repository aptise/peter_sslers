<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/enrollment-factorys">EnrollmentFactorys</a></li>
        <li class="active">New</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>EnrollmentFactorys - New</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/enrollment-factorys/new.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    ${admin_partials.handle_querystring_result()}

    <div class="row">
        <div class="col-sm-12">


            <form action="${admin_prefix}/enrollment-factorys/new"
                  method="POST"
                  id="form-enrollment_factorys-new"
                  >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}
                <table class="table table-condensed">
                    <thead>
                        <tr>
                            <th>
                                Primary Configuration
                            </th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>AcmeAccount</td>
                            <td>
                               ${admin_partials.formgroup__AcmeAccount_select(
                                   acmeAccounts=AcmeAccounts,
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
                            <td>Profile</td>
                            <td>
                               ${admin_partials.formgroup__acme_profile(
                                   field_name="acme_profile__primary",
                                )}
                            </td>
                        </tr>
                        <tr>
                            <td>Key Technology</td>
                            <td>
                               ${admin_partials.formgroup__key_technology(
                                   field_name="private_key_technology__primary",
                                )}
                            </td>
                        </tr>
                        <tr>
                            <td>Key Cycling</td>
                            <td>
                               ${admin_partials.formgroup__private_key_cycle(
                                   field_name="private_key_cycle__primary",
                                )}
                            </td>
                        </tr>
                    </tbody>
                    <thead>
                    <tr>
                        <th>
                            Backup Configuration
                        </th>
                    </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>AcmeAccount</td>
                            <td>
                               ${admin_partials.formgroup__AcmeAccount_select(
                                   acmeAccounts=AcmeAccounts,
                                   field_name="acme_account_id__backup",
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
                            <td>Profile</td>
                            <td>
                               ${admin_partials.formgroup__acme_profile(
                                   field_name="acme_profile__backup",
                                )}
                            </td>
                        </tr>
                        <tr>
                            <td>Key Technology</td>
                            <td>
                               ${admin_partials.formgroup__key_technology(
                                   field_name="private_key_technology__backup",
                                )}
                            </td>
                        </tr>
                        <tr>
                            <td>Key Cycle</td>
                            <td>
                               ${admin_partials.formgroup__private_key_cycle(
                                   field_name="private_key_cycle__backup",
                                )}
                            </td>
                        </tr>
                    </tbody>
                    <tr>
                        <th>
                            Shared Configuration
                        </th>
                    </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>name</td>
                            <td>
                                ${admin_partials.formgroup__name()}
                            </td>
                        </tr>
                        <tr>
                            <td>is_export_filesystem</td>
                            <td>
                                ${admin_partials.formgroup__is_export_filesystem()}
                            </td>
                        </tr>
                        <tr>
                            <td>note</td>
                            <td>
                                ${admin_partials.formgroup__note()}
                            </td>
                        </tr>
                        <tr>
                            <td>template</td>
                            <td>
                                ${admin_partials.formgroup__domain_templates(default_http01="{DOMAIN}")}
                            </td>
                        </tr>
                        <tr>
                            <td></td>
                            <td>
                                <button class="btn btn-primary" type="submit" name="submit" value="submit">
                                    <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
                                    New
                                </button>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </form>
        </div>
    </div>
</%block>
