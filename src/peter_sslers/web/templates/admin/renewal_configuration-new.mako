<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/renewal-configurations/all">Renewal Configurations</a></li>
        <li class="active">New</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Renewal Configuration | New</h2>
    <div class="alert alert-info">
        <em>
            Requests will be performed against the Certificate Authority associated with the Account Key
        </em>
    </div>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/renewal-configuration/new.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">

    <div class="row">
        <div class="col-sm-6">
        
            ${admin_partials.messaging_SystemConfiguration_global()}

            <form
                action="${admin_prefix}/renewal-configuration/new"
                method="POST"
                enctype="multipart/form-data"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}

                <h3>Primary Certificate</h3>
                ${admin_partials.formgroup__AcmeAccount_selector__advanced(
                    support_upload=False,
                    support_profiles=True,
                    default_profile=SystemConfiguration_global.acme_profile__primary,
                    dbSystemConfiguration=SystemConfiguration_global,
                )}
                <h4>PrivateKey</h4>
                ${admin_partials.formgroup__private_key_cycle(
                    field_name="private_key_cycle__primary",
                    default=SystemConfiguration_global.private_key_cycle__primary,
                )}
                ${admin_partials.formgroup__key_technology(
                    field_name="private_key_technology__primary",
                    default=model_websafe.KeyTechnology._DEFAULT_RenewalConfiguration,
                    options=model_websafe.KeyTechnology._options_RenewalConfiguration_private_key_technology,
                )}
                <hr/>
                <hr/>

                <h3>Backup Certificate</h3>
                ${admin_partials.formgroup__AcmeAccount_selector__backup(
                    support_profiles=True,
                    default_profile=SystemConfiguration_global.acme_profile__backup,
                    dbSystemConfiguration=SystemConfiguration_global,
                )}
                <h4>PrivateKey</h4>
                ${admin_partials.formgroup__private_key_cycle(
                    field_name="private_key_cycle__backup",
                    label="[Backup Certificate]",
                    default=SystemConfiguration_global.private_key_cycle__backup,
                )}
                ${admin_partials.formgroup__key_technology(
                    field_name="private_key_technology__backup",
                    label="[Backup Certificate]",
                    default=model_websafe.KeyTechnology._DEFAULT_RenewalConfiguration,
                    options=model_websafe.KeyTechnology._options_RenewalConfiguration_private_key_technology,
                )}
                <hr/>
                <hr/>

                <h3>Shared Configuration</h3>
                ${admin_partials.formgroup__domain_names(
                    specify_challenge=True,
                    domain_names_http01=domain_names_http01,
                    domain_names_dns01=domain_names_dns01,
                    AcmeDnsServer_GlobalDefault=AcmeDnsServer_GlobalDefault,
                    )}
                ${admin_partials.formgroup__note()}
                ${admin_partials.formgroup__label()}
                ${admin_partials.formgroup__is_export_filesystem(default="off", support_enrollment_factory_default=False)}
                <hr/>
                <hr/>

                <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>
            </form>
        </div>
        <div class="col-sm-6">
            <p>This route supports JSON and is self-documenting on GET requests.</p>
            ${admin_partials.info_AcmeAccount()}
            ## ${admin_partials.info_PrivateKey()}
        </div>
    </div>
</%block>
