<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/renewal-configurations">RenewalConfiguration</a></li>
        <li><a href="${admin_prefix}/renewal-configuration/${RenewalConfiguration.id}">Focus [${RenewalConfiguration.id}]</a></li>
        <li class="active">New Configuration</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>RenewalConfiguration - Focus ${RenewalConfiguration.id} - New Configuration</h2>
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

            <form
                action="${admin_prefix}/renewal-configuration/${RenewalConfiguration.id}/new-configuration"
                method="POST"
                enctype="multipart/form-data"
                id="form-renewal_configuration-new_configuration"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}

                <h3>AcmeAccount - Primary</h3>
                ${admin_partials.formgroup__AcmeAccount_selector__advanced(
                    support_upload=False,
                    support_profiles=True,
                    dbAcmeAccountReuse=RenewalConfiguration.acme_account__primary,
                    default_profile=RenewalConfiguration.acme_profile__primary,
                    dbSystemConfiguration=SystemConfiguration_global,
                )}
                <h4>PrivateKey</h4>
                ${admin_partials.formgroup__private_key_cycle(
                    field_name="private_key_cycle__primary",
                    default=RenewalConfiguration.private_key_cycle__primary,
                )}
                ${admin_partials.formgroup__key_technology(
                    field_name="private_key_technology__primary",
                    default=RenewalConfiguration.private_key_technology__primary,
                    options=model_websafe.KeyTechnology._options_RenewalConfiguration_private_key_technology,
                )}
                <hr/>
                <hr/>

                <h3>AcmeAccount - Backup</h3>
                ${admin_partials.formgroup__AcmeAccount_selector__backup(
                    support_profiles=True,
                    dbAcmeAccountReuse=RenewalConfiguration.acme_account__backup,
                    default_profile=RenewalConfiguration.acme_profile__backup,
                    dbSystemConfiguration=SystemConfiguration_global,
                )}
                <hr/>
                <h4>PrivateKey</h4>
                ${admin_partials.formgroup__private_key_cycle(
                    field_name="private_key_cycle__backup",
                    default=RenewalConfiguration.private_key_cycle__backup,
                )}
                ${admin_partials.formgroup__key_technology(
                    field_name="private_key_technology__backup",
                    options=model_websafe.KeyTechnology._options_RenewalConfiguration_private_key_technology,
                    default=RenewalConfiguration.private_key_technology__backup,
                )}

                ${admin_partials.formgroup__domain_names(
                    specify_challenge=True,
                    domain_names_http01=RenewalConfiguration.domains_challenged_liststr("http-01"),
                    domain_names_dns01=RenewalConfiguration.domains_challenged_liststr("dns-01"),
                    AcmeDnsServer_GlobalDefault=AcmeDnsServer_GlobalDefault,
                    )}

                ${admin_partials.formgroup__note()}
                <hr/>

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

