<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-orders/all">AcmeOrders</a></li>
        <li class="active">New</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>AcmeOrder | New</h2>
    <div class="alert alert-info">
        <em>
            Requests will be performed against the Certificate Authority associated with the Account Key
        </em>
    </div>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-order/new/freeform.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">

    <div class="row">
        <div class="col-sm-6">

            <form
                action="${admin_prefix}/acme-order/new/freeform"
                method="POST"
                enctype="multipart/form-data"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}

                <h3>Primary Certificate</h3>
                ${admin_partials.formgroup__AcmeAccount_selector__advanced(
                    support_upload=False,
                    support_profiles=True,
                    default_profile=EnrollmentPolicy_global.acme_profile__primary,
                    dbEnrollmentPolicy=EnrollmentPolicy_global,
                )}
                <hr/>
                <h4>PrivateKey</h4>
                
                ${admin_partials.formgroup__private_key_cycle(
                    field_name="private_key_cycle__primary",
                    default=EnrollmentPolicy_global.private_key_cycle__primary,
                )}
                ${admin_partials.formgroup__PrivateKey_selector__advanced(
                    support_upload=False,
                    option_account_default=True,
                    option_generate_new=True,
                    default="account_default",
                    concept="primary",
                    )}
                <hr/>
                <hr/>

                <h3>Backup Certificate</h3>
                ${admin_partials.formgroup__AcmeAccount_selector__backup(
                    support_profiles=True,
                    default_profile=EnrollmentPolicy_global.acme_profile__backup,
                    dbEnrollmentPolicy=EnrollmentPolicy_global,
                )}
                <hr/>
                <h4>PrivateKey</h4>
                ${admin_partials.formgroup__private_key_cycle(
                    field_name="private_key_cycle__backup",
                    label="[Backup Certificate]",
                    default=EnrollmentPolicy_global.private_key_cycle__backup,
                )}
                ${admin_partials.formgroup__key_technology(
                    field_name="private_key_technology__backup",
                    label="[Backup Certificate]",
                    default=EnrollmentPolicy_global.private_key_technology__backup,
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
                <hr/>
                ${admin_partials.formgroup__note()}
                ${admin_partials.formgroup__processing_strategy()}
                <hr/>

                <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>
            </form>
        </div>
        <div class="col-sm-6">
            <p>This route supports JSON and is self-documenting on GET requests.</p>
            ${admin_partials.info_AcmeAccount()}
            ${admin_partials.info_PrivateKey()}
        </div>
    </div>
</%block>
