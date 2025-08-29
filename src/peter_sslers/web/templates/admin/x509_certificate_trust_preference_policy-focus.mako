<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/x509-certificate-trust-preference-policys">X509CertificateTrustPreferencePolicys</a></li>
        <li class="active">Focus ${X509CertificateTrustPreferencePolicy.id}-${X509CertificateTrustPreferencePolicy.name} </li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>X509CertificateTrustPreferencePolicy - Focus - ${X509CertificateTrustPreferencePolicy.id}-${X509CertificateTrustPreferencePolicy.name}</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/x509-certificate-trust-preference-policy/${X509CertificateTrustPreferencePolicy.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json</a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">

            <table class="table table-striped table-condensed">
                <tr>
                    <th>id</th>
                    <td>
                        <span class="label label-default">
                            ${X509CertificateTrustPreferencePolicy.id}
                        </span>
                    </td>
                </tr>
                <tr>
                    <th>name</th>
                    <td>
                        <span class="label label-default">
                            ${X509CertificateTrustPreferencePolicy.name}
                        </span>
                    </td>
                </tr>

                <tr>
                    <th>preferences</th>
                    <td>




            <ul class="list-styled">
                <%
                    idx_n = len(X509CertificateTrustPreferencePolicy.x509_certificate_trust_preference_policy_items) - 1
                %>
                % for idx, dbPreference in enumerate(X509CertificateTrustPreferencePolicy.x509_certificate_trust_preference_policy_items):
                    <li>
                        <form
                            action="${admin_prefix}/x509-certificate-trust-preference-policy/${X509CertificateTrustPreferencePolicy.id}/delete"
                            method="POST"
                            style="display:inline-block;"
                            id="form-preferred-delete-${dbPreference.slot_id}"
                        >
                            <input type="hidden" name="slot" value="${dbPreference.slot_id}" data-formencode-ignore="1"/>
                            <input type="hidden" name="fingerprint_sha1" value="${dbPreference.x509_certificate_trusted.fingerprint_sha1}" data-formencode-ignore="1"/>
                            <button class="btn btn-xs btn-danger" type="submit">
                                <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                Delete
                            </button>
                        </form>
                        <form
                            action="${admin_prefix}/x509-certificate-trust-preference-policy/${X509CertificateTrustPreferencePolicy.id}/prioritize"
                            method="POST"
                            style="display:inline-block;"
                            id="form-preferred-prioritize_increase-${dbPreference.slot_id}"
                        >
                            <input type="hidden" name="slot" value="${dbPreference.slot_id}" data-formencode-ignore="1"/>
                            <input type="hidden" name="fingerprint_sha1" value="${dbPreference.x509_certificate_trusted.fingerprint_sha1}" data-formencode-ignore="1"/>
                            <input type="hidden" name="priority" value="increase" data-formencode-ignore="1"/>
                            <button class="btn btn-xs btn-primary ${"disabled" if idx == 0 else ""}" type="submit">
                                <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
                                Move Up
                            </button>
                        </form>
                        <form
                            action="${admin_prefix}/x509-certificate-trust-preference-policy/${X509CertificateTrustPreferencePolicy.id}/prioritize"
                            method="POST"
                            style="display:inline-block;"
                            id="form-preferred-prioritize_decrease-${dbPreference.slot_id}"
                        >
                            <input type="hidden" name="slot" value="${dbPreference.slot_id}" data-formencode-ignore="1"/>
                            <input type="hidden" name="fingerprint_sha1" value="${dbPreference.x509_certificate_trusted.fingerprint_sha1}" data-formencode-ignore="1"/>
                            <input type="hidden" name="priority" value="decrease" data-formencode-ignore="1"/>
                            <button class="btn btn-xs btn-primary ${"disabled" if idx == idx_n else ""}" type="submit">
                                <span class="glyphicon glyphicon-download" aria-hidden="true"></span>
                                Move Down
                            </button>
                        </form>
                        <span class="label label-default">${dbPreference.slot_id}</span>
                        ${dbPreference.x509_certificate_trusted.button_view|n}
                    </li>
                % endfor
            </ul>
            
            <h3>Add an Item</h3>
            <p>Add a X509CertificateTrusted to the preference list by entering the fingerprint_sha1.</p>
            <p>You may enter the initial few characters of the fingerprint_sha1.</p>
            <p>Items will be added to the end of the list.</p>
            <form
                action="${admin_prefix}/x509-certificate-trust-preference-policy/${X509CertificateTrustPreferencePolicy.id}/add"
                method="POST"
                id="form-preferred-add"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}
                <input type="text" name="fingerprint_sha1"/>
                <button class="btn btn-xs btn-primary" type="submit">
                    <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                    Add
                </button>
            </form>
            







                    </td>
                </tr>
            </table>
        </div>
    </div>
</%block>
