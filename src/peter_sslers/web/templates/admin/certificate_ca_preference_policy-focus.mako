<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificate-ca-preference-policys">CertificateCAPreferencePolicys</a></li>
        <li class="active">Focus ${CertificateCAPreferencePolicy.id}-${CertificateCAPreferencePolicy.name} </li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>CertificateCAPreferencePolicy - Focus - ${CertificateCAPreferencePolicy.id}-${CertificateCAPreferencePolicy.name}</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/certificate-ca-preference-policy/${CertificateCAPreferencePolicy.id}.json" class="btn btn-xs btn-info">
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
                            ${CertificateCAPreferencePolicy.id}
                        </span>
                    </td>
                </tr>
                <tr>
                    <th>name</th>
                    <td>
                        <span class="label label-default">
                            ${CertificateCAPreferencePolicy.name}
                        </span>
                    </td>
                </tr>

                <tr>
                    <th>preferences</th>
                    <td>




            <ul class="list-styled">
                <%
                    idx_n = len(CertificateCAPreferencePolicy.certificate_ca_preferences) - 1
                %>
                % for idx, dbPreference in enumerate(CertificateCAPreferencePolicy.certificate_ca_preferences):
                    <li>
                        <form
                            action="${admin_prefix}/certificate-ca-preference-policy/${CertificateCAPreferencePolicy.id}/delete"
                            method="POST"
                            style="display:inline-block;"
                            id="form-preferred-delete-${dbPreference.slot_id}"
                        >
                            <input type="hidden" name="slot" value="${dbPreference.slot_id}" data-formencode-ignore="1"/>
                            <input type="hidden" name="fingerprint_sha1" value="${dbPreference.certificate_ca.fingerprint_sha1}" data-formencode-ignore="1"/>
                            <button class="btn btn-xs btn-danger" type="submit">
                                <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                Delete
                            </button>
                        </form>
                        <form
                            action="${admin_prefix}/certificate-ca-preference-policy/${CertificateCAPreferencePolicy.id}/prioritize"
                            method="POST"
                            style="display:inline-block;"
                            id="form-preferred-prioritize_increase-${dbPreference.slot_id}"
                        >
                            <input type="hidden" name="slot" value="${dbPreference.slot_id}" data-formencode-ignore="1"/>
                            <input type="hidden" name="fingerprint_sha1" value="${dbPreference.certificate_ca.fingerprint_sha1}" data-formencode-ignore="1"/>
                            <input type="hidden" name="priority" value="increase" data-formencode-ignore="1"/>
                            <button class="btn btn-xs btn-primary ${"disabled" if idx == 0 else ""}" type="submit">
                                <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
                                Move Up
                            </button>
                        </form>
                        <form
                            action="${admin_prefix}/certificate-ca-preference-policy/${CertificateCAPreferencePolicy.id}/prioritize"
                            method="POST"
                            style="display:inline-block;"
                            id="form-preferred-prioritize_decrease-${dbPreference.slot_id}"
                        >
                            <input type="hidden" name="slot" value="${dbPreference.slot_id}" data-formencode-ignore="1"/>
                            <input type="hidden" name="fingerprint_sha1" value="${dbPreference.certificate_ca.fingerprint_sha1}" data-formencode-ignore="1"/>
                            <input type="hidden" name="priority" value="decrease" data-formencode-ignore="1"/>
                            <button class="btn btn-xs btn-primary ${"disabled" if idx == idx_n else ""}" type="submit">
                                <span class="glyphicon glyphicon-download" aria-hidden="true"></span>
                                Move Down
                            </button>
                        </form>
                        <span class="label label-default">${dbPreference.slot_id}</span>
                        ${dbPreference.certificate_ca.button_view|n}
                    </li>
                % endfor
            </ul>
            
            <h3>Add an Item</h3>
            <p>Add a CertificateCA to the preference list by entering the fingerprint_sha1.</p>
            <p>You may enter the initial few characters of the fingerprint_sha1.</p>
            <p>Items will be added to the end of the list.</p>
            <form
                action="${admin_prefix}/certificate-ca-preference-policy/${CertificateCAPreferencePolicy.id}/add"
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
