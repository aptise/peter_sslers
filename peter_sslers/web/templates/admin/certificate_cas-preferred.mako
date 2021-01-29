<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificate-cas">CertificateCAs</a></li>
        <li class="active">Preferred</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>CertificateCAs - Preferred</h2>
    <p>
        This allows you to set one or more preferred CertificateCAs.
        The PreferredCA will be used for defaults, in order of appearance.
    </p>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/certificate-cas/preferred.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-list-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">

            <ul class="list-styled">
                % for idx, dbPreference in enumerate(CertificateCAPreferences):
                    <li>
                        <form
                            action="${admin_prefix}/certificate-cas/preferred/delete"
                            method="POST"
                            style="display:inline-block;"
                            id="form-preferred-delete-${dbPreference.id}"
                        >
                            <input type="hidden" name="slot" value="${dbPreference.id}" data-formencode-ignore="1"/>
                            <input type="hidden" name="fingerprint_sha1" value="${dbPreference.certificate_ca.fingerprint_sha1}" data-formencode-ignore="1"/>
                            <button class="btn btn-xs btn-danger" type="submit">
                                <span class="glyphicon glyphicon-remove" aria-hidden="true"></span>
                                Delete
                            </button>
                        </form>
                        <form
                            action="${admin_prefix}/certificate-cas/preferred/prioritize"
                            method="POST"
                            style="display:inline-block;"
                            id="form-preferred-prioritize_increase-${dbPreference.id}"
                        >
                            <input type="hidden" name="slot" value="${dbPreference.id}" data-formencode-ignore="1"/>
                            <input type="hidden" name="fingerprint_sha1" value="${dbPreference.certificate_ca.fingerprint_sha1}" data-formencode-ignore="1"/>
                            <input type="hidden" name="priority" value="increase" data-formencode-ignore="1"/>
                            <button class="btn btn-xs btn-primary" type="submit">
                                <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
                                Move Up
                            </button>
                        </form>
                        <form
                            action="${admin_prefix}/certificate-cas/preferred/prioritize"
                            method="POST"
                            style="display:inline-block;"
                            id="form-preferred-prioritize_decrease-${dbPreference.id}"
                        >
                            <input type="hidden" name="slot" value="${dbPreference.id}" data-formencode-ignore="1"/>
                            <input type="hidden" name="fingerprint_sha1" value="${dbPreference.certificate_ca.fingerprint_sha1}" data-formencode-ignore="1"/>
                            <input type="hidden" name="priority" value="decrease" data-formencode-ignore="1"/>
                            <button class="btn btn-xs btn-primary" type="submit">
                                <span class="glyphicon glyphicon-download" aria-hidden="true"></span>
                                Move Down
                            </button>
                        </form>
                        <span class="label label-default">${dbPreference.id}</span>
                        ${dbPreference.certificate_ca.button_view(request)|n}
                    </li>
                % endfor
            </ul>
            
            <h3>Add an Item</h3>
            <p>Add a CertificateCA to the preference list by entering the fingerprint_sha1.</p>
            <p>You may enter the initial few characters of the fingerprint_sha1.</p>
            <p>Items will be added to the end of the list.</p>
            <form
                action="${admin_prefix}/certificate-cas/preferred/add"
                method="POST"
                id="form-preferred-add"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}
                <input type="text" name="fingerprint_sha1"/>
                <button class="btn btn-xs btn-info" type="submit">
                    <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
                    Add
                </button>
            </form>
            
        </div>
    </div>
</%block>
