<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificate-requests">Certificate Requests</a></li>
        <li class="active">New</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Certificate Request - Acme Flow | New</h2>
    <p><em>${request.text_library.info_CertificateRequest_new_AcmeFlow[1]}</em></p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <form action="${admin_prefix}/certificate-request/new-acme-flow" method="POST">
                <% form = request.formhandling.get_form(request) %>
                ${form.html_error_main('Error_Main')|n}

                <div class="form-group">
                    <label for="f1-domain_names">Domain Names</label>
                    <textarea class="form-control" rows="3" name="domain_names" id="f1-domain_names"></textarea>
                    <p class="help-block">enter domain_names above, separated by commas. <b>This should be EXACTLY what you typed in the letsencrypt client.</p>
                </div>

                <button type="submit" class="btn btn-default">Submit</button>
            </form>
        </div>
    </div>
</%block>
