<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/account-keys">Account Keys</a></li>
        <li class="active">New</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Account Key | Upload</h2>
    <p><em>${request.text_library.info_AccountKeys[1]}</em></p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-6">
            <form
                action="${admin_prefix}/account-key/upload"
                method="POST"
                enctype="multipart/form-data"
            >
                <% form = request.formhandling.get_form(request) %>
                ${form.html_error_main_fillable()|n}

                ${admin_partials.formgroup__account_key_file()}
                <hr/>

                <button type="submit" class="btn btn-default">Submit</button>
            </form>
        </div>
        <div class="col-sm-6">
            ${admin_partials.info_AccountKey()}
        </div>
    </div>
</%block>
