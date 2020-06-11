<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/domains">Domains</a></li>
        <li class="active">New</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Domain | New</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-6">

            ${admin_partials.handle_querystring_result()}
            
            <p>
                This form creates a Domain record. It does not queue the Domain for a Certificate.
            </p>

            <form
                action="${admin_prefix}/domain/new"
                method="POST"
                enctype="multipart/form-data"
                id="form-domain-new"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}

                <div class="form-group">
                    <label for="domain_name">Domain Name</label>
                    <input class="form-control" type="text" name="domain_name" value=""/>
                </div>

                <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>
            </form>
        </div>
        <div class="col-sm-6">
            <h3>This form is JSON capable</h3>

            <p>
                <code>curl ${request.api_host}${admin_prefix}/domain/new.json</code>
            </p>
        </div>
    </div>
</%block>
