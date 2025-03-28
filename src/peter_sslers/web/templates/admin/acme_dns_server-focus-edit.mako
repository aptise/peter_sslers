<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-dns-servers">acme-dns Servers</a></li>
        <li><a href="${admin_prefix}/acme-dns-server/${AcmeDnsServer.id}">Focus ${AcmeDnsServer.id}</a></li>
        <li class="active">Edit</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>acme-dns Server: Focus: Edit</h2>
    ${admin_partials.handle_querystring_result()}
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-dns-server/${AcmeDnsServer.id}/edit.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">


            <form
                action="${admin_prefix}/acme-dns-server/${AcmeDnsServer.id}/edit"
                method="POST"
                enctype="multipart/form-data"
                id="form-edit"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}

                <div class="form-group">
                    <label for="api_url">Api Url</label>
                    <input type="text" name="api_url" value="${AcmeDnsServer.api_url}" class="form-control"/>
                </div>
                <div class="form-group">
                    <label for="domain">Domain</label>
                    <input type="text" name="domain" value="${AcmeDnsServer.domain}" class="form-control"/>
                </div>

                <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>

            </form>




        </div>
    </div>
</%block>
