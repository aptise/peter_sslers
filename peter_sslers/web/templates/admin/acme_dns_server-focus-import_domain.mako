<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-dns-servers">acme-dns Servers</a></li>
        <li><a href="${admin_prefix}/acme-dns-server/${AcmeDnsServer.id}">Focus ${AcmeDnsServer.id}</a></li>
        <li class="active">Import Domain</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>acme-dns Server: Focus: Import Domain</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-dns-server/${AcmeDnsServer.id}/import-domain.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <h3>Import Domain</h3>
            <p>
                Use this form if you plan on provisioning a certificate with `DNS-01`
                authentication against this `acme-dns` server.
            </p>
            <p>
                You can enter exisiting acme-dns credentials here.
            </p>

            <form
                action="${admin_prefix}/acme-dns-server/${AcmeDnsServer.id}/import-domain"
                method="POST"
                enctype="multipart/form-data"
                id="form-acme_dns_server-import_domain"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}

                <div class="form-group">
                    <label for="domain_name">Domain name</label>
                    <input class="form-control" name="domain_name" id="domain_name" type="text"/>
                </div>
                
                <hr/>
                
                <p>acme-dns credentials</p>

                <div class="form-group">
                    <label for="username">username</label>
                    <input class="form-control" name="username" id="username" type="text"/>
                </div>

                <div class="form-group">
                    <label for="password">password</label>
                    <input class="form-control" name="password" id="password" type="text"/>
                </div>

                <div class="form-group">
                    <label for="fulldomain">fulldomain</label>
                    <input class="form-control" name="fulldomain" id="fulldomain" type="text"/>
                </div>

                <div class="form-group">
                    <label for="subdomain">subdomain</label>
                    <input class="form-control" name="subdomain" id="subdomain" type="text"/>
                </div>

                <div class="form-group">
                    <label for="allowfrom">allowfrom</label>
                    <input class="form-control" name="allowfrom" id="allowfrom" type="text"/>
                </div>

                <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>

            </form>


        </div>
    </div>
</%block>
