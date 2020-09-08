<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-dns-servers">acme-dns Servers</a></li>
        <li><a href="${admin_prefix}/acme-dns-server/${AcmeDnsServer.id}">Focus ${AcmeDnsServer.id}</a></li>
        <li class="active">Ensure Domains</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>acme-dns Server: Focus: Ensure Domains</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-dns-server/${AcmeDnsServer.id}/ensure-domains.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
        
            <h3>Ensure Domains</h3>
        
            <p>
                Use this form if you plan on provisioning a certificate with `DNS-01` authentication against this `acme-dns` server.
            </p>
            
            <p>If a domain is unknown to this `acme-dns` server, it will be enrolled. If a domain is known to this `acme-dns` server, it will be reused.</p>
            
            <p>After submission, you will receive a payload of the `acme-dns` entries the domains root dns should delegate `_acme-challenge` records onto.</p>
            

            <form
                action="${admin_prefix}/acme-dns-server/${AcmeDnsServer.id}/ensure-domains"
                method="POST"
                enctype="multipart/form-data"
                id="form-acme_dns_server-ensure_domains"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}

                <div class="form-group">
                    <label for="domain_names">Domains</label>
                    <em>A comma separated list of domain names to enroll with this server. </em>
                    <textarea name="domain_names" class="form-control"/></textarea>
                </div>

                <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>

            </form>


        </div>
    </div>
</%block>
