<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/domains">Domains</a></li>
        <li><a href="${admin_prefix}/domain/${Domain.id}">Focus [${Domain.id}-${Domain.domain_name}]</a></li>
        <li class="active">AcmeDnsServer: New</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Domain Focus - acme-dns Server: New</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">

            <form
                action="${admin_prefix}/domain/${Domain.id}/acme-dns-server/new"
                method="POST"
                enctype="multipart/form-data"
                id="form-acme_dns_server-new"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}

                <div class="form-group">
                    <label for="acme_dns_server_id">
                        acme-dns Server
                    </label>
                    <select class="form-control" id="acme_dns_server_id" name="acme_dns_server_id">
                        % for option in AcmeDnsServers:
                            % if option.is_active:
                                <option value="${option.id}" ${'selected' if option.is_global_default else ''}>${option.root_url} (${option.id})</option>
                            % endif
                        % endfor
                    </select>
                </div>

                <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>
            </form>

        </div>
    </div>
</%block>
