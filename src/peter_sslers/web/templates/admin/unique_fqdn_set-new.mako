<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/unique-fqdn-sets">Unique FQDN Sets</a></li>
        <li class="active">New</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Unique FQDN Set: New</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/unique-fqdn-set/new.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-pencil" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            ${admin_partials.handle_querystring_result()}
            <p>
                Create A NEW UniqueFQDNSet.
            </p>
            <table class="table table-striped table-condensed">
                <tbody>
                    <tr>
                        <th>Details</th>
                        <td>
                            <form
                                action="${admin_prefix}/unique-fqdn-set/new"
                                method="POST"
                                enctype="multipart/form-data"
                                id="form-unique_fqdn_set-new"
                            >
                                <% form = request.pyramid_formencode_classic.get_form() %>
                                ${form.html_error_main_fillable()|n}

                                <div class="form-group">
                                    <label for="domain_names">Domains</label>
                                    <em>A comma separated list of domain names for the UniqueFQDNSet. </em>
                                    <textarea name="domain_names" class="form-control"></textarea>
                                </div>

                                <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>
                            </form>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</%block>
