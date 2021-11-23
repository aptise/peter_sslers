<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/unique-fqdn-sets">Unique FQDN Sets</a></li>
        <li><a href="${admin_prefix}/unique-fqdn-set/${UniqueFQDNSet.id}">Focus: ${UniqueFQDNSet.id}</a></li>
        <li class="active">Modify</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Unique FQDN Set: Focus ${UniqueFQDNSet.id}: Modify</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/unique-fqdn-set/${UniqueFQDNSet.id}/modify.json" class="btn btn-xs btn-info">
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
                Modifying will create A NEW UniqueFQDNSet.
            </p>
            <table class="table table-striped table-condensed">
                <thead>
                    <tr>
                        <th colspan="2">
                            Core Details
                        </th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <th>id</th>
                        <td>
                            <span class="label label-default">
                                ${UniqueFQDNSet.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>domain_ids_string</th>
                        <td>
                            <code>
                                ${UniqueFQDNSet.domain_ids_string}
                            </code>
                        </td>
                    </tr>
                    <tr>
                        <th>count_domains</th>
                        <td>
                            <code>
                                ${UniqueFQDNSet.count_domains}
                            </code>
                        </td>
                    </tr>
                    <tr>
                        <th>domains</th>
                        <td>
                            <table class="table table-striped table-condensed">
                                % for to_domain in UniqueFQDNSet.to_domains:
                                    <tr>
                                        <td>
                                            <a  class="label label-info"
                                                href="${admin_prefix}/domain/${to_domain.domain.id}"
                                            >
                                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                Domain-${to_domain.domain.id}
                                            </a>
                                        </td>
                                        <td>
                                            <span class="label label-${'success' if to_domain.domain.is_active else 'warning'}">
                                                ${'Active' if to_domain.domain.is_active else 'inactive'}
                                            </span>
                                        </td>
                                        <td><code>${to_domain.domain.domain_name}</code></td>
                                    </tr>
                                % endfor
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <th>Modifications</th>
                        <td>
                            <form
                                action="${admin_prefix}/unique-fqdn-set/${UniqueFQDNSet.id}/modify"
                                method="POST"
                                enctype="multipart/form-data"
                                id="form-unique_fqdn_set-modify"
                            >
                                <% form = request.pyramid_formencode_classic.get_form() %>
                                ${form.html_error_main_fillable()|n}

                                <div class="form-group">
                                    <label for="domain_names_add">Domains: Add</label>
                                    <em>A comma separated list of domain names to add to this FQDN Set. </em>
                                    <textarea name="domain_names_add" class="form-control"></textarea>
                                </div>
                                <div class="form-group">
                                    <label for="domain_names_del">Domains: Delete</label>
                                    <em>A comma separated list of domain names to remove from this FQDN Set. </em>
                                    <textarea name="domain_names_del" class="form-control"></textarea>
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
