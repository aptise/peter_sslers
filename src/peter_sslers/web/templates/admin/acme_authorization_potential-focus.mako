<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-authz-potentials">ACME Authorization Potentials</a></li>
        <li class="active">ACME Authorization Potential - ${AcmeAuthorizationPotential.id}</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>ACME Authorization Potential - ${AcmeAuthorizationPotential.id}</h2>
</%block>


<%block name="page_header_nav">
    <ul class="nav nav-pills nav-stacked">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-authz-potential/${AcmeAuthorizationPotential.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    ${admin_partials.handle_querystring_result()}
    
    <div class="row">
        <div class="col-sm-12">
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
                                ${AcmeAuthorizationPotential.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>timestamp_created</th>
                        <td><timestamp>${AcmeAuthorizationPotential.timestamp_created or ''}</timestamp>
                        </td>
                    </tr>
                    <tr>
                        <th>domain</th>
                        <td>
                            <a class="label label-info" href="${admin_prefix}/domain/${AcmeAuthorizationPotential.domain_id}">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            Domain-${AcmeAuthorizationPotential.domain_id}</a>
                            <code>${AcmeAuthorizationPotential.domain.domain_name}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeOrder</th>
                        <td>
                            <em>An AcmeAuthorization may be associated with more than one AcmeOrder.</em>
                            <a class="label label-info" href="${admin_prefix}/acme-order/${AcmeAuthorizationPotential.acme_order_id}">
                            <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                            AcmeOrder-${AcmeAuthorizationPotential.acme_order_id}</a>
                        </td>
                    </tr>
                    <tr>
                        <th>AcmeOrder</th>
                        <td>
                            <form method="POST"
                                action="${admin_prefix}/acme-authz-potential/${AcmeAuthorizationPotential.id}/delete"
                                id="form-acme_authz_potential-delete"
                            >
                                <button class="btn btn-xs btn-danger" id="btn-acme_authz_potential-sync">
                                    <span class="glyphicon glyphicon-trash" aria-hidden="true"></span>
                                    Delete
                                </button>
                            </form>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</%block>


