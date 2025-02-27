<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">API: Domain: Autocert</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>API: Domain: Autocert</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/api/domain/autocert.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <p>
                The `autocert` endpoint allows `nginx` to automatically provision a certificate as needed.
            </p>
            <p>
                The endpoint ONLY responds to json requests.  <code>GET</code> will document, <code>POST</code> will submit.
            </p>


            % if not EnrollmentPolicy_autocert.is_configured:
                <div class="alert alert-danger">
                    <p>There `autocert` Enrollment Policy is NOT configured.</p>
                </div>
            % endif

            <table class="table table-striped table-condensed">
                <thead>
                    <tr>
                        <th>EnrollmentPolicy</th>
                        <th>Link</th>
                        <th>Configured?</th>
                    <tr>
                </thead>
                <tbody>
                    <tr>
                        <th>Autocert</th>
                        <td>
                            <a href="${admin_prefix}/enrollment-policy/${EnrollmentPolicy_autocert.slug}" class="label label-info">
                                EnrollmentPolicy-${EnrollmentPolicy_autocert.slug}
                            </a>
                        </td>
                        <td>
                            % if EnrollmentPolicy_autocert.is_configured:
                                <span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span>
                            % else:
                                <span class="label label-danger"><span class="glyphicon glyphicon-remove" aria-hidden="true"></span></span>
                            % endif
                        </td>
                    </tr>
                </tbody>
            </table>

        </div>
    </div>
</%block>
