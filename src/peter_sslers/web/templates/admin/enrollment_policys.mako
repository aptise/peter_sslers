<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Enrollment Policys</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Enrollment Policys</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/enrollment-policys.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>

<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if EnrollmentPolicys:
                ${admin_partials.table_EnrollmentPolicys(EnrollmentPolicys, perspective="EnrollmentPolicies")}
            % else:
                <em>
                    No EnrollmentPolicys
                </em>
            % endif
        </div>
    </div>
</%block>
