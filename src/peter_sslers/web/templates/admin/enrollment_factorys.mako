<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">EnrollmentFactorys</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>EnrollmentFactorys</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/enrollment-factorys.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
        <a href="${admin_prefix}/enrollment-factorys/new" class="btn btn-xs btn-primary">
            <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
            New EnrollmentFactory
        </a>
    </p>
</%block>

<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if EnrollmentFactorys:
                ${admin_partials.table_EnrollmentFactorys(EnrollmentFactorys, perspective="EnrollmentFactorys")}
            % else:
                <em>
                    No EnrollmentFactorys
                </em>
            % endif
        </div>
    </div>
</%block>
