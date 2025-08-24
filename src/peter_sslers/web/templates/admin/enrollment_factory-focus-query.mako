<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/enrollment-factorys">EnrollmentFactorys</a></li>
        <li><a href="${admin_prefix}/enrollment-factory/${EnrollmentFactory.id}">Focus [${EnrollmentFactory.id}-`${EnrollmentFactory.name}`]</a></li>
        <li class="active">Query</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>EnrollmentFactory - Focus - [${EnrollmentFactory.id}-`${EnrollmentFactory.name}`] - Query</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/enrollment-factory/${EnrollmentFactory.id}/query.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-search" aria-hidden="true"></span>
            Query.json
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
                        <th colspan="2">Query</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td colspan="2">
                            <form
                                method="POST"
                                action="${admin_prefix}/enrollment-factory/${EnrollmentFactory.id}/query"
                                id="form-enrollment_factory-query"
                            >
                                ${admin_partials.formgroup__domain_name(domain_name or "")}
                                <button class="btn btn-xs btn-primary" type="submit"  name="submit" value="submit">
                                    <span class="glyphicon glyphicon-seach" aria-hidden="true"></span>
                                    Search
                                </button>
                            </form>
                        </td>
                    </tr>
                </tbody>
                % if domain_name:
                    <thead>
                        <tr>
                            <th colspan="2">Results</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <th>RenewalConfiguration</th>
                            <td>
                                % if RenewalConfiguration:
                                    <a href="${admin_prefix}/renewal-configuration/${RenewalConfiguration.id}" class="label label-info">
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        RenewalConfiguration-${RenewalConfiguration.id}
                                    </a>

                                % else:
                                    Not Found
                                % endif
                            </td>
                        </tr>
                        <tr>
                            <th>X509Certificates</th>
                            <td>
                                % if X509Certificates:
                                    ${admin_partials.table_X509Certificates(X509Certificates, perspective='EnrollmentFactory')}
                                    <i>Only showing the 5 most recent.</i>
                                % else:
                                    Not Found
                                % endif
                            </td>
                        </tr>
                    </tbody>
                % endif
            </table>
        </div>
    </div>
</%block>
