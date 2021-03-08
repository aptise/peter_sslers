<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/root-stores">Root Stores</a></li>
        <li class="active">Focus</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Root Store: Focus</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/root-store/${RootStore.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            ${admin_partials.handle_querystring_result()}
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
                                ${RootStore.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>name</th>
                        <td>
                            <code>${RootStore.name}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>version</th>
                        <td>
                            <code>${RootStore.version_string}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>CertificateCAs</th>
                        <td>
                            % if RootStore.to_certificate_cas:
                                <ul class="list list-unstyled">
                                    % for to_certificate_ca in RootStore.to_certificate_cas:
                                        <li>
                                            ${to_certificate_ca.certificate_ca.button_view|n}
                                        </li>
                                    % endfor
                                </ul>
                            % endif
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</%block>
