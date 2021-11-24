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
                        <th>Versions</th>
                        <td>
                            % if RootStore.root_store_versions:
                                <ul class="list list-unstyled">
                                    % for root_store_version in RootStore.root_store_versions:
                                        <li>
                                            <a class="label label-info"
                                               href="${admin_prefix}/root-store-version/${root_store_version.id}"
                                            >
                                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                RootStoreVersion-${root_store_version.id}&nbsp;
                                            </a>
                                            <code>${root_store_version.version_string}</code>
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
