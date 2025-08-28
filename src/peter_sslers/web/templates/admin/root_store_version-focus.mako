<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/root-stores">Root Stores</a></li>
        <li><a href="${admin_prefix}/root-store/${RootStoreVersion.root_store.id}">Focus: ${RootStoreVersion.root_store.id}</a></li>
        <li class="">Root Store Versions</li>
        <li class="active">Focus</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Root Store Version: Focus</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/root-store-version/${RootStoreVersion.id}.json" class="btn btn-xs btn-info">
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
                                ${RootStoreVersion.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>Root Store</th>
                        <td>
                            <code>${RootStoreVersion.root_store.name}</code><br/>
                            <a class="label label-info"
                               href="${admin_prefix}/root-store/${RootStoreVersion.root_store.id}"
                            >
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                RootStore-${RootStoreVersion.root_store_id}
                            </a>
                        </td>
                    </tr>
                    <tr>
                        <th>version</th>
                        <td>
                            <code>${RootStoreVersion.version_string}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>X509CertificateTrusteds</th>
                        <td>
                            % if RootStoreVersion.to_x509_certificate_trusteds:
                                <ul class="list list-unstyled">
                                    % for to_x509_certificate_trusted in RootStoreVersion.to_x509_certificate_trusteds:
                                        <li>
                                            ${to_x509_certificate_trusted.x509_certificate_trusted.button_view|n}
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
