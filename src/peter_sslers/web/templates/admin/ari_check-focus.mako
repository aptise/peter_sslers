<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/ari-checks">AriChecks</a></li>
        <li class="active">Focus [${AriCheck.id}]</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>AriCheck - Focus</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/ari-check/${AriCheck.id}.json" class="btn btn-xs btn-info">
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
                                ${AriCheck.id}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>X509Certificate</th>
                        <td>
                            % if AriCheck.x509_certificate_id:
                                <a  class="label label-info"
                                    href="${admin_prefix}/x509-certificate/${AriCheck.x509_certificate_id}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    X509Certificate-${AriCheck.x509_certificate_id}
                                </a>
                            % endif
                        </td>
                    </tr>
                    <tr>
                        <th>timestamp_created</th>
                        <td>
                            <code>${AriCheck.timestamp_created}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>ari_check_status</th>
                        <td>
                            <code>${AriCheck.ari_check_status}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>suggested_window_start</th>
                        <td>
                            <code>${AriCheck.suggested_window_start or ""}</code>
                        </td>
                    </tr>
                    <tr>
                        <th>suggested_window_end</th>
                        <td>
                            <code>${AriCheck.suggested_window_end or ""}</code>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</%block>
