<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">CertificateCAPreferencePolicys</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>CertificateCAPreferencePolicys</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/certificate-ca-preference-policys.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json</a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if CertificateCAPreferencePolicys:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped table-condensed">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>name</th>
                        </tr>
                    </thead>
                    % for cap in CertificateCAPreferencePolicys:
                        <tr>
                            <td><a class="label label-info" href="${admin_prefix}/certificate-ca-preference-policy/${cap.id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                CertificateCAPreferencePolicy-${cap.id}</a>
                            </td>
                            <td><code>${cap.name}</code></td>
                        </tr>
                    % endfor
                </table>
            % else:
                <em>
                    No CertificateCAPreferencePolicys
                </em>
            % endif
        </div>
    </div>
</%block>
