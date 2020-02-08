<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">CA Certificates</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>CA Certificates</h2>
    <p>${request.text_library.info_CACertificates[1]}</p>
    <p>
        CaCertificates can be initialized and updated by probing the LetsEncrypt service;
        see <a class="btn btn-xs btn-warning" href="${admin_prefix}/api">Api Endpoints</a>.
    
    </p>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a  href="${admin_prefix}/ca-certificate/upload"
            title="${request.text_library.info_UploadCACertificate[0]}"
            class="btn btn-xs btn-primary"
        >
        <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
        Upload: CA Certificate</a>
        <a href="${admin_prefix}/ca-certificates.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if CaCertificates:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>count active certificates (signed)</th>
                            <th>name</th>
                            <th>timestamp_first_seen</th>
                            <th>cert_pem_md5</th>
                        </tr>
                    </thead>
                    % for cert in CaCertificates:
                        <tr>
                            <td><a class="label label-info" href="${admin_prefix}/ca-certificate/${cert.id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                cacert-${cert.id}</a></td>
                            <td><span class="badge">${cert.count_active_certificates or ''}</span></td>
                            <td>${cert.name or ''}</td>
                            <td><timestamp>${cert.timestamp_first_seen}</timestamp></td>
                            <td><code>${cert.cert_pem_md5}</code></td>
                        </tr>
                    % endfor
                </table>
            % else:
                <em>
                    No Certificate Authority Certificates
                </em>
            % endif
        </div>
    </div>
</%block>
