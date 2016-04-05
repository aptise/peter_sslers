<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="page_header">
    <h2>Admin Index</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-6">
            <h2>Records Archive</h2>
            
            <h4>Core Objects</h4>
            <ul>
                <li><a class="label label-info" href="/.well-known/admin/domains">
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    domains</a> (${request.text_library.info_Domains[0]})</li>
                <li><a class="label label-info" href="/.well-known/admin/certificates">
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    certificates</a> (${request.text_library.info_Certificates[0]})</li>
                <li><a class="label label-info" href="/.well-known/admin/certificate-requests">
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    certificate_requests</a> (${request.text_library.info_CertificateRequests[0]})</li>
                <li><a class="label label-info" href="/.well-known/admin/private-keys">
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                private_keys</a> (${request.text_library.info_PrivateKeys[0]})</li>
            </ul>


            <h4>Recordkeeping</h4>
            <ul>
                <li><a class="label label-info" href="/.well-known/admin/unique-fqdn-sets">
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    unique_fqdn_sets</a> (${request.text_library.info_UniqueFQDNs[0]})</li>
                <li><a class="label label-info" href="/.well-known/admin/account-keys">
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    account_keys</a> (${request.text_library.info_AccountKeys[0]})</li>
                <li><a class="label label-info" href="/.well-known/admin/ca-certificates">
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    ca_certificates</a> (${request.text_library.info_CACertificates[0]})</li>
                <li><a class="label label-info" href="/.well-known/admin/renewal-queue">
                    <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
                    renewal_queue</a></li>
            </ul>

            <h2>Operations</h2>
            ${admin_partials.operations_options(enable_redis=enable_redis,
                                                enable_nginx=enable_nginx,
                                                as_list=True,
                                                )}

        </div>
        <div class="col-sm-6">
            <p>
                <a  href="/.well-known/admin/help"
                    class="btn btn-warning"
                >
                    <span class="glyphicon glyphicon-info-sign" aria-hidden="true"></span>
                    Help</a><br/>
            </p>

            <h2>Create New</h2>
            <p>
                <a  href="/.well-known/admin/certificate-request/new-flow"
                    class="btn btn-xs btn-primary"
                >
                <span class="glyphicon glyphicon-wrench" aria-hidden="true"></span>
                certificate request FLOW</a><br/>
                <em>${request.text_library.info_CertificateRequest_new_flow[0]}</em>
            </p>
            <p>
                <a  href="/.well-known/admin/certificate-request/new-full"
                    class="btn btn-xs btn-primary"
                >
                <span class="glyphicon glyphicon-wrench" aria-hidden="true"></span>
                certificate request FULL</a><br/>
                <em>${request.text_library.info_CertificateRequest_new_full[0]}</em>
            </p>

            <h2>Upload Existing</h2>
            <p>
                <a  href="/.well-known/admin/certificate/upload"
                    class="btn btn-xs btn-primary"
                >
                <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
                Upload Existing Certificate</a><br/>
                <em>${request.text_library.info_UploadExistingCertificate[0]}</em>
            </p>
            <p>
                <a  href="/.well-known/admin/private-key/new"
                    class="btn btn-xs btn-primary"
                >
                <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
                Upload Private Key</a><br/>
                <em>${request.text_library.info_UploadPrivateKey[0]}</em>
            </p>
            <p>
                <a  href="/.well-known/admin/account-key/new"
                    class="btn btn-xs btn-primary"
                >
                <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
                Upload Account Key</a><br/>
                <em>${request.text_library.info_UploadAccountKey[0]}</em>
            </p>
            <p>
                <a  href="/.well-known/admin/ca-certificate/upload"
                    class="btn btn-xs btn-primary"
                >
                <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
                Upload CA Certificate</a><br/>
                <em>${request.text_library.info_UploadCACertificate[0]}</em>
            </p>



        </div>
    </div>
</%block>
