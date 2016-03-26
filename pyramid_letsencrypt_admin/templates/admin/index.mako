<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="page_header">
    <h2>Admin Index</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-6">
            <h2>Records Archive</h2>
            <ul>
                <li>View Existing</li>
                <ul>
                    <li><a href="/.well-known/admin/domains">domains</a> (${request.text_library.info_Domains[0]})</li>
                    <li><a href="/.well-known/admin/certificates">certificates</a> (${request.text_library.info_Certificates[0]})</li>
                    <li><a href="/.well-known/admin/certificate_requests">certificate_requests</a> (${request.text_library.info_CertificateRequests[0]})</li>
                    <li><a href="/.well-known/admin/account_keys">account_keys</a> (${request.text_library.info_AccountKeys[0]})</li>
                    <li><a href="/.well-known/admin/private_keys">private_keys</a> (${request.text_library.info_PrivateKeys[0]})</li>
                </ul>
                <li>View Recordkeeping</li>
                <ul>
                    <li><a href="/.well-known/admin/ca_certificates">ca_certificates</a> (${request.text_library.info_CACertificates[0]})</li>
                </ul>
            </ul>

            <h2>Operations</h2>
            % if enable_redis:
                <p>
                    <a  href="/.well-known/admin/operations/redis"
                        class="btn btn-info"
                    >Redis Operations</a><br/>
                </p>
            % endif
            <p>
                <a  href="/.well-known/admin/operations/deactivate_expired"
                    class="btn btn-info"
                >Deactivate Expired Certificates</a><br/>
            </p>
            <p>
                <a  href="/.well-known/admin/operations/update_recents"
                    class="btn btn-info"
                >Update Recents</a><br/>
            </p>
            <p>
                <a  href="/.well-known/admin/operations/ca_certificate_probes"
                    class="btn btn-info"
                >Probe for CA Certificates</a><br/>
                <em>${request.text_library.info_CACertificateProbes[0]}</em>
            </p>

        </div>
        <div class="col-sm-6">
            <h2>Create New</h2>
            <p>
                <a  href="/.well-known/admin/certificate_request/new-flow"
                    class="btn btn-primary"
                >certificate request FLOW</a><br/>
                <em>${request.text_library.info_CertificateRequest_new_flow[0]}</em>
            </p>
            <p>
                <a  href="/.well-known/admin/certificate_request/new-full"
                    class="btn btn-primary"
                >certificate request FULL</a><br/>
                <em>${request.text_library.info_CertificateRequest_new_full[0]}</em>
            </p>

            <h2>Upload Existing</h2>
            <p>
                <a  href="/.well-known/admin/certificate/upload"
                    class="btn btn-primary"
                >Upload Existing Certificate</a><br/>
                <em>${request.text_library.info_UploadExistingCertificate[0]}</em>
            </p>
            <p>
                <a  href="/.well-known/admin/private_key/new"
                    class="btn btn-primary"
                >Upload Private Key</a><br/>
                <em>${request.text_library.info_UploadPrivateKey[0]}</em>
            </p>
            <p>
                <a  href="/.well-known/admin/account_key/new"
                    class="btn btn-primary"
                >Upload Account Key</a><br/>
                <em>${request.text_library.info_UploadAccountKey[0]}</em>
            </p>
            <p>
                <a  href="/.well-known/admin/ca_certificate/upload"
                    class="btn btn-primary"
                >Upload CA Certificate</a><br/>
                <em>${request.text_library.info_UploadCACertificate[0]}</em>
            </p>



        </div>
    </div>
</%block>
