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
                    <li><a href="/.well-known/admin/domain_keys">domain_keys</a> (${request.text_library.info_DomainKeys[0]})</li>
                </ul>
                <li>View Recordkeeping</li>
                <ul>
                    <li><a href="/.well-known/admin/ca_certificates">ca_certificates</a> (${request.text_library.info_CACertificates[0]})</li>
                    <li><a href="/.well-known/admin/ca_certificate_probes">ca_certificate_probes</a> (${request.text_library.info_CACertificateProbes[0]})</li>
                </ul>
            </ul>
        </div>
        <div class="col-sm-6">
            <h2>Create New</h2>
            <p>
                <a  href="/.well-known/admin/certificate_request/new-flow"
                    class="btn btn-info"
                >certificate request FLOW</a><br/>
                <em>${request.text_library.info_CertificateRequest_new_flow[0]}</em>
            </p>
            <p>
                <a  href="/.well-known/admin/certificate_request/new-full"
                    class="btn btn-info"
                >certificate request FULL</a><br/>
                <em>${request.text_library.info_CertificateRequest_new_full[0]}</em>
            </p>

            <h2>Upload Existing</h2>
            <p>
                <a  href="/.well-known/admin/domain_key/new"
                    class="btn btn-info"
                >Upload Domain Private Key</a><br/>
                <em>${request.text_library.info_UploadDomainKey[0]}</em>
            </p>
            <p>
                <a  href="/.well-known/admin/certificate/upload"
                    class="btn btn-info"
                >Upload Existing Certificate</a><br/>
                <em>${request.text_library.info_UploadExistingCertificate[0]}</em>
            </p>



        </div>
    </div>
</%block>
