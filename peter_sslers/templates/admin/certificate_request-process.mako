<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li><a href="/.well-known/admin/certificate-requests">Certificate Requests</a></li>
        <li><a href="/.well-known/admin/certificate-request/${LetsencryptCertificateRequest.id}">Focus [${LetsencryptCertificateRequest.id}]</a></li>
        <li class="active">Process</li>
    </ol>
</%block>

<%block name="page_header">
    <h2>Certificate Request - Process</h2>
</%block>
    
<%block name="content_main">

    <p>Workspace for 
        <a  class="label label-default"
            href="/.well-known/admin/certificate-request/${LetsencryptCertificateRequest.id}"
        >Certificate ${LetsencryptCertificateRequest.id} | ${LetsencryptCertificateRequest.timestamp_started}</a>
        <span class="label label-info">${LetsencryptCertificateRequest.certificate_request_type}</span>
    </p>

    <p>The `process` tool lets you enter the challenge info for a certification request.</p>
    
    <p>The <code>key</code> is the name of the file letsencrypt expects at a url.
        The <code>value</code> are the files contents.
    </p>

    <p>If letsencrypt says the url should be <code>example.com/acme-challenge/foo-bar-biz</code> , then the key is <code>foo-bar-biz</code></p>
    
    <% request_inactive = True if not LetsencryptCertificateRequest.is_active else False %>
    
    <p>This certificate request is <span class="label label-${'warning' if request_inactive else 'success'}">${"inactive" if request_inactive else "Active"}</span>.</p>
    
    <div class="row">
        <div class="col-sm-6">
            <h5>Domains in Certificate Request</h5>
            ${admin_partials.table_LetsencryptCertificateRequest2LetsencryptDomain(LetsencryptCertificateRequest.certificate_request_to_domains,
                                                                                 request_inactive = request_inactive,
                                                                                 active_domain_id = (LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_domain_id if LetsencryptCertificateRequest2LetsencryptDomain else None),
                                                                                 perspective='certificate_request_sidebar')}

        </div>
        <div class="col-sm-6">
            <h5>Domain Challenge Workspace</h5>
            % if LetsencryptCertificateRequest2LetsencryptDomain is None:
                Select a domain to the left for details.
            % else:
                <p>
                    Domain: <code>${LetsencryptCertificateRequest2LetsencryptDomain.domain.domain_name}</code>
                </p>
                <em>if this has not been verified and the request is still active, you can still change the params</em>
                
                <% 
                    form = None 
                    updates_allowed = True
                    if LetsencryptCertificateRequest2LetsencryptDomain.timestamp_verified:
                        updates_allowed = False
                    if request_inactive:
                        updates_allowed = False
                %>
                % if updates_allowed:
                    <form action="/.well-known/admin/certificate-request/${LetsencryptCertificateRequest.id}/process/domain/${LetsencryptCertificateRequest2LetsencryptDomain.letsencrypt_domain_id}" method="POST">
                        <% form = request.formhandling.get_form(request) %>
                        ${form.html_error_main('Error_Main')|n}
                % endif

                <table class="table table-striped">
                    <tr>
                        <th>timestamp_verified</th>
                        <td>${LetsencryptCertificateRequest2LetsencryptDomain.timestamp_verified or ''}</td>
                    </tr>
                    <tr>
                        <th>ip_verified</th>
                        <td>${LetsencryptCertificateRequest2LetsencryptDomain.ip_verified or ''}</td>
                    </tr>
                    % if updates_allowed:
                        <tr>
                            <th>challenge_key</th>
                            <td><input type="text" class="form-control" name="challenge_key"  value="${LetsencryptCertificateRequest2LetsencryptDomain.challenge_key or ''}"/></td>
                        </tr>
                        <tr>
                            <th>challenge_text</th>
                            <td><input type="text" class="form-control" name="challenge_text"  value="${LetsencryptCertificateRequest2LetsencryptDomain.challenge_text or ''}"/></td>
                        </tr>
                    % else:
                        <tr>
                            <th>challenge_key</th>
                            <td><code>${LetsencryptCertificateRequest2LetsencryptDomain.challenge_key}</code></td>
                        </tr>
                        <tr>
                            <th>challenge_text</th>
                            <td><code>${LetsencryptCertificateRequest2LetsencryptDomain.challenge_text}</code></td>
                        </tr>
                    % endif

                    % if updates_allowed:
                        </table>
                        <br/>
                            <button type="submit" class="btn btn-default">Submit</button>
                        </form>
                    % endif


                </table>
            % endif
        </div>
    </div>


</%block>
