<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/certificate-requests">Certificate Requests</a></li>
        <li><a href="${admin_prefix}/certificate-request/${CertificateRequest.id}">Focus [${CertificateRequest.id}]</a></li>
        <li class="active">ACME Flow Manage</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Certificate Request - ACME Flow Manage</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">

            <p>Workspace for
                <a  class="label label-default"
                    href="${admin_prefix}/certificate-request/${CertificateRequest.id}"
                >CertificateRequest-${CertificateRequest.id} | ${CertificateRequest.timestamp_started}</a>
                <span class="label label-info">${CertificateRequest.certificate_request_source}</span>
            </p>

            <p>The `process` tool lets you enter the challenge info for a certification request.</p>
            <p>
                <b>
                    This tool is a convenience wrapper for using another client to perform the challenge.  You can upload the certificate data onto the request later.
                </b>
            </p>

            <p>The <code>key</code> is the name of the file letsencrypt expects at a url.
                The <code>value</code> are the files contents.
            </p>

            <p>If letsencrypt says the url should be <code>example.com/acme-challenge/foo-bar-biz</code> , then the key is <code>foo-bar-biz</code></p>

            <% request_inactive = True if not CertificateRequest.is_active else False %>

            <p>This certificate request is <span class="label label-${'warning' if request_inactive else 'success'}">${"inactive" if request_inactive else "Active"}</span>.</p>

            <p>
                note: Visiting a `test` URL will direct you to the actual verification URL with "?test=1" appended.  This string instructs the server to not log the visit.  If the "?test=1" string is missing, the server will log the visit.  This is used to track the ACME server verification visits.
            </p>

        </div>
    </div>
    <div class="row">
        <div class="col-sm-6">
            <h5>Domains in Certificate Request</h5>
            ${admin_partials.table_CertificateRequest2Domain(CertificateRequest.unique_fqdn_set.to_domains,
                                                                request_inactive = request_inactive,
                                                                current_domain_id = (CertificateRequest2Domain.domain_id if CertificateRequest2Domain else None),
                                                                perspective='certificate_request_sidebar')}

        </div>
        <div class="col-sm-6">
            <h5>Domain Challenge Workspace</h5>
            % if CertificateRequest2Domain is None:
                Select a domain to the left for details.
            % else:
                <p>
                    Domain: <code>${CertificateRequest2Domain.domain.domain_name}</code>
                </p>
                <em>if this has not been verified and the request is still active, you can still change the params</em>

                <%
                    form = None
                    updates_allowed = True
                    if CertificateRequest2Domain.timestamp_verified:
                        updates_allowed = False
                    if request_inactive:
                        updates_allowed = False
                %>
                % if updates_allowed:
                    <form action="${admin_prefix}/certificate-request/${CertificateRequest.id}/acme-flow/manage/domain/${CertificateRequest2Domain.domain_id}" method="POST">
                        <% form = request.pyramid_formencode_classic.get_form() %>
                        ${form.html_error_main_fillable()|n}
                % endif

                <table class="table table-striped">
                    <tr>
                        <th>timestamp_verified</th>
                        <td>${CertificateRequest2Domain.timestamp_verified or ''}</td>
                    </tr>
                    <tr>
                        <th>ip_verified</th>
                        <td>${CertificateRequest2Domain.ip_verified or ''}</td>
                    </tr>
                    % if updates_allowed:
                        <tr>
                            <th>challenge_key</th>
                            <td><input type="text" class="form-control" name="challenge_key"  value="${CertificateRequest2Domain.challenge_key or ''}"/></td>
                        </tr>
                        <tr>
                            <th>challenge_text</th>
                            <td><input type="text" class="form-control" name="challenge_text"  value="${CertificateRequest2Domain.challenge_text or ''}"/></td>
                        </tr>
                    % else:
                        <tr>
                            <th>challenge_key</th>
                            <td><code>${CertificateRequest2Domain.challenge_key}</code></td>
                        </tr>
                        <tr>
                            <th>challenge_text</th>
                            <td><code>${CertificateRequest2Domain.challenge_text}</code></td>
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
