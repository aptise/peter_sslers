<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-orderlesss">AcmeOrderless</a></li>
        <li><a href="${admin_prefix}/acme-orderlesss/${AcmeOrderless.id}" class="active">Focus - ${AcmeOrderless.id}</a></li>
    </ol>
</%block>


<%block name="page_header_col">
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-orderless/${AcmeOrderless.id}.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <p>
                <b>
                    AcmeOderless is a convenience tool for configuring a server to respond to ACME Challenges form another client.
                </b>
            </p>
            <p>
                This AcmeOderless configuration is :
                    % if AcmeOrderless.is_processing:
                        <span class="label label-success">active</span>
                    % else:
                        <span class="label label-danger">deactivated</span>
                    % endif
                . If an AcmeOderless configuration is deactivated, it can not be edited or reactivated.
            </p>

            % if AcmeOrderless.is_processing:
                <form
                    action="${admin_prefix}/acme-orderless/${AcmeOrderless.id}/deactivate"
                    method="POST"
                    enctype="multipart/form-data"
                >
                    <button type="submit" class="btn btn-xs btn-danger"><span class="glyphicon glyphicon-remove"></span> Deactivate</button>
                </form>
            % endif
            
            <h4>Elements Explained</h4>
            <ul class="list list-unstyled">
                <li><code>token</code> is the name of the file letsencrypt expects at a url.</li>
                <li><code>keyauthorization</code> are the expected contents for the file.</li>
                ## Note: challenge_url is not supported until this is integrated with an AcmeAccount
                ## <li><code>challenge_url</code> is the ACME url that manages the challenge, not your url.</li>
            </ul>

            <p>If letsencrypt says the url should be <code>example.com/acme-challenge/foo-bar-biz</code> , then the token is <code>foo-bar-biz</code></p>

            <p>
                note: Visiting a `test` URL will direct you to the actual verification URL with "?test=1" appended.  This string instructs the server to not log the visit.  If the "?test=1" string is missing, the server will log the visit.  This is used to track the ACME server verification visits.
            </p>
            
            
        </div>
    </div>
    <div class="row">
        <div class="col-sm-12">
        
            <h5>AcmeAccountKey</h5>
            % if AcmeOrderless.acme_account_key_id:
                <p>This AcmeOrderless is connected to:
                    <a class="label label-info" href="${admin_prefix}/acme-account-key/${AcmeOrderless.acme_account_key_id}">
                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                        AcmeAccountKey-${AcmeOrderless.acme_account_key_id}
                    </a>
                 </p>
            % else:
                <p>This AcmeOrderless is not connected to an AcmeAccountKey.</p>
            % endif
        
            <h5>Challenges in this Orderless Request</h5>
            
            <% editable = AcmeOrderless.is_processing %>
            % if editable:
                <form
                    action="${admin_prefix}/acme-orderless/${AcmeOrderless.id}/update"
                    method="POST"
                    enctype="multipart/form-data"
                >
                    <% form = request.pyramid_formencode_classic.get_form() %>
                    ${form.html_error_main_fillable()|n}
            % endif
                <%
                    cols = ['Challenge',
                            'Domain',
                            'Test',
                            'Type',
                            'Status',
                            'Token',
                            'KeyAuthorization',
                            'updated',
                            ]
                            
                    if AcmeOrderless.acme_account_key_id:
                        # Note: challenge_url is not supported until this is integrated with an AcmeAccount
                        cols.append("challenge_url")
                %>
                <table class="table table-condensed table-striped">
                    <thead>
                        <tr>
                            % for col in cols:
                                <th>${col}</th>
                            % endfor
                        </tr>
                    </thead>
                    <tbody>
                        % for challenge in AcmeOrderless.acme_challenges:
                            <tr>
                                % for col in cols:
                                    <td>
                                        % if col == 'Challenge':
                                            <a class="label label-info" href="${admin_prefix}/acme-orderless/${AcmeOrderless.id}/acme-challenge/${challenge.id}">
                                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                AcmeChallenge-${challenge.id}
                                            </a>
                                        % elif col == 'Domain':
                                            <a class="label label-info" href="${admin_prefix}/domain/${challenge.domain_id}">
                                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                                ${challenge.domain_id}
                                                |
                                                ${challenge.domain_name}
                                            </a>
                                        % elif col == 'Test':
                                            % if challenge.acme_challenge_type == "http-01":
                                                % if challenge.token:
                                                    <a href="http://${challenge.domain.domain_name}/.well-known/acme-challenge/${challenge.token}?test=1"
                                                       target="_blank"
                                                       class="btn btn-${"success" if AcmeOrderless.is_processing else "danger"}"
                                                    >
                                                        <span class="glyphicon glyphicon-link" aria-hidden="true"></span>
                                                    </a>
                                                % endif
                                            % endif
                                        % elif col == 'Type':
                                            <span class="label label-default">${challenge.acme_challenge_type}</span>
                                        % elif col == 'Status':
                                            <span class="label label-default">${challenge.acme_status_challenge}</span>
                                        % elif col == 'Token':
                                            % if editable:
                                                <input class="form-control" type="text" name="${challenge.id}_token" value="${challenge.token or ''}"/>
                                            % else:
                                                <code>${challenge.token or ''}</code>
                                            % endif
                                        % elif col == 'KeyAuthorization':
                                            % if editable:
                                                <input class="form-control" type="text" name="${challenge.id}_keyauthorization" value="${challenge.keyauthorization or ''}"/>
                                            % else:
                                                <code>${challenge.keyauthorization or ''}</code>
                                            % endif
                                        % elif col == 'challenge_url':
                                            % if editable:
                                                <input class="form-control" type="text" name="${challenge.id}_url" value="${challenge.challenge_url or ''}"/>
                                            % else:
                                                <code>${challenge.challenge_url or ''}</code>
                                            % endif
                                        % elif col == 'updated':
                                            <timestamp>${challenge.timestamp_updated if challenge.timestamp_updated else ''}</timestamp>
                                        % endif
                                    </td>
                                % endfor
                            </tr>
                        % endfor
                    </tbody>
                </table>
            % if editable:
                    <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>
                </form>
            % endif
            
            % if editable:
                % if len(AcmeOrderless.acme_challenges) < 50:
                    <hr/>
                    <hr/>
                    <h5>Add a New Challenge</h5>
                    <form
                        action="${admin_prefix}/acme-orderless/${AcmeOrderless.id}/add"
                        method="POST"
                        enctype="multipart/form-data"
                    >
                        <div class="form-group">
                            <label for="domain">Domain</label>
                            <input class="form-control" type="text" name="domain" value=""/>
                        </div>
                        <div class="form-group">
                            <label for="token">Token</label>
                            <input class="form-control" type="text" name="token" value=""/>
                        </div>
                        <div class="form-group">
                            <label for="keyauthorization">KeyAuthorization</label>
                            <input class="form-control" type="text" name="keyauthorization" value=""/>
                        </div>
                        % if AcmeOrderless.acme_account_key_id:
                            <div class="form-group">
                                <label for="challenge_url">ChallengeURL</label>
                                <input class="form-control" type="text" name="challenge_url" value=""/>
                            </div>
                        % endif
                        <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>
                    </form>
                % else:
                    Can not add items to this.
                % endif
            % endif

        </div>
    </div>
</%block>
