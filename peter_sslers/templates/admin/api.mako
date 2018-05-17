<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">API</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>API</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <p>
                Many endpoints handle JSON requests, however the `/api` endpoints offer some deeper logic and ONLY respond to JSON requests
            </p>
            <p>Endpoints assume the prefix: <em>${admin_prefix}</em>
            </p>
            <hr/>
            
            <h4>Refresher</h4>
            <p>If not using scripts to access the API, you can use `curl`</p>
            <code>curl --form "domain_names=example.com" ${request.admin_url}/api/domain/enable</code>
            <hr/>
            
<%
    api_docs = [
        {'endpoint': '/api/domain/enable',
         'about': """Enables domain(s) for management. Currently this proxies calls to `/admin/queue-domains`""",
         'POST': True,
         'GET': False,
         'args': """<ul>
                        <li>
                            <code>domain_names</code>
                            <em>A comma (,) separated list of domain names
                            </em>
                        </li>
                    </ul>""",
         },
        {'endpoint': '/api/domain/disable',
         'about': """Disables domain(s) for management""",
         'POST': True,
         'GET': False,
         'args': """<ul>
                        <li>
                            <code>domain_names</code>
                            <em>A comma (,) separated list of domain names
                            </em>
                        </li>
                    </ul>""",
         },
        {'endpoint': '/api/domain/certificate-if-needed',
         'about': """Initiates a CSR if needed""",
         'POST': True,
         'GET': False,
         'args': """<ul>
                        <li>
                            <code>domain_names</code>
                            <em>A comma (,) separated list of domain names
                            </em>
                        </li>
                    </ul>""",
         },
        {'endpoint': '/api/ca-certificate-probes/probe.json',
         'about': """Probes the LetsEncrypt website for certificates""",
         'POST': True,
         'GET': False,
         'args': None,
         },
        {'endpoint': '/api/redis/prime.json',
         'about': """Primes the redis cache""",
         'POST': True,
         'GET': False,
         'args': None,
         },
        {'endpoint': '/api/deactivate-expired.json',
         'about': """Primes the redis cache""",
         'POST': True,
         'GET': False,
         'args': None,
         },
        {'endpoint': '/api/update-recents.json',
         'about': """Primes the redis cache""",
         'POST': True,
         'GET': False,
         'args': None,
         },
        {'endpoint': '/api/nginx/cache-flush.json',
         'about': """Flushes the nginx cache. This will make background requests to configured nginx servers, instructing them to flush their cache. """,
         'POST': True,
         'GET': False,
         'args': None,
         },
        {'endpoint': '/api/nginx/status.json',
         'about': """Checks nginx servers for status via background requests""",
         'POST': True,
         'GET': False,
         'args': None,
         },
        {'endpoint': '/api/queue-renewals/update.json',
         'about': """Updates the renewal queue.""",
         'POST': True,
         'GET': False,
         'args': None,
         },
    ]
%>
            
            <h4>API Endpoints</h4>
            <table class="table table-striped table-condensed">
                <thead>
                    <tr>
                        <th>Endpoint</th>
                        <th>About</th>
                        <th>POST</th>
                        <th>GET</th>
                        <th>Args</th>
                    </tr>
                </thead>
                <tbody>
                    % for ep in api_docs:
                        <tr>
                            <td><code>${ep['endpoint']}</code></td>
                            <td>${ep['about']}</td>
                            <td>
                                % if ep['POST']:
                                    <span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span>
                                % endif
                            </td>
                            <td>
                                % if ep['GET']:
                                    <span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span>
                                % endif
                            </td>
                            <td>${ep['args'] or """<em>None</em>"""|n}</td>
                        </tr>
                    % endfor
                </tbody>
            </table>

<%
    api_docs_other = [
        {'endpoint': '/certificate/upload.json',
         'about': """Upload a certificate""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         },
        {'endpoint': '/ca-certificates.json',
         'about': """list ca-certificates""",
         'POST': True,
         'GET': True,
         'args': "",
         },
        {'endpoint': '/ca-certificates/{PAGE}.json',
         'about': """list ca-certificates, paginated""",
         'POST': True,
         'GET': True,
         'args': "",
         },
        {'endpoint': '/ca-certificate/upload.json',
         'about': """Upload an authority certificate""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         },
        {'endpoint': '/ca-certificate/upload-bundle.json',
         'about': """Upload an authority certificate bundle""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         },
        {'endpoint': '/certificates.json',
         'about': """list certificates""",
         'POST': True,
         'GET': True,
         'args': "",
         },
        {'endpoint': '/certificates/{PAGE}.json',
         'about': """list certificates, paginated""",
         'POST': True,
         'GET': True,
         'args': "",
         },
        {'endpoint': '/certificates/expired.json',
         'about': """list certificates. expired.""",
         'POST': True,
         'GET': True,
         'args': "",
         },
        {'endpoint': '/certificates/expired/{PAGE}.json',
         'about': """list certificates, paginated. expired.""",
         'POST': True,
         'GET': True,
         'args': "",
         },
        {'endpoint': '/certificate/{ID}.json',
         'about': """certficate as json""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         },
        {'endpoint': '/certificate/{ID}/config.json',
         'about': """config info for a certficate""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         },
        {'endpoint': '/certificate/{ID}/nginx-cache-expire.json',
         'about': """send reset to nginx""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         },
        {'endpoint': '/certificate/{ID}/renew-quick.json',
         'about': """renewal - quick""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         },
        {'endpoint': '/certificate/{ID}/renew-custom.json',
         'about': """custom renewal""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         },
        {'endpoint': '/certificate/{ID}/mark.json',
         'about': """mark a certficate""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         },

        {'endpoint': '/certificate-requests.json',
         'about': """list certificate-requests""",
         'POST': True,
         'GET': True,
         'args': "",
         },
        {'endpoint': '/certificate-requests/{PAGE}.json',
         'about': """list certificate-requests, paginated""",
         'POST': True,
         'GET': True,
         'args': "",
         },
        {'endpoint': '/certificate-request/{ID}.json',
         'about': """certificate request info""",
         'POST': True,
         'GET': True,
         'args': "",
         },
        {'endpoint': '/domains.json',
         'about': """list domains""",
         'POST': True,
         'GET': True,
         'args': "",
         },
        {'endpoint': '/domains/{PAGE}.json',
         'about': """list domains""",
         'POST': True,
         'GET': True,
         'args': "",
         },
        {'endpoint': '/domains/expiring.json',
         'about': """list expiring domains""",
         'POST': True,
         'GET': True,
         'args': "",
         },
        {'endpoint': '/domains/expiring/{PAGE}.json',
         'about': """list expiring domains""",
         'POST': True,
         'GET': True,
         'args': "",
         },
        {'endpoint': '/unique-fqdn-set/{DOMAIN|ID}.json',
         'about': """info as json""",
         'POST': True,
         'GET': None,
         'args': """""",
         },
        {'endpoint': '/domain/{DOMAIN|ID}/config.json',
         'about': """config info for a domain""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         },
        {'endpoint': '/domain/{ID}/nginx-cache-expire.json',
         'about': """send reset to nginx""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         },
        {'endpoint': '/domain/{ID}/calendar.json',
         'about': """renewal calendar""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         },
        {'endpoint': '/domain/{ID}/mark.json',
         'about': """mark a domain""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         },
        {'endpoint': '/account-keys.json',
         'about': """list account keys""",
         'POST': True,
         'GET': True,
         'args': "",
         },
        {'endpoint': '/account-keys/{PAGE}.json',
         'about': """list account keys, paginated""",
         'POST': True,
         'GET': True,
         'args': "",
         },
        {'endpoint': '/account-key/{ID}/config.json',
         'about': """config info for an account key""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         },
        {'endpoint': '/account-key/{ID}.json',
         'about': """account-key info""",
         'POST': True,
         'GET': True,
         'args': "",
         },
        {'endpoint': '/account-key/{ID}/mark.json',
         'about': """mark the key""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         },

        {'endpoint': '/private-keys.json',
         'about': """list keys""",
         'POST': True,
         'GET': True,
         'args': "",
         },
        {'endpoint': '/private-keys/{PAGE}.json',
         'about': """list keys, paginated""",
         'POST': True,
         'GET': True,
         'args': "",
         },

        {'endpoint': '/private-key/{ID}/mark.json',
         'about': """mark the key""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         },

        {'endpoint': '/queue-domain/add.json',
         'about': """queue domains""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         },
        {'endpoint': '/queue-domain/process.json',
         'about': """engage queue""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         },
        {'endpoint': '/queue-domain/{ID}/mark.json',
         'about': """mark the queue item""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         },
        {'endpoint': '/api/queue-renewals/process.json',
         'about': """run the queue""",
         'POST': None,
         'GET': True,
         'args': """run the queue. reporting info will be provided. specifically of interest: {"queue_results": {"count_remaining": ???}} which indicates if there is more processing""",
         },
        {'endpoint': '/queue-renewal/{ID}/mark.json',
         'about': """mark the queue item""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         },
        {'endpoint': '/unique-fqdn-set/{ID}.json',
         'about': """info as json""",
         'POST': True,
         'GET': None,
         'args': """""",
         },
        {'endpoint': '/unique-fqdn-set/{ID}/calendar.json',
         'about': """renewal calendar""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         },
    ]
%>
            <h4>JSON Capable Endpoints</h4>
            <table class="table table-striped table-condensed">
                <thead>
                    <tr>
                        <th>Endpoint</th>
                        <th>About</th>
                        <th>POST</th>
                        <th>GET</th>
                        <th>Args</th>
                    </tr>
                </thead>
                <tbody>
                    % for ep in api_docs_other:
                        <tr>
                            <td><code>${ep['endpoint']}</code></td>
                            <td>${ep['about']}</td>
                            <td>
                                % if ep['POST']:
                                    <span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span>
                                % endif
                            </td>
                            <td>
                                % if ep['GET'] is True:
                                    <span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span>
                                % elif ep['GET'] is None:
                                    <span class="label label-warning"><span class="glyphicon glyphicon-exclamation-sign" aria-hidden="true"></span></span>
                                % endif
                            </td>
                            <td>${ep['args'] or """<em>None</em>"""|n}</td>
                        </tr>
                    % endfor
                </tbody>
            </table>
        </div>
    </div>

</%block>
