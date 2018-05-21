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
            <h4>Dedicated API Endpoints</h4>
            <table class="table table-striped table-condensed">
                <thead>
                    <tr>
                        <th>Endpoint</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    % for ep in api_docs:
                        <tr>
                            <td><code>${ep['endpoint']}</code></td>
                            <td>${ep['about']}</td>
                        </tr>
                        <tr>
                            <td></td>
                            <td>
                                <b>Get:</b>
                                % if ep['GET'] is True:
                                    <span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span>
                                % elif ep['GET'] is None:
                                    <span class="label label-warning"><span class="glyphicon glyphicon-exclamation-sign" aria-hidden="true"></span></span>
                                % endif
                                <br/>
                                <b>Post:</b>
                                % if ep['POST']:
                                    <span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span>
                                % endif
                                <br/>
                                % if ep['args']:
                                    <b>Args:</b>
                                    ${ep['args']|n}
                                    <br/>
                                % endif
                                % if ep.get('example') or ep.get('examples'):
                                    <b>Examples:</b>
                                    <br/>
                                    % if ep.get('example'):
                                        <code>${ep.get('example').replace('{ADMIN_PREFIX}', request.admin_url)}</code>
                                    % endif
                                    % if ep.get('examples'):
                                        % for idx, example in enumerate(ep.get('examples')):
                                            % if idx >= 1:
                                                <hr/>
                                            % endif
                                            <code>${example.replace('{ADMIN_PREFIX}', request.admin_url)}</code>
                                        % endfor
                                    % endif
                                % endif
                            </td>
                        </tr>
                    % endfor
                </tbody>
            </table>
<%
api_docs_other = {
    'account-key': [
        {'endpoint': '/account-keys.json',
         'about': """list account keys""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/account-keys.json",
         },
        {'endpoint': '/account-keys/{PAGE}.json',
         'about': """list account keys, paginated""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/account-keys/1.json",
         },
        {'endpoint': '/account-key/{ID}.json',
         'about': """account-key record""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/account-key/1.json",
         },
        {'endpoint': '/account-key/{ID}/config.json',
         'about': """config info for an account key""",
         'POST': True,
         'GET': None,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/account-key/1/config.json",
         },
        {'endpoint': '/account-key/{ID}/parse.json',
         'about': """parse an account key""",
         'POST': True,
         'GET': None,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/account-key/1/parse.json",
         },
        {'endpoint': '/account-key/{ID}/key.key',
         'about': """key as der""",
         'POST': True,
         'GET': None,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/account-key/1/key.key",
         },
        {'endpoint': '/account-key/{ID}/key.pem',
         'about': """key as pem""",
         'POST': True,
         'GET': None,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/account-key/1/key.pem",
         },
        {'endpoint': '/account-key/{ID}/key.pem.txt',
         'about': """key as pem/txt""",
         'POST': True,
         'GET': None,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/account-key/1/key.pem.txt",
         },
        {'endpoint': '/account-key/upload.json',
         'about': """Upload an account-key""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         'examples': ["curl --form 'account_key_file_pem=@key.pem' --form 'acme_account_provider_id=1' {ADMIN_PREFIX}/account-key/upload.json",
                      "curl --form 'account_key_file_le_meta=@meta.json' 'account_key_file_le_pkey=@private_key.json' 'account_key_file_le_reg=@regr.json' {ADMIN_PREFIX}/account-key/upload.json",
                      ],
         },
        {'endpoint': '/account-key/{ID}/mark.json',
         'about': """mark the key""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         'example': "curl --form 'action=active' http://127.0.0.1:7201/.well-known/admin/account-key/1/mark.json",
         },
    ],
    'acme-provider': [
        {'endpoint': '/acme-providers.json',
         'about': """list acme-providers""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/acme-providers.json",
         },
    ],
    'ca-certificate': [
        {'endpoint': '/ca-certificates.json',
         'about': """list ca-certificates""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/ca-certificates.json",
         },
        {'endpoint': '/ca-certificates/{PAGE}.json',
         'about': """list ca-certificates, paginated""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/ca-certificates/1.json",
         },
        {'endpoint': '/ca-certificate/{ID}.json',
         'about': """parse certificate""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/ca-certificate/1.json",
         },
        {'endpoint': '/ca-certificate/{ID}/parse.json',
         'about': """parse certificate""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/ca-certificate/1/parse.json",
         },
        {'endpoint': '/ca-certificates/{ID}/chain.pem',
         'about': """cert as pem""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/ca-certificate/1/chain.pem",
         },
        {'endpoint': '/ca-certificates/{ID}/chain.pem.txt',
         'about': """cert as pem.txt""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/ca-certificate/1/chain.pem.txt",
         },
        {'endpoint': '/ca-certificates/{ID}/chain.cer',
         'about': """cert as cer""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/ca-certificate/1/chain.cer",
         },
        {'endpoint': '/ca-certificates/{ID}/chain.crt',
         'about': """cert as crt""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/ca-certificate/1/chain.crt",
         },
        {'endpoint': '/ca-certificates/{ID}/chain.der',
         'about': """cert as der""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/ca-certificate/1/chain.der",
         },
        {'endpoint': '/ca-certificate/upload.json',
         'about': """Upload an authority certificate""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         'examples': ["curl {ADMIN_PREFIX}/ca-certificate/upload.json",
                      "curl --form 'chain_file=@chain1.pem' --form {ADMIN_PREFIX}/ca-certificate/upload.json",
                      ]
         },
        {'endpoint': '/ca-certificate/upload-bundle.json',
         'about': """Upload an authority certificate bundle""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         'examples': ["curl {ADMIN_PREFIX}/ca-certificate/upload-bundle.json",
                      "curl --form 'isrgrootx1_file=@isrgrootx1.pem' --form 'le_x1_cross_signed_file=@lets-encrypt-x1-cross-signed.pem' --form 'le_x2_cross_signed_file=@lets-encrypt-x2-cross-signed.pem' --form 'le_x3_cross_signed_file=@lets-encrypt-x3-cross-signed.pem' --form 'le_x4_cross_signed_file=@lets-encrypt-x4-cross-signed.pem' --form 'le_x1_auth_file=@letsencryptauthorityx1' --form 'le_x2_auth_file=@letsencryptauthorityx2' {ADMIN_PREFIX}/ca-certificate/upload-bundle.json",
                      ]
         },
    ],
    'certificate': [
        {'endpoint': '/certificates.json',
         'about': """list certificates""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/certificates.json",
         },
        {'endpoint': '/certificates/{PAGE}.json',
         'about': """list certificates, paginated""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/certificates/1.json",
         },
        {'endpoint': '/certificates/expiring.json',
         'about': """list certificates. expiring.""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/certificates/expiring.json",
         },
        {'endpoint': '/certificates/expiring/{PAGE}.json',
         'about': """list certificates, paginated. expiring.""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/certificates/expiring/1.json",
         },
        {'endpoint': '/certificate/{ID}.json',
         'about': """certficate as json""",
         'POST': True,
         'GET': None,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/certificate/1.json",
         },
        {'endpoint': '/certificate/{ID}/config.json',
         'about': """config info for a certficate""",
         'POST': True,
         'GET': None,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/certificate/1/config.json",
         },
        {'endpoint': '/certificate/{ID}/parse.json',
         'about': """parse a certficate""",
         'POST': True,
         'GET': None,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/certificate/1/parse.json",
         },
        {'endpoint': '/certificate/{ID}/nginx-cache-expire.json',
         'about': """send reset to nginx""",
         'POST': True,
         'GET': None,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/certificate/1/nginx-cache-expire.json",
         },
        {'endpoint': '/certificate/{ID}/renew/queue.json',
         'about': """renewal - quick""",
         'POST': True,
         'GET': None,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/certificate/1/renew/queue.json",
         },
        {'endpoint': '/certificate/{ID}/renew/quick.json',
         'about': """renewal - quick""",
         'POST': True,
         'GET': None,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/certificate/1/renew/quick.json",
         },
        {'endpoint': '/certificate/{ID}/renew/custom.json',
         'about': """custom renewal""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         'example': "curl {ADMIN_PREFIX}/certificate/1/renew/custom.json",
         },
        {'endpoint': '/certificate/{ID}/mark.json',
         'about': """mark a certficate""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         'examples': ["curl {ADMIN_PREFIX}/certificate/1/mark.json",
                      "curl --form 'action=active' {ADMIN_PREFIX}/certificate/1/mark.json",
                      ]
         },
        {'endpoint': '/certificate/upload.json',
         'about': """Upload a certificate""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         'examples': ["curl http://127.0.0.1:7201/.well-known/admin/certificate/upload.json",
                      "curl --form 'private_key_file=@privkey1.pem' --form 'certificate_file=@cert1.pem' --form 'chain_file=@chain1.pem' {ADMIN_PREFIX}/certificate/upload.json",
                      ]
         },
    ],
    'certificate-request': [
        {'endpoint': '/certificate-requests.json',
         'about': """list certificate-requests""",
         'POST': True,
         'GET': True,
         'args': "",
         'args': "",
         "example": "curl http://127.0.0.1:7201/.well-known/admin/certificate-requests.json",
         },
        {'endpoint': '/certificate-requests/{PAGE}.json',
         'about': """list certificate-requests, paginated""",
         'POST': True,
         'GET': True,
         'args': "",
         "example": "curl http://127.0.0.1:7201/.well-known/admin/certificate-requests/1.json",
         },
        {'endpoint': '/certificate-request/{ID}.json',
         'about': """certificate request info""",
         'POST': True,
         'GET': True,
         'args': "",
         "example": "curl http://127.0.0.1:7201/.well-known/admin/certificate-request/1.json",
         },
        {'endpoint': '/certificate-request/{ID}/deactivate.json',
         'about': """deactivate the request; only used for AcmeFlow helper""",
         'POST': True,
         'GET': True,
         'args': "",
         "example": "curl http://127.0.0.1:7201/.well-known/admin/certificate-request/1/deactivate.json",
         },

        {'endpoint': '/certificate-request/{ID}/csr.csr',
         'about': """certificate request as CSR file""",
         'POST': True,
         'GET': True,
         'args': "",
         "example": "curl http://127.0.0.1:7201/.well-known/admin/certificate-request/1/csr.csr",
         },
        {'endpoint': '/certificate-request/{ID}/csr.pem',
         'about': """certificate request in pem format""",
         'POST': True,
         'GET': True,
         'args': "",
         "example": "curl http://127.0.0.1:7201/.well-known/admin/certificate-request/1/csr.pem",
         },
        {'endpoint': '/certificate-request/{ID}/csr.pem.txt',
         'about': """certificate request in pem.txt format""",
         'POST': True,
         'GET': True,
         'args': "",
         "example": "curl http://127.0.0.1:7201/.well-known/admin/certificate-request/1/csr.pem.txt",
         },
    ],
    'domain': [
        {'endpoint': '/domains/search.json',
         'about': """search for a domain""",
         'POST': True,
         'GET': False,
         'args': """This route is self-documenting on GET requests""",
         'examples': ["curl {ADMIN_PREFIX}/domains/search.json",
                      "curl --form 'domain=example.com' {ADMIN_PREFIX}/domains/search.json",
                      ],
         },
        {'endpoint': '/domains.json',
         'about': """list domains""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/domains.json",
         },
        {'endpoint': '/domains/{PAGE}.json',
         'about': """list domains""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/domains/1.json",
         },
        {'endpoint': '/domains/expiring.json',
         'about': """list expiring domains""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/domains/expiring.json",
         },
        {'endpoint': '/domains/expiring/{PAGE}.json',
         'about': """list expiring domains""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/domains/expiring/1.json",
         },
        {'endpoint': '/domain/{DOMAIN|ID}.json',
         'about': """core record as json""",
         'POST': True,
         'GET': None,
         'args': "",
         'examples': ["curl {ADMIN_PREFIX}/domain/1.json",
                      "curl {ADMIN_PREFIX}/domain/example.com.json",
                      ],
         },
        {'endpoint': '/domain/{ID}/calendar.json',
         'about': """renewal calendar""",
         'POST': True,
         'GET': None,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/domain/1/calendar.json",
         },
        {'endpoint': '/domain/{DOMAIN|ID}/config.json',
         'about': """certificate configuration info for a domain""",
         'POST': True,
         'GET': None,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/domain/1/config.json",
         },
        {'endpoint': '/domain/{ID}/nginx-cache-expire.json',
         'about': """send cache reset to nginx for this domain""",
         'POST': True,
         'GET': None,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/domain/1/nginx-cache-expire.json",
         },
        {'endpoint': '/domain/{ID}/mark.json',
         'about': """mark a domain""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         'example': "curl --form 'action=active' {ADMIN_PREFIX}/domain/1/mark.json",
         },
    ],
    'private-key': [
        {'endpoint': '/private-keys.json',
         'about': """list keys""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/private-keys.json",
         },
        {'endpoint': '/private-keys/{PAGE}.json',
         'about': """list keys, paginated""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/private-keys/1.json",
         },
        {'endpoint': '/private-key/{ID}.json',
         'about': """Focus on the key""",
         'POST': True,
         'GET': False,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/private-key/1.json",
         },
        {'endpoint': '/private-key/{ID}/parse.json',
         'about': """Parse the key""",
         'POST': True,
         'GET': False,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/private-key/1/parse.json",
         },
         
        {'endpoint': '/private-key/{ID}/key.key',
         'about': """download the key as a key (der)""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/private-key/1/key.key",
         },
        {'endpoint': '/private-key/{ID}/key.key',
         'about': """download the key as a pem (pem)""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/private-key/1/key.pem",
         },
        {'endpoint': '/private-key/{ID}/key.key',
         'about': """download the key as a pem.txt (pem)""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/private-key/1/key.pem.txt",
         },
        {'endpoint': '/private-key/{ID}/mark.json',
         'about': """mark the key""",
         'POST': True,
         'GET': False,
         'args': """This route is self-documenting on GET requests""",
         'examples': ["curl {ADMIN_PREFIX}/private-key/1/mark.json",
                      "curl --form 'action=active' {ADMIN_PREFIX}/private-key/1/mark.json"
                      ],
         },
        {'endpoint': '/private-key/{ID}/upload.json',
         'about': """upload a key""",
         'POST': True,
         'GET': False,
         'args': """This route is self-documenting on GET requests""",
         'examples': ["curl {ADMIN_PREFIX}/private-key/1/upload.json",
                      "curl --form 'private_key_file=@privkey1.pem' {ADMIN_PREFIX}/private-key/1/upload.json",
                      ],
         },
    ],
    'queue-domain': [
        {'endpoint': '/queue-domains.json',
         'about': """list domains in queue (unprocessed)""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/queue-domains.json",
         },
        {'endpoint': '/queue-domains/{PAGE}.json',
         'about': """list domains in queue (unprocessed), paginated""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/queue-domains/1.json",
         },
        {'endpoint': '/queue-domains/all.json',
         'about': """list domains in queue (all)""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/queue-domains/all.json",
         },
        {'endpoint': '/queue-domains/all/{PAGE}.json',
         'about': """list domains in queue (all), paginated""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/queue-domains/all/1.json",
         },
        {'endpoint': '/queue-domains/add.json',
         'about': """queue domains""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         'examples': ["curl {ADMIN_PREFIX}/queue-domains/add.json",
                      'curl --form "domain_names=example.com,foo.example.com" {ADMIN}/queue-domains/add.json'
                      ],
         },
        {'endpoint': '/queue-domains/process.json',
         'about': """engage queue""",
         'POST': True,
         'GET': None,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/queue-domains/process.json",
         },

        {'endpoint': '/queue-domain/{ID}.json',
         'about': """focus on record""",
         'POST': True,
         'GET': None,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/queue-domain/1.json",
         },
        {'endpoint': '/queue-domain/{ID}/mark.json',
         'about': """mark the queue item""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         'examples': ['curl {ADMIN_PREFIX}/queue-domain/1/mark.json',
                      'curl --form "action=cancel" {ADMIN_PREFIX}/queue-domain/1/mark.json',
                      ]
         },
    ],
    'queue-renewal': [

        {'endpoint': '/queue-renewals.json',
         'about': """list renewals in queue (unprocessed)""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/queue-renewals.json",
         },
        {'endpoint': '/queue-renewals/{PAGE}.json',
         'about': """list renewals in queue (unprocessed), paginated""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/queue-renewals/1.json",
         },
        {'endpoint': '/queue-renewals/all.json',
         'about': """list renewals in queue (all)""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/queue-renewals/all.json",
         },
        {'endpoint': '/queue-renewals/all/{PAGE}.json',
         'about': """list renewals in queue (all), paginated""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/queue-renewals/all/1.json",
         },
        {'endpoint': '/queue-renewals/active-failures.json',
         'about': """list renewals in queue (active-failures)""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/queue-renewals/active-failures.json",
         },
        {'endpoint': '/queue-renewals/active-failures/{PAGE}.json',
         'about': """list renewals in queue (active-failures), paginated""",
         'POST': True,
         'GET': True,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/queue-renewals/active-failures/1.json",
         },
        {'endpoint': '/queue-renewal/{ID}.json',
         'about': """focus on record""",
         'POST': True,
         'GET': None,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/queue-renewal/1.json",
         },
        {'endpoint': '/queue-renewal/{ID}/mark.json',
         'about': """mark the queue item""",
         'POST': True,
         'GET': None,
         'args': """This route is self-documenting on GET requests""",
         'examples': ['curl {ADMIN_PREFIX}/queue-renewal/1/mark.json',
                      'curl --form "action=cancel" {ADMIN_PREFIX}/queue-renewal/1/mark.json',
                      ]
         },

    ],
    'unique-fqdn-set': [
        {'endpoint': '/unique-fqdn-sets.json',
         'about': """list as json""",
         'POST': True,
         'GET': None,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/unique-fqdn-sets.json",
         },
        {'endpoint': '/unique-fqdn-sets/1.json',
         'about': """list as json, paginated""",
         'POST': True,
         'GET': None,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/unique-fqdn-sets/1.json",
         },
        {'endpoint': '/unique-fqdn-set/{ID}.json',
         'about': """info as json""",
         'POST': True,
         'GET': None,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/unique-fqdn-set/1.json",
         },
        {'endpoint': '/unique-fqdn-set/{ID}/calendar.json',
         'about': """renewal calendar""",
         'POST': True,
         'GET': None,
         'args': "",
         'example': "curl {ADMIN_PREFIX}/unique-fqdn-set/1/calendar.json",
         },
    ]
}
%>
            <h4>JSON Capable Endpoints</h4>
            <ul>
                % for section in sorted(api_docs_other.keys()):            
                    <li><a href="#${section}">${section}</a></li>
                % endfor
            </ul>
            
            <table class="table table-striped table-condensed">
                <thead>
                    <tr>
                        <th>Endpoint</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    % for section in sorted(api_docs_other.keys()):
                        <tr>
                            <th colspan="5"><a name="${section}"></a>${section}</th>
                        </tr>
                        % for ep in api_docs_other[section]:
                            <tr>
                                <td><code>${ep['endpoint']}</code></td>
                                <td>${ep['about']}</td>
                            </tr>
                            <tr>
                                <td></td>
                                <td>
                                    <b>Get:</b>
                                    % if ep['GET'] is True:
                                        <span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span>
                                    % elif ep['GET'] is None:
                                        <span class="label label-warning"><span class="glyphicon glyphicon-exclamation-sign" aria-hidden="true"></span></span>
                                    % endif
                                    <br/>
                                    <b>Post:</b>
                                    % if ep['POST']:
                                        <span class="label label-success"><span class="glyphicon glyphicon-check" aria-hidden="true"></span></span>
                                    % endif
                                    <br/>
                                    % if ep['args']:
                                        <b>Args:</b>
                                        ${ep['args']}
                                        <br/>
                                    % endif
                                    % if ep.get('example') or ep.get('examples'):
                                        <b>Examples:</b>
                                        <br/>
                                        % if ep.get('example'):
                                            <code>${ep.get('example').replace('{ADMIN_PREFIX}', request.admin_url)}</code>
                                        % endif
                                        % if ep.get('examples'):
                                            % for idx, example in enumerate(ep.get('examples')):
                                                % if idx >= 1:
                                                    <hr/>
                                                % endif
                                                <code>${example.replace('{ADMIN_PREFIX}', request.admin_url)}</code>
                                            % endfor
                                        % endif
                                    % endif
                                </td>
                            </tr>
                        % endfor
                    % endfor
                </tbody>
            </table>
        </div>
    </div>

</%block>
