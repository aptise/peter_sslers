<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">API: Domain: Autocert</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>API: Domain: Autocert</h2>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/api/domain/autocert.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <p>
                The `autocert` endpoint allows `nginx` to automatically provision a certificate as needed.
            </p>
            <p>
                The endpoint ONLY responds to json requests.  GET will document, POST will submit.
            </p>

            % if not AcmeAccount_GlobalDefault:
                <div class="alert alert-danger">
                    <p>There is NO default AcmeAccount configured.</p>
                    <p>You must select a default AcmeAccount to use autocert</p>
                    <p>This can be configured by selecting a new <a href="${admin_prefix}/acme-accounts">AcmeAccount</a>.</p>
                </div>
            % else:
                <div class="alert alert-warning">
                    The default AcmeAccount is:
                    <a href="${admin_prefix}/acme-account/${AcmeAccount_GlobalDefault.id}" span class="label label-info">
                        AcmeAccount-${AcmeAccount_GlobalDefault.id}
                    </a>
                    <code>${AcmeAccount_GlobalDefault.key_pem_sample}</code>
                </p>
            % endif


        </div>
    </div>
</%block>
