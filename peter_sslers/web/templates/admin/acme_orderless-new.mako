<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/acme-orderlesss" class="active">AcmeOrderless</a></li>
        <li class="active">New</li>
    </ol>
</%block>

<%block name="page_header_col">
    <h2>AcmeOrderless Flow | New</h2>
    <p><em>${request.text_library.info_AcmeOrderless_new[1]}</em></p>
    <p>
        The AcmeOrderless Flow system was designed to manage challeneges for a LetsEncrypt certificate issuance initiated with other software.
        This subsystem allows you enter the challenge/response codes via HTML or a JSON API, and tracks when LetsEncrypt makes the validation.
        This is most useful in a clustered environment with the 'manual' certbot plugin populating the challenges.
    </p>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-orderless/new.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-upload" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            <form action="${admin_prefix}/acme-orderless/new" method="POST">
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}

                <div class="form-group">
                    <label for="f1-domain_names">Domain Names</label>
                    <textarea class="form-control" rows="3" name="domain_names" id="f1-domain_names"></textarea>
                    <p class="help-block">enter domain_names above, separated by commas. <b>This should be EXACTLY what you typed in the LetsEncrypt Certbot client.</p>
                </div>

                <h3>AcmeAccount</h3>
                ${admin_partials.formgroup__AcmeAccount_selector__advanced(allow_no_key=True)}
                <hr/>


                <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>
            </form>
        </div>
    </div>
</%block>
