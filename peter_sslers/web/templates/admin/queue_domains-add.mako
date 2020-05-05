<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/queue-domains">Queue: Domains</a></li>
        <li class="active">Add</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Queue: Domains | Add</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-6">
            <form
                action="${admin_prefix}/queue-domains/add"
                method="POST"
            >
                <% form = request.pyramid_formencode_classic.get_form() %>
                ${form.html_error_main_fillable()|n}

                ${admin_partials.formgroup__domain_names()}
                <hr/>

                <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-upload"></span> Submit</button>

            </form>
        </div>
        <div class="col-sm-6">
            <h3>Add Domains to the Queue</h3>
            <p>
                The Domains Queue allows you to batch-process domain names.
            </p>
            <h4>New Domain Names</h4>
            <p>
                 New domain names will be held in a Queue until another process is called to issue them.
            </p>
            <h4>Existing Domain Names</h4>
            <p>
                 If an existing, active, domain name is queued: nothing will happen.<br/>
                 If an existing, inactive, domain name is queued: it will be activated and queued.
            </p>
            <p>
                You can also post to <code>${admin_prefix}/queue-domains/add.json</code>
            </p>
        </div>
    </div>
</%block>
