<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li><a href="/.well-known/admin/private-keys">Private Keys</a></li>
        <li class="active">New</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Private Key | New</h2>
    <p><em>${request.text_library.info_PrivateKeys[1]}</em></p>
</%block>

    
<%block name="content_main">

    <div class="row">
        <div class="col-sm-6">
        
            <%! show_text = False %>

            <form
                action="/.well-known/admin/private-key/new"
                method="POST"
                enctype="multipart/form-data"
            >
                <% form = request.formhandling.get_form(request) %>
                ${form.html_error_main('Error_Main')|n}

                ${admin_partials.formgroup__private_key_file(show_text=show_text)}
                <hr/>

                <button type="submit" class="btn btn-default">Submit</button>
        
            </form>
        </div>
        <div class="col-sm-6">
            ${admin_partials.info_PrivateKey()}
        </div>
    </div>
</%block>
