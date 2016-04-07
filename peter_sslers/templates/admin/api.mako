<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li class="active">Programmatic API</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Programmatic API</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            <p>
                Many endpoints handle JSON requests, however some endpoints offer deeper logic:
            </p>
    
            <p>Enpoints assume the prefix: <em>/.well-known/admin</em>
            </p>
    
            <table class="table table-striped table-condensed">
                <thead>
                    <tr>
                        <th>Endpoint</th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><code>/api/domain/enable</code></td>
                        <td></td>
                    </tr>
                    <tr>
                        <td><code>/api/domain/disable</code></td>
                        <td></td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

</%block>
