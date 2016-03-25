<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li class="active">Redis Operations</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Redis Operations</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-6">
            <div class="alert alert-info">
                Redis is enabled for this server.
            </div>
            <p>
                <a  href="/.well-known/admin/redis/prime"
                    class="btn btn-primary"
                >
                    Prime Redis Cache
                </a>
            </p>
        </div>
        <div class="col-sm-6">
        </div>

    </div>
</%block>
