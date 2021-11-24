<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Domains Blocklisted</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Domains Blocklisted</h2>
    These domains are known to the system and blocklisted from operations.
    Add/Edit is currently done via SQL directly.
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a  class="btn btn-xs btn-info"
            href="${admin_prefix}/domains-blocklisted.json"
        >
            <span class="glyphicon glyphicon-list" aria-hidden="true"></span>
            .json</a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if DomainsBlocklisted:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>domain name</th>
                        </tr>
                    </thead>
                    % for d in DomainsBlocklisted:
                        <tr>
                            <td>
                                <span  class="label label-default"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    DomainBlocklisted-${d.id}
                                </span>
                            </td>
                            <td><code>${d.domain_name}</code></td>
                        </tr>
                    % endfor
                </table>
            % else:
                <em>
                    No DomainsBlocklisted
                </em>
            % endif
            </div>
        </div>
    </div>
</%block>
