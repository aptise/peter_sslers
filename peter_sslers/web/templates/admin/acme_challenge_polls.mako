<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">ACME Challenge Polls</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>ACME Challenge Polls</h2>
</%block>


<%block name="page_header_nav">
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if AcmeChallenges:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>id</th>
                        </tr>
                    </thead>
                    <tbody>
                    % for item in AcmeChallengePolls:
                        <tr>
                            <td><a class="label label-info" href="${admin_prefix}/acme-challenge-polls/${item.id}">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ${item.id}</a></td>
                        </tr>
                    % endfor
                    </tbody>
                </table>
            % else:
                <em>
                    No AcmeChallengePolls
                </em>
            % endif
        </div>
    </div>
</%block>
