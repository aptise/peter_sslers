<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">ACME Challenge Unknown Polls</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>ACME Challenge Unknown Polls</h2>
    <p><em>${request.text_library.info_AcmeChallengeUnknownPolls[1]}</em></p>
</%block>


<%block name="page_header_nav">
    <p class="pull-right">
        <a href="${admin_prefix}/acme-challenge-unknown-polls.json" class="btn btn-xs btn-info">
            <span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
            .json
        </a>
    </p>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if AcmeChallengeUnknownPolls:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>domain</th>
                            <th>challenge</th>
                            <th>timestamp_polled</th>
                            <th>remote_ip_address</th>
                        </tr>
                    </thead>
                    <tbody>
                    % for item in AcmeChallengeUnknownPolls:
                        <tr>
                            <td><span class="label label-default">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ${item.id}</span></td>
                            <td><code>${item.domain}</code></td>
                            <td><code>${item.challenge}</code></td>
                            <td><timestamp>${item.timestamp_polled}</timestamp></td>
                            <td><code>${item.remote_ip_address.remote_ip_address}</code></td>
                        </tr>
                    % endfor
                    </tbody>
                </table>
            % else:
                <em>
                    No Acme Challenge Unknown Polls
                </em>
            % endif
        </div>
    </div>
</%block>
