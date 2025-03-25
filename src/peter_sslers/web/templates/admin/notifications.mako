<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Notifications</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Notifications</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
        
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>id</th>
                        <th>notification_type_id</th>
                        <th>timestamp_created</th>
                        <th>message</th>
                        <th>dismiss</th>
                    </tr>
                </thead>
                <tbody>
                % for notification in Notifications:
                    <tr>
                        <td>
                            <span class="label label-default">
                                <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                ${notification.id}
                            </span>
                        </td>
                        <td><code>${notification.notification_type_id}</code></td>
                        <td><timstamp>${notification.timestamp_created_isoformat}</timestamp></td>
                        <td><code>${notification.message}</code></td>
                        <td>
                            % if notification.is_active:
                                <form action="${admin_prefix}/notification/${notification.id}/mark" method="POST" style="display:inline;" id="form-notification-${notification.id}-mark-dismiss">
                                    <input type="hidden" name="action" value="dismiss"/>
                                    <button class="btn btn-xs btn-warning" type="submit">
                                        <span class="glyphicon glyphicon-times" aria-hidden="true"></span>
                                        dismiss
                                    </button>
                                </form>
                            % endif
                        </td>
                    </tr>
                % endfor
                </tbody>
            </table>

        </div>
    </div>
</%block>



