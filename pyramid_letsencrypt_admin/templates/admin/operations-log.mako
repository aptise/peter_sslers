<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li class="active">Operations</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Operations Log</h2>
</%block>
    

<%block name="content_main">
    % if LetsencryptOperationsEvents:
        ${admin_partials.nav_pager(pager)}
        <table class="table table-striped table-condensed">
            <thead>
                <tr>
                    <th>id</th>
                    <th>event_type</th>
                    <th>event timestamp</th>
                </tr>
            </thead>
            <tbody>
                % for event in LetsencryptOperationsEvents:
                    <tr>
                        <td><span class="label label-default">${event.id}</span></td>
                        <td><span class="label label-default">${event.event_type_text}</span></td>
                        <td><timestamp>${event.timestamp_operation}</timestamp></td>
                    </tr>
                % endfor
            </tbody>
        </table>
    % else:
        <em>
            No certificate probes
        </em>
    % endif



</%block>


