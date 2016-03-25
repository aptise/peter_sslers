<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        <li><a href="/.well-known/admin">Admin</a></li>
        <li class="active">Certificate Probes</li>
    </ol>
</%block>


<%block name="page_header">
    <h2>Certificate Probes</h2>
</%block>
    

<%block name="content_main">
    <h2>Update</h2>
    <p>
        <form action="/.well-known/admin/ca_certificate_probes/probe" method="POST">
            <input type="submit" class="btn btn-info" value="Probe for new certificates"/>
            <br/>
            <em>Checks for new certs on the public internet</em>
        </form>
    </p>

    % if LetsencryptCACertificateProbes:
        ${admin_partials.nav_pager(pager)}
        <table class="table table-striped table-condensed">
            <thead>
                <tr>
                    <th>id</th>
                    <th>event timestamp</th>
                    <th>is_certificates_discovered</th>
                    <th>is_certificates_updated</th>
                </tr>
            </thead>
            <tbody>
                % for event in LetsencryptCACertificateProbes:
                    <tr>
                        <td><span class="label label-default">${event.id}</span></td>
                        <td><timestamp>${event.timestamp_operation}</timestamp></td>
                        <td>
                            % if event.is_certificates_discovered:
                                <span class="label label-success">Y</span>
                            % endif
                        </td>
                        <td>
                            % if event.is_certificates_updated:
                                <span class="label label-success">Y</span>
                            % endif
                        </td>
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


