<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li class="active">Domains</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Domains</h2>
    These domains are known to the system.
</%block>


<%block name="page_header_nav">
    ${admin_partials.domains_section_nav()}
    <p class="pull-right">
        <a  href="${admin_prefix}/domain/new"
            class="btn btn-xs btn-primary"
        >
        <span class="glyphicon glyphicon-plus" aria-hidden="true"></span>
        New</a>
    </p>
</%block>



<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            % if sidenav_option == "expiring":
                <p>Domains that will be expiring within `${expiring_days_ux}` days.</p>
            % endif
            % if sidenav_option == "challenged":
                <p>Domains that have active challenges.</p>
            % endif
            % if sidenav_option == "authz-potential":
                <p>Domains that have active Authz Potential.</p>
            % endif
            % if Domains:
                ${admin_partials.nav_pagination(pager)}
                <table class="table table-striped table-condensed">
                    <thead>
                        <tr>
                            <th>id</th>
                            <th>domain name</th>
                            <th>x509_certificate__latest_multi</th>
                            <th>x509_certificate__latest_single</th>
                        </tr>
                        <tr>
                            <th></th>
                            <th></th>
                            <th>id, expiring, days</th>
                            <th>id, expiring, days</th>
                        </tr>
                    </thead>
                    % for d in Domains:
                        <tr>
                            <td>
                                <a  class="label label-info"
                                    href="${admin_prefix}/domain/${d.id}"
                                >
                                    <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                    Domain-${d.id}</a>
                            </td>
                            <td><code>${d.domain_name}</code></td>
                            <td>
                                % if d.x509_certificate_id__latest_multi:
                                    <a  class="label label-info"
                                        href="${admin_prefix}/x509-certificate/${d.x509_certificate_id__latest_multi}"
                                    >
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        X509Certificate-${d.x509_certificate_id__latest_multi}</a>
                                    <timestamp>${d.x509_certificate__latest_multi.timestamp_not_after}</timestamp>
                                    <span class="label label-${d.x509_certificate__latest_multi.days_to_expiry__label}">${d.x509_certificate__latest_multi.days_to_expiry} days</span>
                                % endif
                            </td>
                            <td>
                                % if d.x509_certificate_id__latest_single:
                                    <a  class="label label-info"
                                        href="${admin_prefix}/x509-certificate/${d.x509_certificate_id__latest_single}"
                                    >
                                        <span class="glyphicon glyphicon-file" aria-hidden="true"></span>
                                        X509Certificate-${d.x509_certificate_id__latest_single}</a>
                                    <timestamp>${d.x509_certificate__latest_single.timestamp_not_after}</timestamp>
                                    <span class="label label-${d.x509_certificate__latest_single.days_to_expiry__label}">${d.x509_certificate__latest_single.days_to_expiry} days</span>
                                % endif
                            </td>
                        </tr>
                    % endfor
                </table>
            % else:
                <em>
                    No Domains
                </em>
            % endif
            </div>
        </div>
    </div>
</%block>
