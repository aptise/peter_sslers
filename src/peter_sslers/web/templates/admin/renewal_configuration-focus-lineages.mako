<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/renewal-configurations">RenewalConfiguration</a></li>
        <li><a href="${admin_prefix}/renewal-configuration/${RenewalConfiguration.id}">Focus [${RenewalConfiguration.id}]</a></li>
        <li class="active">X509Certificates</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>RenewalConfiguration Focus - lineages</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-9">
            <p>
                Most Renewal Configurations will have a single Lineage for each active Certificate type (Primary or Backup).
                A new Lineage is created when there is an intentional Duplicate Certificate, or when an ARI-Replaces field is rejected.
            </p>
        
            % for lineage_id in reversed(sorted(Lineages.keys())):
                <% X509Certificates = reversed(Lineages[lineage_id]) %>
                ${admin_partials.table_X509Certificates(X509Certificates, perspective='RenewalConfiguration', show_replace=True,)}
            % endfor
        </div>
    </div>
</%block>
