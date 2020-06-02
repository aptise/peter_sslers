<%inherit file="/admin/-site_template.mako"/>
<%namespace name="admin_partials" file="/admin/-partials.mako"/>


<%block name="breadcrumb">
    <ol class="breadcrumb">
        ${request.breadcrumb_prefix|n}
        <li><a href="${admin_prefix}">Admin</a></li>
        <li><a href="${admin_prefix}/coverage-assurance-events">Coverage Assurance Events</a></li>
        <li><a href="${admin_prefix}/coverage-assurance-event/${CoverageAssuranceEvent.id}">Focus [${CoverageAssuranceEvent.id}]</a></li>
        <li class="active">Children</li>
    </ol>
</%block>


<%block name="page_header_col">
    <h2>Coverage Assurance Event - Focus - Children</h2>
</%block>


<%block name="content_main">
    <div class="row">
        <div class="col-sm-12">
            ${admin_partials.table_CoverageAssuranceEvents(CoverageAssuranceEvents_Children)}
        </div>
    </div>
</%block>
